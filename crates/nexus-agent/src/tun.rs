//! Linux TUN device management via `/dev/net/tun` ioctls — no external crate.
//!
//! The device is opened `IFF_TUN | IFF_NO_PI` (raw IP packets, no packet-info
//! header) in non-blocking mode and wrapped in `AsyncFd` for Tokio.

use anyhow::{Context, Result};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNGETIFF: libc::c_ulong = 0x800454d2;

/// `struct ifreq` — we only need name + flags (start of the union).
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: i16,
    _pad: [u8; 22],
}

/// An open TUN device. Dropping it closes the fd; the kernel removes the
/// interface automatically.
pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    /// Allocate a `nexus%d` interface (kernel picks the number).
    pub fn create() -> Result<Self> {
        let raw = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error())
                .context("opening /dev/net/tun (is the tun module loaded?)");
        }
        // Safety: fd is valid and exclusively owned by us from here on.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut req = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        req.ifr_name[..6].copy_from_slice(b"nexus%d");
        if unsafe { libc::ioctl(raw, TUNSETIFF, &req) } < 0 {
            return Err(io::Error::last_os_error()).context("ioctl TUNSETIFF failed");
        }

        // Read back the assigned name.
        let mut name_req = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: 0,
            _pad: [0; 22],
        };
        if unsafe { libc::ioctl(raw, TUNGETIFF, &mut name_req) } < 0 {
            return Err(io::Error::last_os_error()).context("ioctl TUNGETIFF failed");
        }
        let len = name_req.ifr_name.iter().position(|&c| c == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_req.ifr_name[..len]).to_string();

        Ok(Self {
            fd: AsyncFd::new(owned)?,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet. Waits for EPOLLIN; retries on EAGAIN.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| read_fd(inner.as_raw_fd(), buf)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet. Waits for EPOLLOUT; retries on EAGAIN.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| write_fd(inner.as_raw_fd(), buf)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
