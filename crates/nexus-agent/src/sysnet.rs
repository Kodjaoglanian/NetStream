//! System network plumbing: `ip` invocations for interface configuration and
//! `getifaddrs` enumeration of local IPv4 addresses (LAN endpoint candidates).

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .context("executing `ip` — is iproute2 installed?")?;
    if !out.status.success() {
        bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Configure `dev` with the mesh VIP (/16), an MTU, and bring it up.
pub fn setup_interface(dev: &str, vip: Ipv4Addr, mtu: u16) -> Result<()> {
    ip(&["link", "set", "dev", dev, "mtu", &mtu.to_string()])?;
    ip(&["addr", "replace", &format!("{vip}/16"), "dev", dev])?;
    ip(&["link", "set", "dev", dev, "up"])?;
    Ok(())
}

/// Remove the interface (best-effort — TUN auto-destructs on close anyway).
pub fn teardown_interface(dev: &str) {
    let _ = ip(&["link", "del", "dev", dev]);
}

/// Bind the data-plane UDP socket. Prefers a dual-stack `[::]` socket
/// (IPV6_V6ONLY=0) so IPv4 peers arrive as v4-mapped addresses on one fd;
/// falls back to plain `0.0.0.0` when IPv6 is unavailable.
pub fn bind_udp(port: u16) -> Result<std::net::UdpSocket> {
    // Try dual-stack first.
    match bind_udp6_dualstack(port) {
        Ok(s) => return Ok(s),
        Err(e) => {
            tracing::debug!(error = %e, "dual-stack bind failed, using IPv4");
        }
    }
    let s = std::net::UdpSocket::bind(("0.0.0.0", port))
        .with_context(|| format!("binding UDP :{port}"))?;
    s.set_nonblocking(true)?;
    Ok(s)
}

fn bind_udp6_dualstack(port: u16) -> Result<std::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;
    unsafe {
        let fd = libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_INET6)");
        }
        let off: libc::c_int = 0;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e).context("setsockopt IPV6_V6ONLY");
        }
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_scope_id: 0,
        };
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e).context("bind [::]:port");
        }
        Ok(std::net::UdpSocket::from_raw_fd(fd))
    }
}

/// All non-loopback, up IPv4 addresses on the host — LAN candidates.
pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let flags = ifa.ifa_flags as libc::c_int;
            let up = flags & libc::IFF_UP != 0;
            let loopback = flags & libc::IFF_LOOPBACK != 0;
            if !up || loopback {
                continue;
            }
            if (*ifa.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                out.push(Ipv4Addr::from(sin.sin_addr.s_addr.to_be()));
            }
        }
        libc::freeifaddrs(head);
    }
    out
}
