//! Minimal HTTP/1.1 client used for control-plane REST calls.
//!
//! Supports `http://` over plain TCP and `https://` via rustls (webpki roots).
//! Requests always use `Connection: close`, so responses end at EOF; both
//! `Content-Length` and `chunked` transfer encoding are handled.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

struct ParsedUrl<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path: String,
    authority: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl<'_>> {
    let (tls, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (true, r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r, 80u16)
    } else {
        bail!("unsupported URL scheme (need http:// or https://): {url}");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        bail!("empty host in URL {url}");
    }
    let (host, port) = match authority.rsplit_once(':') {
        // Handle IPv6 literals [::1]:8080 vs plain host:port vs bare host.
        Some((h, p)) if !authority.contains('[') || h.ends_with(']') => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (authority, default_port),
        },
        _ => (authority, default_port),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    Ok(ParsedUrl {
        tls,
        host,
        port,
        path: path.to_string(),
        authority: authority.to_string(),
    })
}

async fn connect(parsed: &ParsedUrl<'_>) -> Result<Box<dyn AsyncIo>> {
    let tcp = TcpStream::connect((parsed.host, parsed.port))
        .await
        .with_context(|| format!("connecting to {}:{}", parsed.host, parsed.port))?;
    tcp.set_nodelay(true).ok();
    if !parsed.tls {
        return Ok(Box::new(tcp));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = rustls::pki_types::ServerName::try_from(parsed.host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid DNS name {}", parsed.host))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
    Ok(Box::new(tls))
}

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl AsyncIo for TcpStream {}
impl AsyncIo for tokio_rustls::client::TlsStream<TcpStream> {}

/// Perform one request and return (status code, body).
async fn request(
    url: &str,
    method: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String)> {
    let parsed = parse_url(url)?;
    let mut io = connect(&parsed).await?;

    let mut req = String::with_capacity(512);
    req.push_str(&format!("{method} {} HTTP/1.1\r\n", parsed.path));
    req.push_str(&format!("Host: {}\r\n", parsed.authority));
    req.push_str("User-Agent: nexus-agent/0.1\r\n");
    req.push_str("Connection: close\r\n");
    if let Some(tok) = bearer {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    io.write_all(req.as_bytes()).await?;
    io.flush().await?;

    // Read headers.
    let mut reader = BufReader::new(io);
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        headers.clear();
        // Read header block up to CRLFCRLF.
        let mut hdr = Vec::with_capacity(1024);
        loop {
            match reader.read_exact(&mut byte).await {
                Ok(_) => hdr.push(byte[0]),
                Err(e) => return Err(e).context("reading response headers"),
            }
            if hdr.len() >= 4 && &hdr[hdr.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if hdr.len() > 16384 {
                bail!("response headers too large");
            }
        }
        let text = String::from_utf8_lossy(&hdr).to_string();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .context("malformed status line")?;
        // Skip informational 1xx responses.
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        headers = text.lines().skip(1).map(|l| l.to_string()).collect();
        return read_body(&mut reader, &headers, status).await;
    }
}

fn header_value(headers: &[String], name: &str) -> Option<String> {
    headers.iter().find_map(|l| {
        l.split_once(':').and_then(|(k, v)| {
            if k.trim().eq_ignore_ascii_case(name) {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
    })
}

async fn read_body(
    reader: &mut BufReader<Box<dyn AsyncIo>>,
    headers: &[String],
    status: u16,
) -> Result<(u16, String)> {
    if let Some(len) = header_value(headers, "content-length").and_then(|v| v.parse::<usize>().ok())
    {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        return Ok((status, String::from_utf8_lossy(&buf).to_string()));
    }
    if header_value(headers, "transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        let mut out = Vec::new();
        loop {
            let mut line = Vec::new();
            loop {
                let mut b = [0u8; 1];
                reader.read_exact(&mut b).await?;
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            let size_str = String::from_utf8_lossy(&line);
            let size = usize::from_str_radix(size_str.trim(), 16).context("bad chunk size")?;
            if size == 0 {
                // Consume trailing CRLF (and any trailers — read until blank line).
                loop {
                    let mut l = Vec::new();
                    loop {
                        let mut b = [0u8; 1];
                        reader.read_exact(&mut b).await?;
                        if b[0] == b'\n' {
                            break;
                        }
                        l.push(b[0]);
                    }
                    if l.iter().all(|c| *c == b'\r') || l.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).await?;
            out.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
        }
        return Ok((status, String::from_utf8_lossy(&out).to_string()));
    }
    // No length: read until EOF (Connection: close).
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf).await;
    Ok((status, String::from_utf8_lossy(&buf).to_string()))
}

pub async fn post_json(url: &str, bearer: Option<&str>, body: &str) -> Result<(u16, String)> {
    request(url, "POST", bearer, Some(body)).await
}
