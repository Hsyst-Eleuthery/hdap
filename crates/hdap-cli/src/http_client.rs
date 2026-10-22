//! Minimal HTTP/1.1 client over `std::net::TcpStream` — mirrors the server's
//! own transport (`hdap-server::http`). Supports plaintext (loopback/dev) and
//! TLS with per-node self-signed certificate pinning (AME-09).

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Network timeouts so a GUI can never hang its UI thread on a bad peer:
/// resolve+connect bounded, and read/write bounded.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// A parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    /// Lower-cased header names.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A plain or TLS HTTP/1.1 client targeting a single host:port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClient {
    pub host: String,
    pub port: u16,
    /// TLS mandatory (pinning) when true; plaintext (loopback/dev) when false.
    pub use_tls: bool,
    /// Certificate pin (SHA-256 of the node's TLS cert DER). `Some` → must
    /// match exactly; `None` (with `use_tls`) → TOFU on the first connection.
    pub tls_pin: Option<String>,
    /// Bound on TCP connect (and the TLS handshake that follows).
    pub connect_timeout: Duration,
    /// Bound on each socket read/write, i.e. waiting for the node's answer.
    pub io_timeout: Duration,
}

impl HttpClient {
    /// Override the network timeouts (used by tests to keep them short).
    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    /// `endpoint` for human-facing error messages.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// On Linux an expired `SO_RCVTIMEO`/`SO_SNDTIMEO` surfaces as `EAGAIN`
    /// ("Resource temporarily unavailable"), which reads like a transient
    /// error instead of the timeout it actually is. Rewrite it so the node
    /// that went silent is named.
    fn explain(&self, phase: &str, e: io::Error) -> io::Error {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) || e.raw_os_error() == Some(11)
        {
            return io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timeout de {phase} em {} após {:?} — o nó não respondeu",
                    self.endpoint(),
                    if phase == "conexão" {
                        self.connect_timeout
                    } else {
                        self.io_timeout
                    }
                ),
            );
        }
        e
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn target(path: &str, query: &BTreeMap<String, String>) -> String {
    if query.is_empty() {
        return path.to_string();
    }
    let q = query
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{q}")
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

fn header_content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(n) = value.trim().parse() {
                    return n;
                }
            }
        }
    }
    0
}

fn parse_response(raw: &[u8]) -> io::Result<HttpResponse> {
    let pos = find_head_end(raw).ok_or_else(|| io::Error::other("malformed response"))?;
    let head = &raw[..pos];
    let body_raw = &raw[pos + 4..];
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::other("empty status"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("bad status line"))?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers
                .entry(name.trim().to_ascii_lowercase())
                .or_insert_with(|| value.trim().to_string());
        }
    }
    let declared = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(body_raw.len());
    let body = body_raw[..body_raw.len().min(declared)].to_vec();
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

impl HttpClient {
    pub fn new(host: &str, port: u16) -> Self {
        HttpClient {
            host: host.to_string(),
            port,
            use_tls: false,
            tls_pin: None,
            connect_timeout: CONNECT_TIMEOUT,
            io_timeout: IO_TIMEOUT,
        }
    }

    /// TLS client pinned to the node's self-signed certificate (AME-09).
    /// An empty `tls_pin` behaves as "no pin yet" → TOFU on first connect.
    pub fn new_tls(host: &str, port: u16, tls_pin: String) -> Self {
        HttpClient {
            host: host.to_string(),
            port,
            use_tls: true,
            tls_pin: if tls_pin.trim().is_empty() {
                None
            } else {
                Some(tls_pin)
            },
            connect_timeout: CONNECT_TIMEOUT,
            io_timeout: IO_TIMEOUT,
        }
    }

    fn connect(&self) -> io::Result<TlsOrPlain> {
        let addr: SocketAddr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| self.explain("conexão", e))?
            .next()
            .ok_or_else(|| io::Error::other("host did not resolve"))?;
        let tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)
            .map_err(|e| self.explain("conexão", e))?;
        tcp.set_read_timeout(Some(self.io_timeout))?;
        tcp.set_write_timeout(Some(self.io_timeout))?;
        if self.use_tls {
            hdap_tls::connect(
                tcp,
                &self.host,
                hdap_tls::PinVerifier::new(self.tls_pin.clone()),
            )
            .map_err(|e| self.explain("handshake TLS", e))
            .map(TlsOrPlain::Tls)
        } else {
            Ok(TlsOrPlain::Plain(tcp))
        }
    }

    /// Issue a raw request. Query values are percent-encoded.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> io::Result<HttpResponse> {
        let mut stream = self.connect()?;
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            target(path, query),
            self.host,
            body.len()
        );
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .map_err(|e| self.explain("escrita", e))?;
        stream
            .write_all(body)
            .map_err(|e| self.explain("escrita", e))?;
        stream.flush().map_err(|e| self.explain("escrita", e))?;

        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream
                .read(&mut buf)
                .map_err(|e| self.explain("leitura", e))?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_head_end(&raw) {
                let declared = header_content_length(&raw[..pos]);
                if raw.len() >= pos + 4 + declared {
                    break;
                }
            }
        }
        parse_response(&raw)
    }

    pub fn get(&self, path: &str, query: &BTreeMap<String, String>) -> io::Result<HttpResponse> {
        self.request("GET", path, query, &BTreeMap::new(), &[])
    }

    pub fn get_with_token(
        &self,
        path: &str,
        query: &BTreeMap<String, String>,
        token: &str,
    ) -> io::Result<HttpResponse> {
        let mut headers = BTreeMap::new();
        headers.insert("x-hdap-token".to_string(), token.to_string());
        self.request("GET", path, query, &headers, &[])
    }

    pub fn post_with_token(
        &self,
        path: &str,
        query: &BTreeMap<String, String>,
        token: &str,
        body: &[u8],
    ) -> io::Result<HttpResponse> {
        let mut headers = BTreeMap::new();
        headers.insert("x-hdap-token".to_string(), token.to_string());
        self.request("POST", path, query, &headers, body)
    }
}

/// A transport that is either a plain TCP socket or a pinned TLS stream.
#[allow(clippy::large_enum_variant)]
enum TlsOrPlain {
    Plain(TcpStream),
    Tls(hdap_tls::ClientStream),
}

impl Read for TlsOrPlain {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TlsOrPlain::Plain(s) => s.read(buf),
            TlsOrPlain::Tls(s) => s.read(buf),
        }
    }
}

impl Write for TlsOrPlain {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TlsOrPlain::Plain(s) => s.write(buf),
            TlsOrPlain::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TlsOrPlain::Plain(s) => s.flush(),
            TlsOrPlain::Tls(s) => s.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_escapes_space_and_plus() {
        assert_eq!(urlencode("a b+c"), "a%20b%2Bc");
        assert_eq!(urlencode("docs/segredo"), "docs%2Fsegredo");
    }

    #[test]
    fn target_builds_query_string() {
        let mut q = BTreeMap::new();
        q.insert("owner".to_string(), "jose x".to_string());
        q.insert("path".to_string(), "a/b".to_string());
        assert_eq!(target("/ktema", &q), "/ktema?owner=jose%20x&path=a%2Fb");
        assert_eq!(target("/ktema", &BTreeMap::new()), "/ktema");
    }

    #[test]
    fn parses_response_with_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nX-HDAP-Hash: ab\r\n\r\nhello";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.headers["content-length"], "5");
        assert_eq!(resp.body, b"hello");
    }

    /// A peer that accepts the TCP connection and then never answers must
    /// surface as `TimedOut` naming the node — not as the raw
    /// `EAGAIN`/"Resource temporarily unavailable" that `SO_RCVTIMEO`
    /// produces, which is what the GUI used to show.
    #[test]
    fn unresponsive_peer_reports_a_named_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Accept and hold the socket open without replying.
            if let Ok((sock, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(30));
                drop(sock);
            }
        });
        let c = HttpClient::new("127.0.0.1", port)
            .with_timeouts(Duration::from_secs(2), Duration::from_millis(300));
        let err = c
            .request("GET", "/health", &BTreeMap::new(), &BTreeMap::new(), &[])
            .expect_err("silent peer must not answer");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("leitura"), "should name the phase: {msg}");
        assert!(
            msg.contains(&format!("127.0.0.1:{port}")),
            "should name the node: {msg}"
        );
        assert!(
            !msg.contains("Resource temporarily unavailable"),
            "EAGAIN leaked through: {msg}"
        );
    }

    /// A black-holed address must fail with the connect phase named.
    #[test]
    fn unreachable_host_reports_a_named_connect_timeout() {
        let c = HttpClient::new("10.255.255.1", 9)
            .with_timeouts(Duration::from_millis(400), Duration::from_millis(400));
        let err = c
            .request("GET", "/health", &BTreeMap::new(), &BTreeMap::new(), &[])
            .expect_err("unroutable peer must not answer");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("conexão"), "should name the phase: {msg}");
        assert!(
            msg.contains("10.255.255.1:9"),
            "should name the node: {msg}"
        );
    }
}
