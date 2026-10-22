//! Minimal HTTP/1.1 client for outbound federation calls (replication).
//!
//! Transport policy: a peer configured with a `tls_pin` is contacted over TLS
//! with that pin enforced (AME-37). Plaintext is refused unless the peer is
//! loopback, so a replicated blob can never travel in cleartext to a remote
//! node just because a pin was omitted.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for a plaintext reply before concluding the peer speaks
/// TLS and retrying. Kept very short: a real plaintext loopback peer answers in
/// microseconds, while a TLS peer silently waits for more record bytes.
const PLAINTEXT_PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Upper bound on a peer response body. Without this a malicious peer can
/// stream until the node runs out of memory (it is fetching on demand, during
/// a request).
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A plain HTTP/1.1 client targeting a single host:port.
/// Used by the server to dial peers for blob replication.
#[derive(Debug, Clone)]
pub struct FedHttpClient {
    pub host: String,
    pub port: u16,
    /// Certificate pin for this peer. `None` means plaintext, which is only
    /// permitted for loopback.
    pub tls_pin: Option<String>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    /// Set once a plaintext probe turns out to be a TLS peer, so the remaining
    /// requests on this client (e.g. every blob in a namespace) skip the probe.
    peer_tls: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FedHttpClient {
    /// `endpoint` is `host:port`; IPv6 literals must be bracketed (`[::1]:8443`).
    pub fn new(endpoint: &str, tls_pin: Option<String>) -> Result<Self, io::Error> {
        let (host, port_str) = split_endpoint(endpoint)?;
        let port = port_str
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
        Ok(Self {
            host,
            port,
            tls_pin,
            connect_timeout: CONNECT_TIMEOUT,
            io_timeout: IO_TIMEOUT,
            peer_tls: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Plaintext is only ever allowed towards loopback (AME-37): replication
    /// moves whole plaintext blobs, so a missing pin must not silently
    /// downgrade a remote peer to cleartext.
    fn require_transport_ok(&self) -> io::Result<()> {
        if self.tls_pin.is_some() || is_loopback_host(&self.host) {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing plaintext federation to a remote peer without a tls_pin",
        ))
    }

    fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Build the raw HTTP/1.1 request bytes (headers + body).
    fn build_request(
        &self,
        method: &str,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.endpoint(),
            body.len()
        );
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Read a bounded response off an established stream.
    fn read_response(&self, stream: &mut dyn ReadWrite) -> io::Result<HttpResponse> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_RESPONSE_BYTES {
                return Err(io::Error::other("peer response exceeds MAX_RESPONSE_BYTES"));
            }
            buf.extend_from_slice(&chunk[..n]);
            // Stop as soon as the declared body has arrived rather than
            // waiting for the peer to close the connection.
            if let Some(done) = response_complete(&buf) {
                buf.truncate(done);
                break;
            }
        }
        parse_response(&buf)
    }

    /// Send a prebuilt request and read the reply.
    ///
    /// Transport: a configured pin means TLS-with-pin, full stop. Without a pin
    /// the peer must be loopback (AME-37). An endpoint-addressed peer carries
    /// no pin, so the scheme is unknown: try plaintext first (fast for a
    /// `--no-tls` peer) and, if that yields no parseable status line, retry
    /// over TLS in TOFU mode (accept the presented certificate). This is how a
    /// derived `pyle-<base64(host:port)>` id reaches a peer that runs TLS.
    fn send(&self, request: &[u8]) -> io::Result<HttpResponse> {
        self.require_transport_ok()?;
        if let Some(pin) = &self.tls_pin {
            let tcp = self.connect_tcp()?;
            let mut stream = hdap_tls::connect(
                tcp,
                &self.host,
                hdap_tls::PinVerifier::new(Some(pin.clone())),
            )?;
            stream.write_all(request)?;
            stream.flush()?;
            return self.read_response(&mut stream);
        }
        // Already learned this peer speaks TLS: skip straight to it.
        if self.peer_tls.load(std::sync::atomic::Ordering::Relaxed) {
            return self.tls_tofu(request);
        }
        // No pin, loopback: probe plaintext first with a short read deadline
        // (a TLS peer would otherwise hold the read until the full IO timeout).
        let mut plain = self.connect_tcp()?;
        plain.set_read_timeout(Some(PLAINTEXT_PROBE_TIMEOUT))?;
        let probe = plain
            .write_all(request)
            .and_then(|_| plain.flush())
            .and_then(|_| self.read_response(&mut plain));
        if let Ok(resp) = probe {
            if resp.status != 0 {
                return Ok(resp);
            }
        }
        // Empty, unparseable or timed-out reply: the peer speaks TLS. Remember
        // it so the rest of this client's requests go straight there.
        let resp = self.tls_tofu(request)?;
        self.peer_tls
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(resp)
    }

    /// Dial over TLS accepting the presented certificate (TOFU).
    fn tls_tofu(&self, request: &[u8]) -> io::Result<HttpResponse> {
        let tcp = self.connect_tcp()?;
        let mut stream = hdap_tls::connect(tcp, &self.host, hdap_tls::PinVerifier::new(None))?;
        stream.write_all(request)?;
        stream.flush()?;
        self.read_response(&mut stream)
    }

    fn connect_tcp(&self) -> io::Result<TcpStream> {
        let addrs: Vec<_> = (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no addresses resolved",
            ));
        }
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(self.io_timeout))?;
                    stream.set_write_timeout(Some(self.io_timeout))?;
                    return Ok(stream);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "could not connect")
        }))
    }

    /// Issue a GET request with federation auth headers. When `requester` is
    /// given, it is both sent as `X-HDAP-Requester` and folded into the signed
    /// payload, so the source enforces that user's authorization and the claim
    /// cannot be changed in flight.
    pub fn get_with_fed_auth(
        &self,
        path: &str,
        node_id: &str,
        sign_key: &SigningKey,
        requester: Option<&str>,
    ) -> io::Result<HttpResponse> {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // When pulling on a user's behalf, bind that identity into the signed
        // payload too: the source enforces *that user's* authorization, so a
        // tampered requester header cannot widen the pull.
        let payload = match requester {
            Some(r) => format!("{node_id}:{nonce}:{ts}:{r}"),
            None => format!("{node_id}:{nonce}:{ts}"),
        };
        let sig = sign_key.sign(payload.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let mut headers = BTreeMap::new();
        headers.insert("X-HDAP-Node-Id".to_string(), node_id.to_string());
        headers.insert("X-HDAP-Nonce".to_string(), nonce);
        headers.insert("X-HDAP-Timestamp".to_string(), ts.to_string());
        headers.insert("X-HDAP-Signature".to_string(), sig_b64);
        if let Some(r) = requester {
            headers.insert("X-HDAP-Requester".to_string(), r.to_string());
        }

        let request = self.build_request("GET", path, &headers, &[]);
        self.send(&request)
    }

    /// Issue an unauthenticated `GET` (health/registry discovery).
    pub fn get_json(&self, path: &str) -> io::Result<HttpResponse> {
        let headers = BTreeMap::new();
        let request = self.build_request("GET", path, &headers, &[]);
        self.send(&request)
    }

    /// Issue an unauthenticated `POST` with a JSON body (handshake).
    pub fn post_json(&self, path: &str, body: &str) -> io::Result<HttpResponse> {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let request = self.build_request("POST", path, &headers, body.as_bytes());
        self.send(&request)
    }

    /// Issue a `POST` signed as this node (federation auth). Used to push
    /// out-of-band updates such as deletion tombstones to peers that hold a
    /// replica; the body is not folded into the signature because the replay
    /// guard is the nonce and idempotency is the operation id inside the JSON.
    pub fn post_with_fed_auth(
        &self,
        path: &str,
        body: &str,
        node_id: &str,
        sign_key: &SigningKey,
    ) -> io::Result<HttpResponse> {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = format!("{node_id}:{nonce}:{ts}");
        let sig = sign_key.sign(payload.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let mut headers = BTreeMap::new();
        headers.insert("X-HDAP-Node-Id".to_string(), node_id.to_string());
        headers.insert("X-HDAP-Nonce".to_string(), nonce);
        headers.insert("X-HDAP-Timestamp".to_string(), ts.to_string());
        headers.insert("X-HDAP-Signature".to_string(), sig_b64);
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let request = self.build_request("POST", path, &headers, body.as_bytes());
        self.send(&request)
    }
}

/// Trait object for the two transports the client speaks.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Split `host:port`, accepting bracketed IPv6 literals (`[::1]:8443`) as well
/// as the plain `host:port` form. A bare `a:b:c` is rejected rather than
/// mis-split into host `a`, port `b`.
fn split_endpoint(endpoint: &str) -> io::Result<(String, &str)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unclosed IPv6 literal"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing port"))?;
        if host.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
        }
        return Ok((host.to_string(), port));
    }
    let (host, port) = endpoint
        .split_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint must be host:port"))?;
    if host.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
    }
    Ok((host.to_string(), port))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Total buffer length once the response is complete, if the peer declared a
/// `Content-Length`. `None` means "keep reading until EOF".
fn response_complete(buf: &[u8]) -> Option<usize> {
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))?;
    let (head_idx, sep) = head_end;
    let head = String::from_utf8_lossy(&buf[..head_idx]).to_lowercase();
    for line in head.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim() == "content-length" {
                if let Ok(n) = value.trim().parse::<usize>() {
                    let have = buf.len() - (head_idx + sep);
                    if have >= n {
                        return Some(head_idx + sep + n);
                    }
                    return None;
                }
            }
        }
    }
    None
}

fn parse_response(buf: &[u8]) -> io::Result<HttpResponse> {
    let mut headers = BTreeMap::new();
    let mut status = 0;
    let mut in_headers = true;
    for (i, line) in buf.split(|b| *b == b'\n').enumerate() {
        if i == 0 {
            // Status line
            let parts: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
            if parts.len() >= 2 {
                status = std::str::from_utf8(parts[1])
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            }
            continue;
        }
        if in_headers {
            if line.len() <= 1 {
                // Empty line -> end of headers
                in_headers = false;
                continue;
            }
            if let Some(pos) = line.iter().position(|b| *b == b':') {
                let key = std::str::from_utf8(&line[..pos])
                    .unwrap_or("")
                    .to_lowercase();
                let val = std::str::from_utf8(&line[pos + 1..])
                    .unwrap_or("")
                    .trim()
                    .to_string();
                headers.insert(key, val);
            }
        }
    }
    // Find body start in original buffer
    let mut body = Vec::new();
    for (i, window) in buf.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            body = buf[i + 4..].to_vec();
            break;
        }
    }
    if body.is_empty() {
        for (i, window) in buf.windows(2).enumerate() {
            if window == b"\n\n" {
                body = buf[i + 2..].to_vec();
                break;
            }
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_split_host_and_port() {
        let c = FedHttpClient::new("example.org:8443", None).unwrap();
        assert_eq!(c.host, "example.org");
        assert_eq!(c.port, 8443);
    }

    #[test]
    fn bracketed_ipv6_endpoints_are_accepted() {
        let c = FedHttpClient::new("[::1]:8443", None).unwrap();
        assert_eq!(c.host, "::1");
        assert_eq!(c.port, 8443);
        // Re-rendered bracketed, so the Host header stays parseable.
        assert_eq!(c.endpoint(), "[::1]:8443");
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        for bad in ["example.org", "[::1]8443", ":8443", ""] {
            assert!(FedHttpClient::new(bad, None).is_err(), "accepted {bad:?}");
        }
    }

    /// AME-37: a remote peer without a pin must not be contacted in cleartext.
    #[test]
    fn plaintext_is_refused_for_remote_peers_without_a_pin() {
        let c = FedHttpClient::new("198.51.100.7:8443", None).unwrap();
        let err = c.require_transport_ok().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // A configured pin is always allowed.
        let pinned = FedHttpClient::new("198.51.100.7:8443", Some("sha256:aa".into())).unwrap();
        assert!(pinned.require_transport_ok().is_ok());
    }

    #[test]
    fn plaintext_is_allowed_only_for_loopback() {
        // IPv6 literals must be bracketed, exactly as on the wire.
        for host in ["127.0.0.1:8443", "localhost:8443", "[::1]:8443"] {
            let c = FedHttpClient::new(host, None).unwrap();
            assert!(
                c.require_transport_ok().is_ok(),
                "loopback {host} should be allowed"
            );
        }
    }

    #[test]
    fn a_declared_body_length_ends_the_read() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello-and-more";
        // The declared body is complete before the buffer ends: stop there.
        assert_eq!(response_complete(raw), Some(raw.len() - b"-and-more".len()));
    }

    #[test]
    fn an_incomplete_body_keeps_the_read_open() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhello";
        assert_eq!(response_complete(raw), None);
    }

    #[test]
    fn a_response_without_content_length_reads_until_eof() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nhello";
        assert_eq!(response_complete(raw), None);
    }

    #[test]
    fn responses_are_parsed_from_the_header_block() {
        let raw = b"HTTP/1.1 200 OK\r\nX-HDAP-Hash: abc\r\nContent-Length: 3\r\n\r\nxyz";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.headers.get("x-hdap-hash").map(String::as_str),
            Some("abc")
        );
        assert_eq!(r.body, b"xyz");
    }
}
