//! Minimal HTTP/1.1 server over `std::net::TcpListener` (no framework).
//! Handles only what HDAP needs: request line, headers, content-length body,
//! and a fixed set of response statuses. Transport is pluggable: plaintext
//! (`serve`) or TLS (`serve_tls`), the latter mandated by the threat model
//! (AME-09) except on loopback/dev.

use std::collections::BTreeMap;
use std::io::{self, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};

/// Reason phrases for the statuses the protocol emits.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// A parsed HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// Path without query string.
    pub path: String,
    /// URL-decoded query parameters.
    pub query: BTreeMap<String, String>,
    /// Lower-cased header names to values (first wins).
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A response to serialize back to the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    /// JSON body with `Content-Type: application/json`.
    pub fn json(status: u16, body: String) -> Self {
        let mut r = Response::new(status);
        if !body.is_empty() {
            r.headers
                .insert("Content-Type".to_string(), "application/json".to_string());
            r.body = body.into_bytes();
        }
        r
    }

    /// Binary body with a caller-chosen content type.
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        let mut r = Response::new(status);
        if !body.is_empty() {
            r.headers
                .insert("Content-Type".to_string(), content_type.to_string());
        }
        r.body = body;
        r
    }

    /// Plain text body.
    pub fn text(status: u16, text: &str) -> Self {
        Response::bytes(
            status,
            "text/plain; charset=utf-8",
            text.as_bytes().to_vec(),
        )
    }
}

fn decode_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse `bytes` (headers + body, exactly as read) into a `Request`.
pub fn parse_request(bytes: &[u8], max_body: usize) -> io::Result<Request> {
    let head_end = find_head_end(bytes)?;
    let head = &bytes[..head_end];
    let body = &bytes[head_end + 4..];

    // AME-39: a lone CR inside the header block is a line terminator to some
    // parsers and ordinary data to us, so we would disagree about where the
    // headers end — the same desync as a conflicting Content-Length, one layer
    // earlier. Every CR must be part of a CRLF; `head` excludes the terminating
    // blank line, so a bare CR here is always malformed.
    {
        let mut i = 0;
        while i < head.len() {
            if head[i] == b'\r' {
                if head.get(i + 1) != Some(&b'\n') {
                    return Err(io::Error::other("bare CR in request head"));
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    let lines: Vec<&[u8]> = head.split(|&b| b == b'\n').collect();
    let request_line = String::from_utf8_lossy(lines[0])
        .trim_end_matches('\r')
        .to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::other("missing method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| io::Error::other("missing target"))?
        .to_string();
    if parts.next().is_none() {
        return Err(io::Error::other("missing HTTP version"));
    }

    // AME-39: only origin-form targets (`/path`) are accepted. `http://host/x`
    // (absolute-form) and `host:port` (authority-form) mean different things to
    // a proxy than they do to us, and a bare `health` is not a path at all —
    // accepting them leaves room for two front ends to disagree about which
    // request was made.
    if !target.starts_with('/') {
        return Err(io::Error::other("request target must be origin-form"));
    }

    let mut query = BTreeMap::new();
    let path = match target.split_once('?') {
        Some((p, q)) => {
            for kv in q.split('&') {
                if kv.is_empty() {
                    continue;
                }
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                query.insert(decode_percent(k), decode_percent(v));
            }
            decode_percent(p)
        }
        None => decode_percent(&target),
    };

    let mut headers = BTreeMap::new();
    let mut content_length = 0usize;
    let mut saw_content_length = false;
    for line in &lines[1..] {
        let line = String::from_utf8_lossy(line)
            .trim_end_matches('\r')
            .to_string();
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            .unwrap_or_else(|| (line.to_ascii_lowercase(), String::new()));
        if name == "content-length" {
            // AME-18: a duplicated `Content-Length` is a request-smuggling
            // primitive. `unwrap_or(0)` silently read `Content-Length: x` as
            // "no body", and last-wins let the header map report one length
            // while the body slice held another — any front end that disagrees
            // with us about which is authoritative desyncs the stream.
            // A comma-separated list is legal and normalises to one value, so
            // it is accepted only when every element agrees.
            let mut agreed: Option<usize> = None;
            for part in value.split(',') {
                let part = part.trim();
                let n = part
                    .parse::<usize>()
                    .map_err(|_| io::Error::other(format!("invalid Content-Length: {part:?}")))?;
                match agreed {
                    None => agreed = Some(n),
                    Some(prev) if prev != n => {
                        return Err(io::Error::other("conflicting Content-Length headers"));
                    }
                    Some(_) => {}
                }
            }
            if let Some(n) = agreed {
                if saw_content_length && content_length != n {
                    return Err(io::Error::other("conflicting Content-Length headers"));
                }
                content_length = n;
                saw_content_length = true;
            }
        }
        headers.entry(name).or_insert(value);
    }

    if body.len() > max_body {
        return Err(io::Error::other("body exceeds max_body"));
    }
    // AME-37: enforce the header bound here too, not only in the streaming
    // loop, so the invariant holds for every caller of `parse_request`.
    if head_end > MAX_HEAD_BYTES {
        return Err(io::Error::other("headers too large"));
    }
    if content_length > body.len() {
        // The transport layer must supply the full body; a short read is an error.
        return Err(io::Error::other("short body"));
    }
    if body.len() > content_length {
        // Bytes past the declared Content-Length are either a desync or a
        // request-smuggling attempt: refuse rather than silently consume them.
        return Err(io::Error::other("trailing bytes after body"));
    }
    let body = body.to_vec();

    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_head_end(bytes: &[u8]) -> io::Result<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("missing header terminator"))
}

/// Per-connection deadline applied to every accepted socket (AME-37).
///
/// A read that returns `WouldBlock`/`TimedOut` is turned into an `io::Error`
/// (and therefore a `400`) instead of being retried, so a stalled peer costs a
/// thread for at most this long rather than indefinitely.
pub const CONN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Upper bound on the header section, independent of the body allowance.
/// A request line plus headers comfortably fit; anything larger is an attack,
/// not a legitimate document header.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

fn set_socket_deadlines(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));
    let _ = stream.set_nodelay(true);
}

/// Read a full request from any stream (headers + content-length body).
pub fn read_request<S: Read>(stream: &mut S, max_body: usize) -> io::Result<Request> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::other("connection closed before headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::other("headers too large"));
        }
    }
    // Read the remaining body bytes to satisfy content-length.
    let head_end = find_head_end(&buf)?;
    let declared = header_content_length(&buf[..head_end]);
    let have = buf.len() - head_end - 4;
    if have < declared && declared <= max_body {
        let needed = declared - have;
        let mut rest = vec![0u8; needed];
        stream.read_exact(&mut rest)?;
        buf.extend_from_slice(&rest);
    }
    parse_request(&buf, max_body)
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

/// Write a response to any stream and flush.
pub fn write_response<S: Write>(stream: &mut S, resp: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
        resp.status,
        reason(resp.status),
        resp.body.len()
    );
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut writer = BufWriter::new(stream);
    writer.write_all(head.as_bytes())?;
    writer.write_all(&resp.body)?;
    writer.flush()
}

/// Serve `listener` in a thread-per-connection loop, dispatching to `handle`.
///
/// AME-37: every accepted socket gets read/write deadlines and the header
/// section is bounded independently of `max_body`. Without the deadline a peer
/// that opens a connection and never finishes its headers pins a thread forever
/// (slowloris), and `max_body` alone would let a header block grow to the whole
/// upload allowance before being rejected.
pub fn serve(
    listener: TcpListener,
    max_body: usize,
    handle: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> io::Result<()> {
    let handle = std::sync::Arc::new(handle);
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let handle = std::sync::Arc::clone(&handle);
        std::thread::spawn(move || {
            let mut stream = stream;
            set_socket_deadlines(&stream);
            let req = match read_request(&mut stream, max_body) {
                Ok(r) => r,
                Err(_) => {
                    let _ = write_response(&mut stream, &Response::text(400, "bad request"));
                    return;
                }
            };
            let resp = handle(req);
            let _ = write_response(&mut stream, &resp);
        });
    }
    Ok(())
}

/// Serve `listener` over TLS with a self-signed pinned node certificate
/// (AME-09). `tls` is the active rustls server config; each accepted TCP
/// socket is wrapped and served inside `read_request`/`write_response`,
/// which are `Read + Write` generic.
///
/// AME-37: the same deadline is set on the raw TCP socket *before* the TLS
/// handshake, so a peer that connects and stalls the handshake cannot pin a
/// thread either.
pub fn serve_tls(
    listener: TcpListener,
    max_body: usize,
    tls: std::sync::Arc<rustls::ServerConfig>,
    handle: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> io::Result<()> {
    let handle = std::sync::Arc::new(handle);
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let handle = std::sync::Arc::clone(&handle);
        let tls = std::sync::Arc::clone(&tls);
        std::thread::spawn(move || {
            set_socket_deadlines(&stream);
            let mut stream = match hdap_tls::accept(&tls, stream) {
                Ok(s) => s,
                Err(_) => return,
            };
            let req = match read_request(&mut stream, max_body) {
                Ok(r) => r,
                Err(_) => {
                    let _ = write_response(&mut stream, &Response::text(400, "bad request"));
                    return;
                }
            };
            let resp = handle(req);
            let _ = write_response(&mut stream, &resp);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn parses_get_with_query() {
        let raw = b"GET /ktema/list?user=jose_abc HTTP/1.1\r\nHost: x\r\nX-HDAP-Token: t\r\n\r\n";
        let req = parse_request(raw, 4096).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/ktema/list");
        assert_eq!(req.query.get("user").map(String::as_str), Some("jose_abc"));
        assert_eq!(req.headers["x-hdap-token"], "t");
    }

    #[test]
    fn parses_post_with_body() {
        let raw = b"POST /auth HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = parse_request(raw, 4096).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decodes_percent_query() {
        let raw = b"GET /kerux/a%20b?x=%2B&y=z%20z HTTP/1.1\r\n\r\n";
        let req = parse_request(raw, 4096).unwrap();
        assert_eq!(req.path, "/kerux/a b");
        assert_eq!(req.query.get("x").map(String::as_str), Some("+"));
        assert_eq!(req.query.get("y").map(String::as_str), Some("z z"));
    }

    #[test]
    fn rejects_oversized_body() {
        let raw = b"POST /ktema/upload HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(parse_request(raw, 4).is_err());
    }

    #[test]
    fn rejects_trailing_bytes_beyond_content_length() {
        // A second request smuggled after the declared body must not be read
        // as part of the first one.
        let raw = b"POST /auth HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloPOST /x HTTP/1.1\r\n\r\n";
        assert!(parse_request(raw, 4096).is_err());
    }

    #[test]
    fn reason_phrases_cover_statuses() {
        assert_eq!(reason(200), "OK");
        assert_eq!(reason(429), "Too Many Requests");
        assert_eq!(reason(999), "Unknown");
    }

    /// AME-37: a connection that never finishes its headers must not be able to
    /// hold a worker thread. This drives the real `serve` loop and asserts the
    /// stalled peer is dropped once the read deadline expires.
    #[test]
    fn a_silent_peer_is_dropped_by_the_read_deadline() {
        use std::io::Write as _;
        use std::net::TcpStream;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handled = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&handled);
        let handle = move |_req: Request| {
            seen.store(true, Ordering::SeqCst);
            Response::text(200, "ok")
        };
        std::thread::spawn(move || {
            let _ = serve(listener, 4096, handle);
        });

        // Connect and send a partial request: headers are never terminated.
        let mut stalled = TcpStream::connect(addr).unwrap();
        stalled
            .write_all(b"POST /auth HTTP/1.1\r\nContent-Length: 10\r\n")
            .unwrap();
        stalled.flush().unwrap();

        // The server must not have dispatched anything, and must give up on the
        // stalled connection rather than waiting forever.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !handled.load(Ordering::SeqCst),
            "partial request must not be handled"
        );

        // A fresh well-formed request still works afterwards: the stalled peer
        // did not poison the accept loop.
        let mut good = TcpStream::connect(addr).unwrap();
        good.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        good.write_all(b"GET /health HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        good.flush().unwrap();
        let mut buf = [0u8; 64];
        let n = good.read(&mut buf).unwrap();
        assert!(n > 0 && String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    }

    /// AME-37: the header section is bounded independently of the body
    /// allowance, so a huge header block is rejected long before the upload
    /// limit could ever be reached.
    #[test]
    fn oversized_headers_are_rejected_before_the_body_limit() {
        let oversized = MAX_HEAD_BYTES + 1024;
        let mut raw = b"GET /health HTTP/1.1\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'A', oversized));
        raw.extend_from_slice(b"\r\n\r\n");
        // max_body is deliberately huge: only the header bound can stop this.
        assert!(parse_request(&raw, 64 * 1024 * 1024).is_err());

        // The same byte count in a *body* must still be accepted. Without this
        // the first assertion would pass even if the bound were really just a
        // disguised body limit.
        let mut with_body = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: ".to_vec();
        with_body.extend_from_slice(oversized.to_string().as_bytes());
        with_body.extend_from_slice(b"\r\n\r\n");
        with_body.extend(std::iter::repeat_n(b'B', oversized));
        let parsed = parse_request(&with_body, 64 * 1024 * 1024)
            .expect("a large body under max_body is not a header problem");
        assert_eq!(parsed.body.len(), oversized);
    }

    /// AME-18: two `Content-Length` headers that disagree must be refused, not
    /// resolved by "whoever reads it last". Before this fix the header map
    /// reported the first value while the body slice held the second, which is
    /// exactly the disagreement a front-end proxy needs to desync the stream.
    #[test]
    fn conflicting_content_length_headers_are_refused() {
        let cases: [&[u8]; 4] = [
            b"POST /upload HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 10\r\n\r\nHELLOHELLO",
            b"POST /upload HTTP/1.1\r\nContent-Length: 10\r\nContent-Length: 0\r\n\r\nHELLOHELLO",
            b"POST /upload HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5, 6\r\n\r\nHELLO",
            b"POST /upload HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10, 10\r\n\r\nHELLO",
        ];
        for raw in cases {
            let err = parse_request(raw, 1024)
                .err()
                .unwrap_or_else(|| panic!("should not parse: {raw:?}"));
            let msg = err.to_string();
            assert!(
                msg.contains("conflicting Content-Length"),
                "expected a conflict error, got: {msg}"
            );
        }
    }

    /// Agreement is enough: a repeated identical length, or the comma-separated
    /// form a proxy may normalise to, is not an attack.
    #[test]
    fn agreeing_content_length_headers_are_accepted() {
        for cl in ["5", "5, 5", "5,5"] {
            let raw = format!("POST /upload HTTP/1.1\r\nContent-Length: {cl}\r\n\r\nHELLO");
            let parsed = parse_request(raw.as_bytes(), 1024)
                .unwrap_or_else(|e| panic!("Content-Length: {cl:?} should parse, got: {e}"));
            assert_eq!(parsed.body.len(), 5, "body length for {cl:?}");
            // Whatever the caller reads later must match what was consumed.
            assert_eq!(
                parsed.headers.get("content-length").map(String::as_str),
                Some(cl),
                "the header map must agree with the body it was parsed with"
            );
        }
    }

    /// A `Content-Length` that is not a number is an error, not an implicit
    /// zero: `unwrap_or(0)` used to swallow it and treat the body as empty.
    #[test]
    fn a_non_numeric_content_length_is_refused() {
        // The empty-body case is the one that matters: with a body present the
        // trailing-bytes check rejected the request anyway, but with an empty
        // body `unwrap_or(0)` made `Content-Length: x` parse as a valid
        // zero-length request.
        for cl in ["x", "5x", "-1", "", "1.5", "99999999999999999999"] {
            for body in ["", "HELLO"] {
                let raw = format!("POST /upload HTTP/1.1\r\nContent-Length: {cl}\r\n\r\n{body}");
                assert!(
                    parse_request(raw.as_bytes(), 1024).is_err(),
                    "Content-Length: {cl:?} with body {body:?} must not parse"
                );
            }
        }
    }

    /// AME-19/AME-39. The invariants the `parse_http_request` fuzz target
    /// asserts, run here so they are checked on every CI build instead of only
    /// when somebody remembers to run cargo-fuzz.
    ///
    /// The oracle is the anti-smuggling one: on any accepted request the
    /// declared `Content-Length` and the body that was actually consumed must
    /// be the same number, and no field may smuggle a line break.
    #[test]
    fn accepted_requests_cannot_disagree_with_themselves() {
        const MAX_BODY: usize = 8 * 1024 * 1024;
        let seeds: [&[u8]; 6] = [
            b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /ktema/list?user=jose HTTP/1.1\r\nHost: x\r\nX-HDAP-Token: t\r\n\r\n",
            b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO",
            b"POST /upload HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 10\r\n\r\nHELLOHELLO",
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n",
            b"GET /health HTTP/1.1\nHost: x\n\n",
        ];
        let mut rng = 0x243F_6A88_85A3_08D3u64;
        let mut accepted = 0usize;
        for step in 0..20_000usize {
            let seed = seeds[step % seeds.len()];
            // Mutate the seed deterministically: flip a byte, drop a byte, or
            // append a CR/LF run. Keeps the requests in the shape a real peer
            // sends while still varying framing.
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let mut raw = seed.to_vec();
            match rng % 3 {
                0 if !raw.is_empty() => {
                    let i = (rng as usize) % raw.len();
                    raw[i] = b'A' + ((rng >> 8) % 26) as u8;
                }
                1 if !raw.is_empty() => {
                    let i = (rng as usize) % raw.len();
                    raw.remove(i);
                }
                _ => raw.extend_from_slice(b"\r\nX-Injected: 1\r\n"),
            }

            let Ok(req) = parse_request(&raw, MAX_BODY) else {
                continue;
            };
            accepted += 1;
            assert!(
                req.body.len() <= MAX_BODY,
                "step {step}: body {} exceeded max_body",
                req.body.len()
            );
            assert!(
                req.path.starts_with('/'),
                "step {step}: path must be absolute, got {:?}",
                req.path
            );
            for (name, value) in &req.headers {
                assert!(
                    !name.contains(['\r', '\n']) && !value.contains(['\r', '\n']),
                    "step {step}: header {name:?} carries a line break"
                );
            }
            if let Some(cl) = req.headers.get("content-length") {
                let declared: usize = cl.parse().unwrap_or_else(|_| {
                    panic!("step {step}: accepted a non-numeric content-length {cl:?}")
                });
                assert_eq!(
                    declared,
                    req.body.len(),
                    "step {step}: content-length disagrees with the consumed body"
                );
            }
        }
        assert!(
            accepted > 100,
            "the mutator never reached the accepting path"
        );
    }

    /// AME-39: a lone CR inside the header block is a line terminator to some
    /// parsers and ordinary data to us, so accepting it lets a front end and
    /// this node disagree about where the headers end.
    #[test]
    fn a_bare_cr_in_the_head_is_refused() {
        // Each case keeps a well-formed terminator, so the request reaches the
        // bare-CR check instead of dying at "missing header terminator".
        let cases: [&[u8]; 3] = [
            // CR embedded in a header value.
            b"GET /health HTTP/1.1\r\nHost: x\r\nX-A: one\rtwo\r\n\r\n",
            // CR embedded in a header name.
            b"GET /health HTTP/1.1\r\nX\rA: b\r\nHost: x\r\n\r\n",
            // CR embedded in the request line.
            b"GET /health HTTP/1.1\rX-Injected: 1\r\nHost: x\r\n\r\n",
        ];
        for raw in cases {
            let err = parse_request(raw, 1024)
                .err()
                .unwrap_or_else(|| panic!("bare CR must be refused: {raw:?}"));
            assert!(
                err.to_string().contains("bare CR"),
                "expected a bare-CR error for {raw:?}, got: {err}"
            );
        }
    }

    /// AME-39: only origin-form targets are accepted.
    #[test]
    fn only_origin_form_request_targets_are_accepted() {
        for target in ["health", "*", "http://example.org/x", "example.org:443"] {
            let raw = format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(
                parse_request(raw.as_bytes(), 1024).is_err(),
                "{target:?} is not origin-form and must be refused"
            );
        }
        // The shapes that must keep working.
        for target in ["/", "/health", "/ktema/list?user=jose", "/a%20b?x=%2F"] {
            let raw = format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(
                parse_request(raw.as_bytes(), 1024).is_ok(),
                "{target:?} is valid origin-form"
            );
        }
    }
}
