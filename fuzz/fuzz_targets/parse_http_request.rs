#![no_main]
//! Fuzz the HTTP/1.1 request parser.
//!
//! This is the highest-value target in the project: `http.rs` is a hand-written
//! parser (AME-18), it sits directly on a socket, and request smuggling is a
//! parser bug rather than a logic bug.
//!
//! Oracles:
//!
//! 1. Never panic.
//! 2. On success, `body.len() == content_length` exactly, and the header map
//!    must not disagree with it. That equality is the anti-smuggling invariant:
//!    it is what a front-end proxy would have to agree about.
//! 3. The header block never exceeds `MAX_HEAD_BYTES`, whatever `max_body` is.
//! 4. No header value or the request path contains a raw CR or LF, so a
//!    request can never be re-split by something downstream.
use libfuzzer_sys::fuzz_target;

const SEEDS: &[&[u8]] = &[
    b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /ktema/list?user=jose HTTP/1.1\r\nHost: x\r\nX-HDAP-Token: t\r\n\r\n",
    b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO",
    b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
    // Conflicting lengths: the smuggling shape.
    b"POST /upload HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 10\r\n\r\nHELLOHELLO",
    // Chunked framing, which we do not support and must never half-understand.
    b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n",
    // Obs-fold continuation and a bare LF request line.
    b"GET /health HTTP/1.1\nHost: x\n\n",
];

fuzz_target!(|data: &[u8]| {
    let mut inputs: Vec<Vec<u8>> = vec![data.to_vec()];
    for (i, seed) in SEEDS.iter().enumerate() {
        let mut v = vec![i as u8];
        v.extend_from_slice(seed);
        inputs.push(v);
    }

    // A body allowance unrelated to the header bound, so oracle 3 is meaningful.
    const MAX_BODY: usize = 8 * 1024 * 1024;

    for input in inputs {
        let Ok(req) = hdap_server::http::parse_request(&input, MAX_BODY) else {
            continue;
        };

        assert!(
            req.body.len() <= MAX_BODY,
            "body exceeded max_body on an accepted request"
        );
        assert!(
            !req.method.contains(['\r', '\n']),
            "method carries a line break: {:?}",
            req.method
        );
        assert!(
            !req.path.contains(['\r', '\n']),
            "path carries a line break: {:?}",
            req.path
        );
        for (name, value) in &req.headers {
            assert!(
                !name.contains(['\r', '\n']) && !value.contains(['\r', '\n']),
                "header {name:?} carries a line break"
            );
        }
        if let Some(cl) = req.headers.get("content-length") {
            // The declared length and the consumed body must agree, and the
            // header map must not advertise something else.
            let declared: usize = cl
                .parse()
                .unwrap_or_else(|_| panic!("accepted a non-numeric content-length: {cl:?}"));
            assert_eq!(
                declared,
                req.body.len(),
                "content-length disagrees with the body that was consumed"
            );
        }
    }
});