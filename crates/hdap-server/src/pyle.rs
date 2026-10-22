//! Endpoint-addressed pyle identifiers.
//!
//! A node names itself after the address it listens on:
//!
//! ```text
//! pyle-<base64url(host:port)>      e.g. pyle-bG9jYWxob3N0OjM4NDU
//! ```
//!
//! The id therefore *is* the address. An access URI
//! (`HDAP!pyle-bG9jYWxob3N0OjM4NDU@user/path`) carries everything a peer needs
//! to find the node, so cross-pyle resolution does not depend on a separate
//! out-of-band registry just to know *where* a named pyle lives. Encoding is
//! URL-safe base64 without padding, so the id is safe inside a URI path.
//!
//! The id certifies *location*, not identity: reaching the endpoint proves
//! nothing about who answers there. Content trust still comes from the author
//! signature and the content hash, and peer trust from the key pinned on first
//! handshake (federation is always open).

use base64::Engine;

const PREFIX: &str = "pyle-";

/// Build the canonical id for a `host:port` endpoint.
pub fn id_from_endpoint(endpoint: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(endpoint.as_bytes());
    format!("{PREFIX}{b64}")
}

/// Recover the `host:port` an endpoint-addressed id encodes, if it is one.
pub fn endpoint_from_id(id: &str) -> Option<String> {
    let rest = id.strip_prefix(PREFIX)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(rest)
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    if text.is_empty() || !text.contains(':') {
        return None;
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_round_trips_through_its_id() {
        for endpoint in ["localhost:3845", "127.0.0.1:8443", "[::1]:9000"] {
            let id = id_from_endpoint(endpoint);
            assert!(id.starts_with("pyle-"));
            assert_eq!(endpoint_from_id(&id).as_deref(), Some(endpoint));
        }
    }

    #[test]
    fn the_id_is_uri_safe() {
        let id = id_from_endpoint("localhost:3845");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "id must stay URI-safe: {id}"
        );
    }

    #[test]
    fn a_plain_name_is_not_endpoint_addressed() {
        // `node-a` has no prefix; a prefixed name that does not decode to a
        // host:port is rejected rather than guessed.
        assert_eq!(endpoint_from_id("node-a"), None);
        assert_eq!(endpoint_from_id("pyle-not-base64!!"), None);
        assert_eq!(endpoint_from_id("pyle-"), None);
    }
}
