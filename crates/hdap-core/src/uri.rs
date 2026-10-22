//! The `HDAP!` access URI.
//!
//! `HDAP!<pyle>@<user>/<path>` names a space served by a pyle: the GUI and the
//! CLI hand the whole string to a local node, which decides whether the space
//! is local or must be pulled from another pyle (spec §14). Parsing lives here
//! so client and server agree on the exact grammar instead of each guessing.

/// Split an access URI into `(pyle, user, path)`.
///
/// The `HDAP!` scheme is case-insensitive; a missing path becomes the empty
/// string (the user's root) and the returned path never carries leading or
/// trailing slashes. `None` for anything that is not a well-formed URI, so a
/// bare nickname or an endpoint URL is never mistaken for one.
pub fn parse_access_uri(uri: &str) -> Option<(String, String, String)> {
    let rest = uri
        .trim()
        .strip_prefix("HDAP!")
        .or_else(|| uri.trim().strip_prefix("hdap!"))?;
    let (pyle, tail) = rest.split_once('@')?;
    let (user, path) = match tail.split_once('/') {
        Some((u, p)) => (u, p),
        None => (tail, ""),
    };
    let pyle = pyle.trim();
    let user = user.trim();
    if pyle.is_empty() || user.is_empty() {
        return None;
    }
    Some((
        pyle.to_string(),
        user.to_string(),
        path.trim_matches('/').to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_access_uri;

    #[test]
    fn splits_pyle_user_and_path() {
        assert_eq!(
            parse_access_uri("HDAP!pyle-b@jose_0123/docs/a.txt"),
            Some(("pyle-b".into(), "jose_0123".into(), "docs/a.txt".into()))
        );
        // Root of a space.
        assert_eq!(
            parse_access_uri("HDAP!node-a@maria_ab"),
            Some(("node-a".into(), "maria_ab".into(), String::new()))
        );
        // The scheme is case-insensitive and slashes are normalized away.
        assert_eq!(
            parse_access_uri("hdap!n@u_1//x/y/"),
            Some(("n".into(), "u_1".into(), "x/y".into()))
        );
    }

    #[test]
    fn rejects_anything_that_is_not_an_access_uri() {
        for bad in [
            "",
            "jose/docs/a.txt",
            "HDAP!@user/x",
            "HDAP!pyle@/x",
            "HDAP!pyle",
            "https://127.0.0.1:8443/x",
        ] {
            assert!(parse_access_uri(bad).is_none(), "accepted {bad:?}");
        }
    }
}
