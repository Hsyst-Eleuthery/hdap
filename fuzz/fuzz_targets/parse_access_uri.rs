#![no_main]
//! Fuzz the `HDAP!<pyle>@<user>/<path>` access-URI grammar.
//!
//! The URI is pasted by users into the GUI/CLI and then used to route a fetch
//! to a peer, so a panic is a client crash and a wrong split can send a read to
//! the wrong namespace. Oracles:
//! 1. parsing never panics;
//! 2. anything accepted has non-empty pyle and user;
//! 3. the returned path is normalized (no leading/trailing slash);
//! 4. re-parsing the reassembled string gives the same triple.
use hdap_core::uri::parse_access_uri;
use libfuzzer_sys::fuzz_target;

const SEEDS: &[&str] = &[
    "HDAP!pyle-b@jose_0123/docs/a.txt",
    "hdap!n@u_1//x/y/",
    "HDAP!node-a@maria_ab",
    "HDAP!@user/x",
    "HDAP!pyle@/x",
];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut inputs = vec![text.to_string()];
    for seed in SEEDS {
        inputs.push((*seed).to_string());
    }

    for uri in inputs {
        if let Some((pyle, user, path)) = parse_access_uri(&uri) {
            assert!(!pyle.is_empty() && !user.is_empty(), "empty component: {uri:?}");
            assert!(!path.starts_with('/') && !path.ends_with('/'), "unnormalized path: {uri:?}");
            let rebuilt = format!("HDAP!{pyle}@{user}/{path}");
            assert_eq!(
                parse_access_uri(&rebuilt),
                Some((pyle, user, path)),
                "reassembly changed the URI: {uri:?}"
            );
        }
    }
});
