#![no_main]
//! Fuzz the `.hdap` document parser.
//!
//! Two oracles, both cheap enough to leave on every input:
//!
//! 1. `parse` must never panic. Every byte string off the wire eventually
//!    reaches this function, so a panic here is a remote crash.
//! 2. Anything `parse` accepts must survive `render` -> `parse` unchanged.
//!    A parser that drops a field, reorders signatures or loses a duplicate
//!    check breaks the canonical form, and the network then disagrees with
//!    itself about what a document says — which matters because `content_hash`
//! is taken over exactly this rendering.
//!
//! Seeds are valid documents so the mutator starts inside the parser instead of
//! dying at the magic line.
use libfuzzer_sys::fuzz_target;

const SEEDS: &[&str] = &[
    // A minimal well-formed document.
    "# HSYST DESCENTRALIZED ARCHIVE PROTOCOL\n## DOC: prosopeion\n### HEAD:\n# VERSION: 1\n# EDITION: 1\n# CREATED_AT: 1737500000\n### :END HEAD\n### BODY:\n# NICKNAME: jose\n# SUFFIX: a3f9c2d1e0b7aa11\n# SIGN_PUBKEY: BABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABA\n# OMPHALOS: abababababababababababababababababababababababababababababababab\n### :END BODY\n## :END DOC\n",
    // The same, with an edition chain and a signature block.
    "# HSYST DESCENTRALIZED ARCHIVE PROTOCOL\n## DOC: prosopeion\n### HEAD:\n# VERSION: 1\n# EDITION: 2\n# CREATED_AT: 1737500000\n# PREV_HASH: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n### :END HEAD\n### BODY:\n# NICKNAME: jose\n# SIGN_PUBKEY: BABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABA\n### :END BODY\n### SIGS:\n# SIGNER: jose_a3f9c2d1e0b7aa11\n# SIGNER_PUBKEY: BABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABA\n# SIGNATURE: c2lnbmF0dXJl\n### :END SIGS\n## :END DOC\n",
];

fuzz_target!(|data: &[u8]| {
    // The fuzzer's own bytes, plus every seed prefixed by a one-byte selector,
    // so structured documents are reachable without a separate mutator.
    let mut inputs: Vec<Vec<u8>> = vec![data.to_vec()];
    for (i, seed) in SEEDS.iter().enumerate() {
        let mut v = vec![i as u8];
        v.extend_from_slice(seed.as_bytes());
        inputs.push(v);
    }

    for input in inputs {
        // Lossy so arbitrary bytes still reach the parser as text: a `.hdap`
        // body is a string, and invalid UTF-8 must not be a way to skip the
        // checks entirely.
        let text = String::from_utf8_lossy(&input);
        let Ok(doc) = hdap_core::doc::parse(&text) else {
            continue;
        };
        let rendered = doc.render();
        let reparsed = hdap_core::doc::parse(&rendered)
            .unwrap_or_else(|e| panic!("accepted input rendered to unparseable form: {e:?}\n{rendered}"));
        assert_eq!(
            reparsed.render(),
            rendered,
            "canonical form is not a fixed point"
        );
        assert_eq!(reparsed.doc_type, doc.doc_type, "type changed");
        assert_eq!(reparsed.body, doc.body, "body changed");
        assert_eq!(reparsed.head_extra, doc.head_extra, "head changed");
        assert_eq!(
            reparsed.sigs.len(),
            doc.sigs.len(),
            "signature count changed"
        );
    }
});