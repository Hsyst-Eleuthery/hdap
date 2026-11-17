#![no_main]
//! Fuzz the `adeia` permission-line grammar and ACL document decoding.
//!
//! Oracles:
//! 1. `parse_perm_line` must never panic on arbitrary bytes — it is reached
//!    from user-edited `.hdap` ACLs and from federated documents.
//! 2. A line it accepts must stay accepted after `render`-style normalization
//!    (whitespace changes only), and its right must round-trip to a known name.
//! 3. Feeding arbitrary text into the document parser and then into the ACL
//!    document decoder must never panic either.
use hdap_core::protocol::{parse_perm_line, Right};
use libfuzzer_sys::fuzz_target;

const SEEDS: &[&str] = &[
    "PERM jose all read",
    "PERM jose path:docs/secret deny",
    "PERM * user:maria_a1b2 own",
    "PERM owner path:/ write",
    "PERM jose user:maria_a1b2 read",
];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut inputs = vec![text.to_string()];
    for seed in SEEDS {
        inputs.push((*seed).to_string());
        // Extra whitespace must not change the decision.
        inputs.push(format!("  {seed}   "));
    }

    for line in inputs {
        if let Some((owner, scope, right)) = parse_perm_line(&line) {
            assert!(!owner.is_empty(), "accepted an empty owner: {line:?}");
            // The right name must be one of the canonical values.
            assert!(
                matches!(
                    right.as_str(),
                    "deny" | "read" | "write" | "own"
                ),
                "unknown right survived the parser: {line:?}"
            );
            assert!(matches!(right, Right::Deny | Right::Read | Right::Write | Right::Own));
            if let Ok(_scope) = scope {
                // A well-formed scope must parse the same after whitespace noise.
                assert!(parse_perm_line(&format!("  {line}  ")).is_some());
            }
        }
    }

    // The document-level path must not panic on malformed ACLs either.
    if let Ok(doc) = hdap_core::doc::parse(&text) {
        let _ = hdap_core::protocol::DiadosiDoc::from_doc(&doc);
    }
});
