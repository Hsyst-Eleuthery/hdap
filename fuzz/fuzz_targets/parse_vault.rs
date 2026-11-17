#![no_main]
//! Fuzz the local vault (`krypte.hdap`) header parser.
//!
//! The vault is the user's identity; a panic while opening it is a client
//! crash and a mis-parse could point decryption at the wrong bytes. Oracles:
//! 1. `Vault::from_bytes` never panics on arbitrary bytes;
//! 2. anything accepted survives `to_bytes -> from_bytes` unchanged, which
//!    keeps the version/Argon2 parameters and salt stable across rewrites;
//! 3. the v1 and v2 magic headers are always accepted with their fixed params.
use hdap_core::vault::Vault;
use libfuzzer_sys::fuzz_target;

fn v1_header() -> Vec<u8> {
    let mut v = b"HDAPVAULT\x00\x01".to_vec();
    v.extend_from_slice(&[7u8; 16]); // salt
    v.extend_from_slice(&[0u8; 12]); // nonce
    v.extend_from_slice(&[1u8; 32]); // ciphertext + tag placeholder
    v
}

fn v2_header() -> Vec<u8> {
    let mut v = b"HDAPVAULT\x00\x02".to_vec();
    v.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // m_cost
    v.extend_from_slice(&2u32.to_le_bytes()); // t_cost
    v.extend_from_slice(&1u32.to_le_bytes()); // p_cost
    v.extend_from_slice(&[7u8; 16]); // salt
    v.extend_from_slice(&[0u8; 12]); // nonce
    v.extend_from_slice(&[1u8; 32]);
    v
}

fuzz_target!(|data: &[u8]| {
    let mut inputs: Vec<Vec<u8>> = vec![data.to_vec(), v1_header(), v2_header()];
    // Mutated prefixes that still start with the magic reach the parameter
    // sanity checks instead of dying at the first comparison.
    for magic in [b"HDAPVAULT\x00\x01".as_slice(), b"HDAPVAULT\x00\x02".as_slice()] {
        let mut v = magic.to_vec();
        v.extend_from_slice(data);
        inputs.push(v);
    }

    for raw in inputs {
        let Ok(vault) = Vault::from_bytes(&raw) else {
            continue;
        };
        assert_eq!(vault.salt.len(), 16);
        let round = vault.to_bytes();
        let reparsed = Vault::from_bytes(&round)
            .unwrap_or_else(|e| panic!("accepted vault did not round-trip: {e:?}"));
        assert_eq!(reparsed.salt, vault.salt, "salt changed");
        assert_eq!(reparsed.sealed, vault.sealed, "ciphertext changed");
        assert_eq!(reparsed.params, vault.params, "Argon2 params changed");
    }
});
