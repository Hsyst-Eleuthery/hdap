//! Encrypted identity store on the client side: a `krypte.hdap` sealed around
//! the user's passphrase (Argon2id + ChaCha20-Poly1305) plus the public
//! `prosopeion.hdap` render, used to rebuild the `Identity` (especificacao §6).

use std::fmt;
use std::io;
use std::path::Path;

use ed25519_dalek::SigningKey;
use hdap_core::crypto::{sha256, CryptoError};
use hdap_core::doc::{parse, ParseError};
use hdap_core::identity::Identity;
use hdap_core::vault::{Vault, VaultError, VaultSecrets, VAULT_MAGIC, VAULT_SALT_LEN};
use x25519_dalek::StaticSecret;

/// Errors produced while persisting or restoring an identity.
#[derive(Debug)]
pub enum IdentityStoreError {
    Io(io::Error),
    Vault(VaultError),
    Doc(ParseError),
    Crypto(CryptoError),
    Malformed,
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityStoreError::Io(e) => write!(f, "io error: {e}"),
            IdentityStoreError::Vault(e) => write!(f, "vault error: {e:?}"),
            IdentityStoreError::Doc(e) => write!(f, "doc error: {e}"),
            IdentityStoreError::Crypto(e) => write!(f, "crypto error: {e:?}"),
            IdentityStoreError::Malformed => write!(f, "malformed vault file"),
        }
    }
}

impl std::error::Error for IdentityStoreError {}

impl From<io::Error> for IdentityStoreError {
    fn from(e: io::Error) -> Self {
        IdentityStoreError::Io(e)
    }
}

impl From<VaultError> for IdentityStoreError {
    fn from(e: VaultError) -> Self {
        IdentityStoreError::Vault(e)
    }
}

impl From<ParseError> for IdentityStoreError {
    fn from(e: ParseError) -> Self {
        IdentityStoreError::Doc(e)
    }
}

impl From<CryptoError> for IdentityStoreError {
    fn from(e: CryptoError) -> Self {
        IdentityStoreError::Crypto(e)
    }
}

/// Persist the identity to `krypte_path` (sealed) and its public doc to
/// `prosopeion_path`.
pub fn save(
    identity: &Identity,
    password: &[u8],
    krypte_path: &Path,
    prosopeion_path: &Path,
) -> Result<(), IdentityStoreError> {
    let secrets = VaultSecrets {
        seed: sha256(&identity.sign_key.to_bytes()),
        sign_secret: identity.sign_key.to_bytes(),
        enc_secret: identity.enc_secret.to_bytes(),
    };
    let vault = Vault::seal(&secrets, password);
    let mut raw = Vec::with_capacity(VAULT_MAGIC.len() + VAULT_SALT_LEN + vault.sealed.len());
    raw.extend_from_slice(VAULT_MAGIC);
    raw.extend_from_slice(&vault.salt);
    raw.extend_from_slice(&vault.sealed);
    std::fs::write(krypte_path, raw)?;
    std::fs::write(prosopeion_path, identity.signed_prosopeion_doc().render())?;
    Ok(())
}

/// Rebuild the identity from the sealed vault and the stored properties doc.
/// Fails on a wrong passphrase, corrupted file, or a private/public mismatch.
pub fn load(
    password: &[u8],
    krypte_path: &Path,
    prosopeion_path: &Path,
) -> Result<Identity, IdentityStoreError> {
    let raw = std::fs::read(krypte_path)?;
    if raw.len() < VAULT_MAGIC.len() + VAULT_SALT_LEN {
        return Err(IdentityStoreError::Malformed);
    }
    let (magic, rest) = raw.split_at(VAULT_MAGIC.len());
    if magic != VAULT_MAGIC {
        return Err(IdentityStoreError::Malformed);
    }
    let (salt, sealed) = rest.split_at(VAULT_SALT_LEN);
    let vault = Vault {
        salt: salt.try_into().map_err(|_| IdentityStoreError::Malformed)?,
        sealed: sealed.to_vec(),
    };
    let secrets = vault.open(password)?;
    let prosopeion_text = std::fs::read_to_string(prosopeion_path)?;
    let doc = parse(&prosopeion_text)?;
    let sign_key = SigningKey::from_bytes(&secrets.sign_secret);
    let enc_secret = StaticSecret::from(secrets.enc_secret);
    Ok(Identity::from_doc(&doc, sign_key, enc_secret)?)
}

/// The next OTP step this client believes the node expects.
///
/// The chain is single-use per login (AME-14), so a client that always starts
/// from step 1 can log in exactly once for the whole life of a node — and
/// never again after the node restarts from a database. The counter is a
/// plain file next to the vault: it is a hint, not a secret, because the node
/// is the authority and can overrule it.
pub const STEP_FILE: &str = "omphalos.step";

/// Read the remembered next step, defaulting to the first step when absent or
/// unreadable (the node will tell us the truth on the first attempt).
pub fn load_step(home: &Path) -> usize {
    std::fs::read_to_string(home.join(STEP_FILE))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

/// Remember the next step after a successful login.
pub fn save_step(home: &Path, next: usize) -> Result<(), IdentityStoreError> {
    std::fs::write(home.join(STEP_FILE), next.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_roundtrips_through_disk_with_wrong_password_rejected() {
        let dir = std::env::temp_dir().join(format!("hdap-cli-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let krypte_path = dir.join("krypte.hdap");
        let prosopeion_path = dir.join("prosopeion.hdap");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("jose", now);
        save(&id, b"segredo", &krypte_path, &prosopeion_path).unwrap();

        let restored = load(b"segredo", &krypte_path, &prosopeion_path).unwrap();
        assert_eq!(restored.global_id(), id.global_id());
        assert_eq!(restored.otp_anchor, id.otp_anchor);
        assert_eq!(restored.sign_pubkey(), id.sign_pubkey());
        assert_eq!(restored.enc_pubkey(), id.enc_pubkey());

        // wrong passphrase must not open the vault
        assert!(load(b"errada", &krypte_path, &prosopeion_path).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
