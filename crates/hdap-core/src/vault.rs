//! Local vault (`krypte.hdap`): encrypted storage of the user's secret
//! material. Never leaves the client (especificacao-hdap.md §6).

use crate::crypto::{aead_open, aead_seal, derive_key_argon2, sha256, CryptoError};
use ed25519_dalek::SigningKey;

pub const VAULT_MAGIC: &[u8] = b"HDAPVAULT\x00\x01";
pub const VAULT_SALT_LEN: usize = 16;

/// Errors opening a vault (wrong passphrase or corruption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    Crypto(CryptoError),
    Malformed,
}

pub type VaultResult<T> = Result<T, VaultError>;

/// Secret material stored inside the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSecrets {
    /// HDAP Identifier seed — root of the identity + OTP chain.
    pub seed: [u8; 32],
    /// Ed25519 private key (signing role).
    pub sign_secret: [u8; 32],
    /// X25519 private key (encryption role).
    pub enc_secret: [u8; 32],
}

impl VaultSecrets {
    pub fn from_signing(sign_key: &SigningKey) -> Self {
        VaultSecrets {
            seed: sha256(&sign_key.to_bytes()),
            sign_secret: sign_key.to_bytes(),
            enc_secret: [0u8; 32],
        }
    }
}

/// A vault sealed around a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub salt: [u8; VAULT_SALT_LEN],
    pub sealed: Vec<u8>,
}

fn bundle(secrets: &VaultSecrets) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(&secrets.seed);
    b.extend_from_slice(&secrets.sign_secret);
    b.extend_from_slice(&secrets.enc_secret);
    b
}

fn unbundle(b: &[u8]) -> VaultResult<VaultSecrets> {
    if b.len() != 96 {
        return Err(VaultError::Malformed);
    }
    let seed: [u8; 32] = b[0..32].try_into().unwrap();
    let sign_secret: [u8; 32] = b[32..64].try_into().unwrap();
    let enc_secret: [u8; 32] = b[64..96].try_into().unwrap();
    Ok(VaultSecrets {
        seed,
        sign_secret,
        enc_secret,
    })
}

impl Vault {
    /// Seal `secrets` with a fresh random salt.
    pub fn seal(secrets: &VaultSecrets, password: &[u8]) -> Vault {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; VAULT_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self::seal_with_salt(secrets, password, salt)
    }

    /// Seal with a caller-provided salt (deterministic — for tests/vectors).
    pub fn seal_with_salt(
        secrets: &VaultSecrets,
        password: &[u8],
        salt: [u8; VAULT_SALT_LEN],
    ) -> Vault {
        let key = derive_key_argon2(password, &salt);
        let sealed = aead_seal(&key, &bundle(secrets));
        Vault { salt, sealed }
    }

    /// Open the vault with a passphrase. `Err` on wrong password or
    /// corruption.
    pub fn open(&self, password: &[u8]) -> VaultResult<VaultSecrets> {
        let key = derive_key_argon2(password, &self.salt);
        let bundle = aead_open(&key, &self.sealed).map_err(VaultError::Crypto)?;
        unbundle(&bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519_keygen;
    use rand_core::OsRng;

    #[test]
    fn vault_roundtrip_and_wrong_password() {
        let key = ed25519_keygen(&mut OsRng);
        let secrets = VaultSecrets::from_signing(&key);
        let v = Vault::seal(&secrets, b"s3nh4");
        let opened = v.open(b"s3nh4").unwrap();
        assert_eq!(opened, secrets);

        assert!(v.open(b"errada").is_err());
    }

    #[test]
    fn vault_persists_and_tampering_detected() {
        let secrets = VaultSecrets {
            seed: [1u8; 32],
            sign_secret: [2u8; 32],
            enc_secret: [3u8; 32],
        };
        let v = Vault::seal_with_salt(&secrets, b"pw", [9u8; 16]);
        // serialize to "disk"
        let mut raw = Vec::new();
        raw.extend_from_slice(VAULT_MAGIC);
        raw.extend_from_slice(&v.salt);
        raw.extend_from_slice(&v.sealed);
        // re-read
        let (magic, rest) = raw.split_at(VAULT_MAGIC.len());
        assert_eq!(magic, VAULT_MAGIC);
        let (salt, sealed) = rest.split_at(VAULT_SALT_LEN);
        let re_v = Vault {
            salt: salt.try_into().unwrap(),
            sealed: sealed.to_vec(),
        };
        assert_eq!(re_v.open(b"pw").unwrap(), secrets);

        // flip one bit in sealed region
        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let (_, rest) = bad.split_at(VAULT_MAGIC.len());
        let (salt, sealed) = rest.split_at(VAULT_SALT_LEN);
        let bad_v = Vault {
            salt: salt.try_into().unwrap(),
            sealed: sealed.to_vec(),
        };
        assert!(bad_v.open(b"pw").is_err());
    }
}
