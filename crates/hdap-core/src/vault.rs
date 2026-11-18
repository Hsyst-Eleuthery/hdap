//! Local vault (`krypte.hdap`): encrypted storage of the user's secret
//! material. Never leaves the client (especificacao-hdap.md §6).
//!
//! v2 header (`HDAPVAULT\0\x02`):
//! `magic(11) || version:u32le || m_cost:u32le || t_cost:u32le ||
//! p_cost:u32le || salt(16) || nonce(12) || ciphertext+tag`.
//! v1 files (`HDAPVAULT\0\x01`) are still readable: their parameters were
//! fixed at 19 MiB / t=2 / p=1.

use crate::crypto::{
    aead_open, aead_seal, derive_key_argon2_with, sha256, Argon2Params, CryptoError,
    ARGON2_PARAMS_V1, ARGON2_PARAMS_V2,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

pub const VAULT_MAGIC: &[u8] = b"HDAPVAULT\x00\x02";
pub const VAULT_MAGIC_V1: &[u8] = b"HDAPVAULT\x00\x01";
pub const VAULT_PARAMS_LEN: usize = 16;
pub const VAULT_SALT_LEN: usize = 16;

/// Errors opening a vault (wrong passphrase or corruption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    Crypto(CryptoError),
    Malformed,
    /// The recorded KDF parameters are outside the accepted safety envelope.
    UnsupportedParams,
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
    /// OTP-chain root for recovery-phrase accounts (hdap:recovery:otp
    /// derivation). Only present when the identity was created from a recovery
    /// phrase; absent for regular identities. Zeroized on drop.
    pub recovery_root: Option<[u8; 32]>,
}

impl VaultSecrets {
    pub fn from_signing(sign_key: &SigningKey) -> Self {
        VaultSecrets {
            seed: sha256(&sign_key.to_bytes()),
            sign_secret: sign_key.to_bytes(),
            enc_secret: [0u8; 32],
            recovery_root: None,
        }
    }

    /// Build secrets for a recovery-phrase identity. All three key fields must
    /// be provided; nothing is zeroed out, so the vault stays complete.
    pub fn from_recovery(
        seed: &[u8; 32],
        sign_secret: &[u8; 32],
        enc_secret: &[u8; 32],
        recovery_root: &[u8; 32],
    ) -> Self {
        VaultSecrets {
            seed: *seed,
            sign_secret: *sign_secret,
            enc_secret: *enc_secret,
            recovery_root: Some(*recovery_root),
        }
    }
}

impl Drop for VaultSecrets {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.sign_secret.zeroize();
        self.enc_secret.zeroize();
        if let Some(root) = &mut self.recovery_root {
            root.zeroize();
        }
    }
}

/// A vault sealed around a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub salt: [u8; VAULT_SALT_LEN],
    pub sealed: Vec<u8>,
    /// Argon2id parameters recorded in the header (v2) or inherited (v1).
    pub params: Argon2Params,
}

fn bundle(secrets: &VaultSecrets) -> Vec<u8> {
    let mut b = Vec::with_capacity(129);
    b.push(if secrets.recovery_root.is_some() {
        1
    } else {
        0
    });
    b.extend_from_slice(&secrets.seed);
    b.extend_from_slice(&secrets.sign_secret);
    b.extend_from_slice(&secrets.enc_secret);
    if let Some(root) = &secrets.recovery_root {
        b.extend_from_slice(root);
    }
    b
}

fn unbundle(b: &[u8]) -> VaultResult<VaultSecrets> {
    // Differentiate by length so old vaults (exactly 96 bytes, no flag byte)
    // keep opening after this change:
    //   96 bytes  = legacy format: seed(32) + sign_secret(32) + enc_secret(32)
    //   97 bytes  = new format without recovery_root: flag(0) + 96 bytes
    //   129 bytes = new format with recovery_root: flag(1) + 128 bytes
    match b.len() {
        96 => {
            let seed: [u8; 32] = b[0..32].try_into().map_err(|_| VaultError::Malformed)?;
            let sign_secret: [u8; 32] = b[32..64].try_into().map_err(|_| VaultError::Malformed)?;
            let enc_secret: [u8; 32] = b[64..96].try_into().map_err(|_| VaultError::Malformed)?;
            Ok(VaultSecrets {
                seed,
                sign_secret,
                enc_secret,
                recovery_root: None,
            })
        }
        97 | 129 => {
            if b.is_empty() {
                return Err(VaultError::Malformed);
            }
            let flag = b[0];
            let mut offset = 1;
            let seed: [u8; 32] = b
                .get(offset..offset + 32)
                .ok_or(VaultError::Malformed)?
                .try_into()
                .map_err(|_| VaultError::Malformed)?;
            offset += 32;
            let sign_secret: [u8; 32] = b
                .get(offset..offset + 32)
                .ok_or(VaultError::Malformed)?
                .try_into()
                .map_err(|_| VaultError::Malformed)?;
            offset += 32;
            let enc_secret: [u8; 32] = b
                .get(offset..offset + 32)
                .ok_or(VaultError::Malformed)?
                .try_into()
                .map_err(|_| VaultError::Malformed)?;
            offset += 32;
            let recovery_root = if flag == 1 {
                Some(
                    b.get(offset..offset + 32)
                        .ok_or(VaultError::Malformed)?
                        .try_into()
                        .map_err(|_| VaultError::Malformed)?,
                )
            } else if flag == 0 {
                None
            } else {
                return Err(VaultError::Malformed);
            };
            Ok(VaultSecrets {
                seed,
                sign_secret,
                enc_secret,
                recovery_root,
            })
        }
        _ => Err(VaultError::Malformed),
    }
}

impl Vault {
    /// Seal `secrets` with a fresh random salt and the current parameters.
    pub fn seal(secrets: &VaultSecrets, password: &[u8]) -> Vault {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; VAULT_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self::seal_with_salt_and_params(secrets, password, salt, ARGON2_PARAMS_V2)
    }

    /// Seal with a caller-provided salt (deterministic — for tests/vectors).
    pub fn seal_with_salt(
        secrets: &VaultSecrets,
        password: &[u8],
        salt: [u8; VAULT_SALT_LEN],
    ) -> Vault {
        Self::seal_with_salt_and_params(secrets, password, salt, ARGON2_PARAMS_V2)
    }

    pub fn seal_with_salt_and_params(
        secrets: &VaultSecrets,
        password: &[u8],
        salt: [u8; VAULT_SALT_LEN],
        params: Argon2Params,
    ) -> Vault {
        let mut key = derive_key_argon2_with(password, &salt, &params);
        let sealed = aead_seal(&key, &bundle(secrets));
        key.zeroize();
        Vault {
            salt,
            sealed,
            params,
        }
    }

    /// Open the vault with a passphrase. `Err` on wrong password or
    /// corruption.
    pub fn open(&self, password: &[u8]) -> VaultResult<VaultSecrets> {
        let mut key = derive_key_argon2_with(password, &self.salt, &self.params);
        let plain = aead_open(&key, &self.sealed).map_err(VaultError::Crypto)?;
        key.zeroize();
        let mut plain = plain;
        let result = unbundle(&plain);
        plain.zeroize();
        result
    }

    /// Serialize with the v2 versioned header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(
            VAULT_MAGIC.len() + VAULT_PARAMS_LEN + VAULT_SALT_LEN + self.sealed.len(),
        );
        raw.extend_from_slice(VAULT_MAGIC);
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&self.params.m_cost.to_le_bytes());
        raw.extend_from_slice(&self.params.t_cost.to_le_bytes());
        raw.extend_from_slice(&self.params.p_cost.to_le_bytes());
        raw.extend_from_slice(&self.salt);
        raw.extend_from_slice(&self.sealed);
        raw
    }

    /// Parse both v1 and v2 on-disk formats.
    pub fn from_bytes(raw: &[u8]) -> VaultResult<Vault> {
        if raw.len() < VAULT_MAGIC.len() + VAULT_PARAMS_LEN + VAULT_SALT_LEN {
            return Err(VaultError::Malformed);
        }
        if raw.starts_with(VAULT_MAGIC_V1) {
            let rest = &raw[VAULT_MAGIC_V1.len()..];
            if rest.len() < VAULT_SALT_LEN {
                return Err(VaultError::Malformed);
            }
            let salt: [u8; VAULT_SALT_LEN] = rest[..VAULT_SALT_LEN]
                .try_into()
                .map_err(|_| VaultError::Malformed)?;
            return Ok(Vault {
                salt,
                sealed: rest[VAULT_SALT_LEN..].to_vec(),
                params: ARGON2_PARAMS_V1,
            });
        }
        if !raw.starts_with(VAULT_MAGIC) {
            return Err(VaultError::Malformed);
        }
        let rest = &raw[VAULT_MAGIC.len()..];
        let word = |i: usize| -> VaultResult<u32> {
            let b: [u8; 4] = rest[i * 4..i * 4 + 4]
                .try_into()
                .map_err(|_| VaultError::Malformed)?;
            Ok(u32::from_le_bytes(b))
        };
        let version = word(0)?;
        let params = Argon2Params {
            m_cost: word(1)?,
            t_cost: word(2)?,
            p_cost: word(3)?,
        };
        if version != 2 {
            return Err(VaultError::Malformed);
        }
        // Sanity envelope: enough work to be safe, small enough not to be a
        // denial-of-service when opening an untrusted vault file.
        if !(19 * 1024..=1024 * 1024).contains(&params.m_cost)
            || !(1..=16).contains(&params.t_cost)
            || !(1..=8).contains(&params.p_cost)
        {
            return Err(VaultError::UnsupportedParams);
        }
        let offset = VAULT_PARAMS_LEN;
        let salt: [u8; VAULT_SALT_LEN] = rest[offset..offset + VAULT_SALT_LEN]
            .try_into()
            .map_err(|_| VaultError::Malformed)?;
        Ok(Vault {
            salt,
            sealed: rest[offset + VAULT_SALT_LEN..].to_vec(),
            params,
        })
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
            recovery_root: None,
        };
        let v = Vault::seal_with_salt(&secrets, b"pw", [9u8; 16]);
        let raw = v.to_bytes();
        let re_v = Vault::from_bytes(&raw).unwrap();
        assert_eq!(re_v.params, ARGON2_PARAMS_V2);
        assert_eq!(re_v.open(b"pw").unwrap(), secrets);

        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(Vault::from_bytes(&bad).unwrap().open(b"pw").is_err());
    }

    #[test]
    fn v1_vault_is_still_readable() {
        let secrets = VaultSecrets {
            seed: [4u8; 32],
            sign_secret: [5u8; 32],
            enc_secret: [6u8; 32],
            recovery_root: None,
        };
        let v = Vault::seal_with_salt_and_params(&secrets, b"pw", [8u8; 16], ARGON2_PARAMS_V1);
        let mut raw = Vec::new();
        raw.extend_from_slice(VAULT_MAGIC_V1);
        raw.extend_from_slice(&v.salt);
        raw.extend_from_slice(&v.sealed);
        let parsed = Vault::from_bytes(&raw).unwrap();
        assert_eq!(parsed.params, ARGON2_PARAMS_V1);
        assert_eq!(parsed.open(b"pw").unwrap(), secrets);
    }

    /// Old vaults (pre-recovery-root) are exactly 96 bytes with no flag:
    /// seed(32) + sign_secret(32) + enc_secret(32). They must keep opening.
    #[test]
    /// Old vaults (pre-recovery-root) are exactly 96 bytes with no flag:
    /// seed(32) + sign_secret(32) + enc_secret(32). They must keep opening.
    fn legacy_96_byte_vault_opens_without_flag() {
        // Fixed bytes from an old vault's plaintext bundle (seed, sign_secret,
        // enc_secret, no flag byte). Exactly 96 bytes.
        let old_plaintext: [u8; 96] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, // seed
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40, // sign_secret
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
            0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
            0x5d, 0x5e, 0x5f, 0x60, // enc_secret
        ];
        let secrets = unbundle(&old_plaintext).unwrap();
        assert_eq!(
            secrets.seed,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32
            ]
        );
        assert_eq!(
            secrets.sign_secret,
            [
                33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
                54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
            ]
        );
        assert_eq!(
            secrets.enc_secret,
            [
                65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
                86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96
            ]
        );
        assert!(secrets.recovery_root.is_none());
    }

    #[test]
    fn new_97_byte_vault_without_root_opens() {
        let mut plaintext = Vec::with_capacity(97);
        plaintext.push(0); // flag = no recovery_root
        plaintext.extend_from_slice(&[1u8; 32]); // seed
        plaintext.extend_from_slice(&[2u8; 32]); // sign_secret
        plaintext.extend_from_slice(&[3u8; 32]); // enc_secret
        assert_eq!(plaintext.len(), 97);
        let secrets = unbundle(&plaintext).unwrap();
        assert_eq!(secrets.seed, [1u8; 32]);
        assert_eq!(secrets.sign_secret, [2u8; 32]);
        assert_eq!(secrets.enc_secret, [3u8; 32]);
        assert!(secrets.recovery_root.is_none());
    }

    /// New vaults with recovery_root are 129 bytes (flag 1 + 128 bytes).
    #[test]
    fn new_129_byte_vault_with_root_opens() {
        let mut plaintext = Vec::with_capacity(129);
        plaintext.push(1); // flag = has recovery_root
        plaintext.extend_from_slice(&[1u8; 32]); // seed
        plaintext.extend_from_slice(&[2u8; 32]); // sign_secret
        plaintext.extend_from_slice(&[3u8; 32]); // enc_secret
        plaintext.extend_from_slice(&[4u8; 32]); // recovery_root
        assert_eq!(plaintext.len(), 129);
        let secrets = unbundle(&plaintext).unwrap();
        assert_eq!(secrets.seed, [1u8; 32]);
        assert_eq!(secrets.sign_secret, [2u8; 32]);
        assert_eq!(secrets.enc_secret, [3u8; 32]);
        assert_eq!(secrets.recovery_root, Some([4u8; 32]));
    }
}
