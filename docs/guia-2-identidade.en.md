# User Guide — Chapter 2: Identity and Home

*Revision 2026-11-17.*

**HDAP v2.0 — Teleios**

**Written by Thaís (op3n/op3ny)**

---

## Your identity is a key pair

In HDAP there is no email, phone number, or central registry. Your identity is an Ed25519/X25519 key pair generated locally and stored in `krypte.hdap`, a vault encrypted with your passphrase. The server knows only your public key; your private key never leaves your machine.

Your global id has the form `nickname_suffix`, where `suffix` is 8 random bytes hex-encoded. This is what you register on a node and what others use to address you.

## Creating an identity

```
hdap-cli init maria
```

This generates a new identity and displays a **recovery phrase** (64 hex chars). Write it down and keep it offline. With the recovery phrase and your passphrase, you can rebuild the identity from scratch even if `krypte.hdap` is lost:

```
hdap-cli recover <64-hex-phrase> maria
```

There is no central recovery. If you lose the vault, the passphrase, **and** the recovery phrase, the identity is gone forever.

## Recovery phrase

The recovery phrase encodes 32 bytes of entropy from which all your keys are deterministically derived:
- Ed25519 signing key
- X25519 encryption key
- OTP chain seed and anchor

It is shown only once, at identity creation. Store it in a password manager, on paper, or another offline medium — never in the same place as your passphrase.

## The vault (`krypte.hdap`)

The vault is sealed with Argon2id + ChaCha20-Poly1305 using your passphrase. It contains your signing key, encryption key, OTP anchor, and chain length. The header is versioned (`HDAPVAULT\0\x02`), so v1 vaults (19 MiB Argon2) remain readable and are rewritten in v2 format on next use.

## The home (`prosopeion.hdap`)

Next to the vault, `prosopeion.hdap` is your public profile document: nickname, suffix, public keys, OTP anchor, and creation time, self-signed by your identity key. It is what you publish when registering on a node.

## Registering on a node

```
hdap-cli --tls-pin "$PIN" register
```

Registration is idempotent: re-registering with the same key returns success without error. Registering with a different key under the same `user_id` returns `409 identity key conflict`.

## Logging in

Login uses 3FA: (1) Ed25519 possession, (2) OTP knowledge, (3) challenge-bound HMAC of the session secret. The server issues a challenge (`nonce` + `ts`); you return exactly that `ts`. Your local clock never decides validity.

## OMPHALOS rotation

Your OTP anchor can be rotated with `hdap-cli rotate TOKEN`. This requires your identity key to sign `hdap:omphalos:v2:{user}:{old_anchor}:{new_anchor}:{new_k}`. A stolen token alone cannot rotate the anchor.

## Backup

Back up `krypte.hdap`, `prosopeion.hdap`, and your passphrase. Keep them in separate physical locations. There is no "forgot my password" — losing any of these means losing the identity.
