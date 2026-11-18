# HDAP — Hsyst Descentralized Archive Protocol

> **Files with authorship. Memory with proof. A home that does not depend on a single server.**

*Reviewed 2026-11-17 · v2.0.0 (Téleia vási · Teleios).*

Hi, I'm **Thaís (op3n/op3ny)**. HDAP started with a simple question: how can we store files so that possession, authorship and history do not depend on a company's goodwill? The answer was not another cloud — it was a protocol small enough to be understood and strong enough to be verified.

This is **v2.0**, the **Téleia vási** generation of the protocol, codenamed **Teleios**. It succeeds v1.001 (**Themelio · Epoptia**) without changing the document format: `# VERSION:` is still `1`. What changed is the interoperability language between nodes — Unix UTC time in every proof, HKDF key derivation, hashed session storage, a versioned local vault and authentication bound to the server-issued challenge. The full picture is in [docs/VERSAO.md](docs/VERSAO.md) (Portuguese).

[![CI](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What changed in Teleios

- **UTC everywhere.** Every protocol timestamp is a Unix `u64` in seconds. The client returns exactly the `ts` issued by the server; its own clock and timezone never decide validity. `/health` exposes `time_utc`/`date_utc` and every HTTP response carries `X-HDAP-Server-Time`.
- **Keys derived with HKDF-SHA256** under separate labels: `hdap:ecies` (envelope), `hdap:session` (session secret) and `hdap:otp` (OTP chain root).
- **Third factor bound to the challenge.** `prove_session_secret_bound` produces `hdap:f3:v2:{user}:{server}:hdap:challenge:{nonce}:{ts}`. The legacy `hdap:code:...` proof is accepted **only** for identities that predate v2, so no v2 client can opt out of the binding.
- **Bounded OTP.** `MAX_OTP_CHAIN_LEN = 4096` and the registered `otp_k` limit verification; a client-supplied `seed_iter` never chooses the bound.
- **Signed OMPHALOS rotation.** `POST /omphalos` requires a session, an Ed25519 `identity_signature` over `hdap:omphalos:v2:{user_id}:{old_anchor}:{new_anchor}:{new_k}`, a 64-hex `otp_anchor` and a strictly increasing `seed_iter`. A stolen token alone cannot take the account.
- **Secrets at rest.** Sessions are stored only as `v2:{sha256("hdap:session-store:" + token)}`; v1 rows are hashed on load. `--master-key-file` keeps the master key outside the SQLite database, whose row is redacted to zeros.
- **Versioned vault.** `HDAPVAULT\0\x02` records Argon2id parameters in the header (64 MiB by default); v1 vaults remain readable.
- **Ángelma.** The node message (MOTD) supports `HDAP{[uptime]}`, `HDAP{[users]}`, `HDAP{[protocol]}` and other tags; it appears in `/health`, `/motd`, the CLI and the GUI.
- **Safer CLI.** `--pass-env`, `--pass-file` or a TTY prompt replace `--pass` on argv (which still works but prints a warning).
- **Hardened operation.** `--max-connections` (default 256), `--cleanup-interval` (default 60 s) and `--time-tolerance` (default 300 s, federation only).

## Download

Packages for each platform are published in [Releases](https://github.com/Hsyst-Eleuthery/hdap/releases). Release **v2.0 (Teleios)** is packaged as `2.0.0`:

| Platform | Artifact |
|---|---|
| Linux x86_64, static (musl) | `hdap-2.0.0-x86_64-unknown-linux-musl.tar.gz` |
| Linux x86_64, glibc | `hdap-2.0.0-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `hdap-2.0.0-x86_64-pc-windows-gnu.zip` |

## Quick start (CLI, 5 minutes)

The minimum path is: start a node, read its `tls_pin` on stderr, create an identity with `init`, register, authenticate and upload a file. No e-mail, no central account.

```bash
export PIN='paste the node TLS pin here'
export HDAP_PASS='a strong passphrase'

# health needs no identity and no passphrase
hdap-cli --tls-pin "$PIN" health

hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" init thais
hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" register
TOKEN=$(hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" auth)
ID=$(hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" whoami)

# rotate the OTP anchor; then obtain a token from the new chain
hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" rotate "$TOKEN"
hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" auth
```

Global options may appear before or after the command. `health`, `resolve`, `prices`, `download`, `delete` and `list` do not ask for a passphrase. Without `--tls-pin` the CLI speaks plain HTTP, which is only appropriate against a loopback node started with `--no-tls`.

## Running a node

```bash
./target/release/hdap-server \
  --listen 0.0.0.0:8443 \
  --advertise arquivo.example.com:8443 \
  --data /var/lib/hdap \
  --master-key-file /var/lib/hdap/master.key \
  --motd "HDAP Ángelma · uptime HDAP{[uptime]} · HDAP{[protocol]}" \
  --max-connections 256 \
  --cleanup-interval 60 \
  --time-tolerance 300 \
  --rate-limit 60
```

TLS is mandatory outside loopback. Back up `tls.identity`, the master key and the database together: losing the first changes the pin, and losing the second makes the blobs unreadable. `--motd-file` reads the Ángelma from a UTF-8 file; when both `--motd` and `--motd-file` are given, the last one wins.

**Back up now.** The identity is the key pair inside `krypte.hdap`, encrypted by your passphrase; there is no central recovery. Copy `krypte.hdap` to two separate physical locations right after `hdap init` and store the passphrase elsewhere. On the server, back up `tls.identity`, the `--master-key-file` and the database together.

## Official nodes and TLS pins

| Address | `server_id` | `tls_pin` (SHA-256 of certificate) |
|---|---|---|
| `pyle1.hdap.hsyst.org:8443` | `pyle-cHlsZTEuaGRhcC5oc3lzdC5vcmc6ODQ0Mw` | `e31eea2c5576724d58741ebfe6629065ab15bbfec2725f416280f820f3ccb2e0` |
| `pyle2.hdap.hsyst.org:8444` | `pyle-cHlsZTIuaGRhcC5oc3lzdC5vcmc6ODQ0NA` | `f94f5606d9f0f87a433ebdaa7fc3a9750df72698bc240a4d459286bdeb717f13` |
| `pyle3.hdap.hsyst.org:8445` | `pyle-cHlsZTMuaGRhcC5oc3lzdC5vcmc6ODQ0NQ` | `01dd1c576af6559bcaf0ecc6590ce8c22518b4ed6f0e4ac5bd90dcc247d41d5f` |
| `pyle.thais.fyi:8443` | `pyle-cHlsZS50aGFpcy5meWk6ODQ0Mw` | `c270bafd948dc5bb185009973099702789b3c7f4eea414670a1180b9f9162573` |

The pyle id is derived from the announced address; the pin is the SHA-256 of the certificate DER and is what actually authenticates the node. **Verify these pins out of band** before trusting them: [docs/pins-oficiais.md](docs/pins-oficiais.md) has the full table, each node's keys and the maintainer's OpenPGP fingerprint (`1489 36AB E859 A3A9 0ED1 E17A 5FF5 3F39 FFC4 D03F`). Never accept a changed pin without independent confirmation.

## Verification

The suite has **261 automated tests** covering core, server, CLI, TLS and the GUI, including F3 bound to the challenge, OTP limits, v1/v2 vaults, hashed sessions, external master key, signed OMPHALOS rotation and Ángelma/UTC display. CI enforces `cargo fmt --check` and `cargo clippy -D warnings`.

Honest limits: there is no central password recovery; metadata is public by design; deletion is incentive-based, not physical enforcement; federation is open with first-contact key pinning; and the session token is deterministic for `(K, server_id, exp)` — two logins in the same second may produce the same value. A signature proves that a key signed those bytes, **not** that the signer created the content: copying a public file and signing it is possible. The ledger records who signed and submitted first (`origin_user`) separately from the namespace owner (`namespace_owner`). See [SECURITY.md](SECURITY.md) and [docs/modelo-de-ameaca.md](docs/modelo-de-ameaca.md).

## Documentation

Documentation is available in Portuguese and English. Start with [docs/VERSAO.md](docs/VERSAO.md) for the v2 overview, [docs/guia-1-introducao.en.md](docs/guia-1-introducao.en.md) for the user guide in English, [docs/tecnico.md](docs/tecnico.md) for architecture, [docs/especificacao-hdap.md](docs/especificacao-hdap.md) for normative semantics, [docs/rfc-hdap.md](docs/rfc-hdap.md) for the wire format, [docs/guia-de-execucao.md](docs/guia-de-execucao.md) for building and releasing, and [CHANGELOG.md](CHANGELOG.md) for history.

## Contact and codenames

Maintained by **Thaís (op3n/op3ny)**: [thais@hsyst.org](mailto:thais@hsyst.org), [@op3ny](https://github.com/op3ny), Discord `@op3n`. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Every release carries two codenames: a **protocol codename** (the generation's language) and a **release codename** (the package). v1.0 was **Themelio · Veritas Aeterna**; v1.001 was **Themelio · Epoptia**; v2.0 is **Teleios (Téleia vási) · Teleios**. Fixes within v2 are `v2.001`, `v2.002`, and so on, with the protocol codename unchanged. Document `# VERSION: 1` is independent of the protocol generation.

---

<p align="center">
<strong>HDAP — proof comes before trust.</strong><br>
Thaís (op3n/op3ny)
</p>
