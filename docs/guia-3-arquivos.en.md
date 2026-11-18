# User Guide — Chapter 3: Files, Documents and Permissions

*Revision 2026-11-17.*

**HDAP v2.0 — Teleios**

**Written by Thaís (op3n/op3ny)**

---

## Documents `.hdap`

Everything in HDAP is a document: identity, permissions, aliases, transfer offers. A `.hdap` file has a canonical header (`# VERSION: 1`, `CREATED_AT`, etc.), a body of key-value fields, and one or more Ed25519 signatures. The canonical byte rendering is content-addressed: any change to a field, signature order, or duplicate line changes the hash.

Documents are immutable: edits append a new version linked by `PREV_HASH`, forming an edit chain.

## Files and content hash

A file is identified by its content hash (SHA-256 of the bytes). Uploading stores the encrypted blob under `namespace_owner/path`, keyed by hash. Two uploads of identical bytes share the same blob — no duplication.

## Permissions (`adeia`)

Permissions are declarative lines in the document:

```
PERM <owner> <subject> <path> <right>
```

- `owner`: who grants (your user_id)
- `subject`: `all` or `user:<id>`
- `path`: file path, folder path, or `/` for the whole space
- `right`: `read`, `write`, `own`, or `deny`

Precedence: most specific path wins; `user:<id>` beats `all` at the same path; `deny` beats positive rights at the same level; no rule means deny. Paths respect component boundaries (`docs` covers `docs/a.txt` but not `docs2/a.txt`).

## Authorship vs ownership

The signature proves **possession of the key over the bytes**, not that the signer created the content. Anyone can copy a public file and sign it. The ledger records separately:
- `origin_user`: who signed and uploaded first (first writer wins for that hash)
- `namespace_owner`: who owns the target directory

These are independent fields. `namespace_owner` can change via possession transfer without rewriting `origin_user`.

## The `prytaneion`

The `prytaneion` is the public ledger recording uploads, replicas, and transfers. Each entry stores `origin_user`, `origin_user_pubkey`, `sphragis` (signature), `namespace_owner`, and content hash. It is append-only and tamper-evident.

## Upload flow

1. Client requests a challenge (`/proklesis`)
2. Client completes 3FA login, obtains a session token
3. Client signs the file bytes with the identity key
4. Client POSTs the file to `/ktema?owner=<namespace>` with the signature
5. If bytes already exist under that path, the upload is idempotent — no bandwidth or quota is charged
