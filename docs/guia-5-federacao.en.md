# User Guide — Chapter 5: Federation and Replication

*Revision 2026-11-17.*

**HDAP v2.0 — Teleios**

**Written by Thaís (op3n/op3ny)**

---

## No central server

There is no single HDAP server. There are many independent nodes ("pyles"), each run by its own operator. Pyles federate: they discover each other, verify signatures, and replicate content when it makes sense.

## First-contact pinning

When you first connect to a pyle, you receive its TLS pin (SHA-256 of the certificate). Pin it out of band. On subsequent connections, any certificate that does not match the pinned pin is rejected (TOFU — trust on first use).

You can pre-pin federation peers with `--federation-peer NODE:PUBKEY:ENDPOINT[:TLS_PIN]` so the node rejects impersonators from the start.

## Replication (`apographon`)

Content can be replicated between pyles. A replica is verified by hash: the receiving node checks that the content hash matches before accepting. Replication is pull-based — a node fetches content it is interested in.

## Possession transfer (`metabibasis`)

You can move your home (namespace) from one pyle to another. The transfer is dual-signed: both the source and destination operators sign, and the `prytaneion` records the change of `namespace_owner`. Your `origin_user` (authorship) stays intact.

## Home succession (`diadosi`)

If a pyle goes down, a previously signed succession document (`diadosi.hdap`) allows a trusted substitute to take over your home. This is not a backup of your keys — it is a fallback operator for your namespace.

## Federation security

All federation traffic is TLS-encrypted. Content authenticity comes from Ed25519 signatures on documents, not from transport trust. An impostor can connect but cannot forge your content.
