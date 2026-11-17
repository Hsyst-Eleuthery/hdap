# User Guide — Chapter 4: Bandwidth and Economy

*Revision 2026-11-17.*

**HDAP v2.0 — Teleios**

**Written by Thaís (op3n/op3ny)**

---

## Bandwidth as credit

HDAP does not charge money for storage. Instead, publishing consumes bandwidth credit (`mochthos`), earned by solving a proof-of-work challenge. Your client mines a small hash puzzle and receives a `syngraphe` (bandwidth contract) that is debited when you upload.

This makes spam expensive: flooding the network requires real computation, not just free requests.

## Earning band credit

```
hdap-cli band TOKEN TARGET_BITS
```

Solves a PoW of the given difficulty and credits your account. The target bits are set by the node (`--pylaia-target`, default 12).

## Quota (`moira`)

Each account has a storage quota (`moira_bytes`, default 0 = unlimited). Uploading consumes quota equal to the delta of new bytes stored. Re-uploading identical bytes costs nothing — the delta is zero.

## Delta accounting

If you overwrite a file with identical content, `st.stored` does not increase and no band credit is consumed. Only new or changed bytes count against quota and bandwidth.

## Price list (`katallaxia`)

Nodes may publish a price list for services (storage, replication, transfer). Prices are optional and advisory; the client decides whether to accept them.
