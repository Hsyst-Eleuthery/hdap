# User Guide — Chapter 6: Operation and Recovery

*Revision 2026-11-17.*

**HDAP v2.0 — Teleios**

**Written by Thaís (op3n/op3ny)**

---

## Running a node

```
hdap-server --listen 0.0.0.0:8443 --advertise mypyle.example.org:8443 \
  --data /var/lib/hdap --master-key-file /var/lib/hdap/master.key
```

The master key is generated on first boot (64 hex chars, file mode 0600). Back it up together with `hdap.db` and `tls.identity` — without it, blobs are unreadable.

## Ángelma (MOTD)

The node's message of the day is configured with `--motd` or `--motd-file`. It supports tags like `HDAP{[uptime]}`, `HDAP{[users]}`, `HDAP{[date_utc]}`. It appears on `/health`, `/motd`, and in the CLI/GUI.

## Operation commands

- `hdap-cli health` — node facts, protocol version, UTC time, Ángelma
- `hdap-cli whoami` — your global id
- `hdap-cli rotate TOKEN` — rotate OTP anchor (requires identity key signature)
- `hdap-cli recover PHRASE NICKNAME` — rebuild identity from recovery phrase

## Recovery

If you lose `krypte.hdap`:
1. Get your recovery phrase (64 hex chars, shown at identity creation)
2. Run `hdap-cli recover <PHRASE> <NICKNAME>`
3. Provide a passphrase to seal the new vault
4. Re-register on your nodes

If you lose the recovery phrase too, the identity is unrecoverable. There is no central authority.

## Production deployment

Use systemd (`docs/hdap-server.service`) or Docker (`Dockerfile`, `docker-entrypoint.sh`). Run as a non-root user. Keep `--data` outside `/tmp`. Back up `krypte.hdap`, `tls.identity`, `master.key`, and `hdap.db` together.

## Upgrading

HDAP v2 reads v1 documents and v1 vaults without conversion. `# VERSION: 1` remains valid. The protocol version is `2` (`PROTOCOL_VERSION`), announced on `/health`.
