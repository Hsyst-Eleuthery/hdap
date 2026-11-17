//! `hdap-server` — standalone HDAP node daemon.
//!
//! Serves the HTTP/1.1 surface in `hdap_server::node` over TCP. TLS is
//! enabled by default with a fresh self-signed Ed25519 certificate per run
//! (AME-09); the resulting `tls_pin` is printed to stderr and exposed on
//! `/health` so clients can pin it (TOFU). `--no-tls` is for loopback/dev
//! only.

use std::net::TcpListener;
use std::process::ExitCode;

use hdap_server::{config::FederationPeer, Config, Node};

struct Args {
    listen: String,
    /// Explicit node id. When absent the node names itself after its listen
    /// address (`pyle-<base64url(host:port)>`), so access URIs carry the
    /// address and peers can dial without a separate registry.
    server_id: Option<String>,
    no_tls: bool,
    cfg: Config,
    /// Pre-pinned federation peers passed via `--federation-peer` (repeatable).
    /// Format: `node_id:pubkey:endpoint[:tls_pin]`.
    federation_peers: Vec<(String, FederationPeer)>,
    /// Where the SQLite archive lives. Everything the node holds — accounts,
    /// sealed content, the band ledger and the replay guards — is in here.
    data_dir: String,
    /// Run without a database file (state dies with the process). For tests
    /// and throwaway experiments; a real node must not use this.
    ephemeral: bool,
    /// Public `host:port` peers should dial. Needed when `--id` is not derived
    /// from the listen address (and when binding a wildcard).
    advertise: Option<String>,
}

fn print_usage() {
    println!(
        "hdap-server — HDAP node daemon\n\
         \n\
         USAGE:\n  \
           hdap-server [OPTIONS]\n\
         \n\
         OPTIONS:\n  \
           --data DIR           where the archive lives (default ./hdap-node-data)\n  \
            --listen ADDR:PORT   bind address (default 127.0.0.1:8443)\n  \
            --id SERVER_ID       node identifier (default: pyle-<base64(advertise or listen)>)\n  \
             --no-tls             plaintext HTTP (loopback/dev only)\n  \
             --open-federation    accepted for compatibility; federation is always open\n  \
            --advertise ADDR:PORT  public address peers dial; also defines the default id\n  \
           --ephemeral          keep state in RAM only (no database file)\n  \
           --choregia BYTES     band bytes per mochthos (default 4194304)\n  \
           --moira BYTES        per-user storage quota; 0 = unlimited (default 0)\n  \
           --max-upload BYTES   max upload size (default 104857600)\n  \
           --pow-secs N         target seconds per band PoW (default 4)\n  \
           --pow-min-bits N     absolute work floor, never negotiable (default 18)\n  \
           --pow-max-bits N     difficulty ceiling; caps a fake hashrate claim\n  \
           --pow-strict         refuse out-of-range hashrate claims instead of clamping\n  \
           --band-per-hour N    band ceiling per account per hour; 0 = unlimited\n  \
           --entry-pow           require PoW on login (default on)\n  \
           --no-entry-pow        disable the login entry PoW (pylaia)\n  \
           --pylaia-target N     entry PoW difficulty in bits (default 12)\n  \
           --rate-limit N       max requests/sec per peer (0 disables)\n  \
           --motd TEXT          Ángelma (message of the day); HDAP{{[tag]}} placeholders\n  \
           --motd-file FILE     read the Ángelma from a UTF-8 file (last one wins)\n  \
           --master-key-file FILE  store the blob key outside the DB (hex, 0600)\n  \
           --max-connections N  simultaneous connections (default 256)\n  \
           --max-challenges N  outstanding login challenges per user (default 4)\n  \
           --cleanup-interval N seconds between expiry purges; 0 disables (default 60)\n  \
           --time-tolerance N   federation clock-skew tolerance in seconds (default 300)\n  \
           --federation-peer NODE:PUBKEY:ENDPOINT[:TLS_PIN]  pre-pin a federation peer\n  \
           --help               show usage\n  \
           --version            show version"
    );
}

fn print_version() {
    println!("hdap-server {}", env!("CARGO_PKG_VERSION"));
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1).peekable();
    let mut out = Args {
        listen: "127.0.0.1:8443".to_string(),
        server_id: None,
        no_tls: false,
        data_dir: "hdap-node-data".to_string(),
        ephemeral: false,
        advertise: None,
        cfg: Config::default(),
        federation_peers: Vec::new(),
    };
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--listen" => out.listen = take_value(&mut args, "--listen"),
            "--id" => out.server_id = Some(take_value(&mut args, "--id")),
            "--no-tls" => out.no_tls = true,
            // Federation is always open. The flag is kept as an accepted no-op
            // so existing deployments that pass it keep booting.
            "--open-federation" => {}
            "--advertise" => out.advertise = Some(take_value(&mut args, "--advertise")),
            "--data" => out.data_dir = take_value(&mut args, "--data"),
            "--ephemeral" => out.ephemeral = true,
            "--choregia" => out.cfg.choregia_per_mochthos = parse_value(&mut args, "--choregia"),
            "--moira" => out.cfg.moira_bytes = parse_value(&mut args, "--moira"),
            "--max-upload" => out.cfg.max_upload_bytes = parse_value(&mut args, "--max-upload"),
            "--pow-secs" => {
                let v = parse_value::<f64>(&mut args, "--pow-secs");
                out.cfg.pow.target_secs = v.max(1.0) as u32;
            }
            "--pow-min-bits" => {
                let v = parse_value::<usize>(&mut args, "--pow-min-bits");
                out.cfg.pow.min_bits = v;
            }
            "--pow-max-bits" => {
                let v = parse_value::<usize>(&mut args, "--pow-max-bits");
                out.cfg.pow.max_bits = v;
            }
            "--band-per-hour" => {
                out.cfg.band_bytes_per_hour = parse_value(&mut args, "--band-per-hour")
            }
            "--pow-strict" => out.cfg.pow_strict_hashrate = true,
            "--entry-pow" => out.cfg.require_entry_pow = true,
            "--no-entry-pow" => out.cfg.require_entry_pow = false,
            "--pylaia-target" => out.cfg.pylaia_target = parse_value(&mut args, "--pylaia-target"),
            "--rate-limit" => out.cfg.rate_limit_per_sec = parse_value(&mut args, "--rate-limit"),
            "--motd" => out.cfg.motd = take_value(&mut args, "--motd"),
            "--motd-file" => {
                let path = take_value(&mut args, "--motd-file");
                out.cfg.motd = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read --motd-file {path}: {e}"));
            }
            "--master-key-file" => {
                out.cfg.master_key_file = Some(std::path::PathBuf::from(take_value(
                    &mut args,
                    "--master-key-file",
                )));
            }
            "--max-connections" => {
                out.cfg.max_connections = parse_value(&mut args, "--max-connections")
            }
            "--max-challenges" => {
                out.cfg.max_proklesis_per_user = parse_value(&mut args, "--max-challenges")
            }
            "--cleanup-interval" => {
                out.cfg.cleanup_interval_secs = parse_value(&mut args, "--cleanup-interval")
            }
            "--time-tolerance" => {
                out.cfg.time_tolerance_secs = parse_value(&mut args, "--time-tolerance")
            }
            "--federation-peer" => {
                let spec = take_value(&mut args, "--federation-peer");
                let mut parts = spec.splitn(4, ':');
                let node_id = parts.next().unwrap_or("").to_string();
                let pubkey = parts.next().unwrap_or("").to_string();
                let endpoint = parts.next().unwrap_or("").to_string();
                let tls_pin = parts.next().map(|s| s.to_string());
                if node_id.is_empty() || pubkey.is_empty() || endpoint.is_empty() {
                    panic!("invalid --federation-peer '{spec}': expected NODE:PUBKEY:ENDPOINT[:TLS_PIN]");
                }
                out.federation_peers.push((
                    node_id,
                    FederationPeer {
                        pubkey,
                        endpoint,
                        tls_pin,
                    },
                ));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                print_version();
                std::process::exit(0);
            }
            other => panic!("unknown flag `{other}`"),
        }
    }

    // Apply pre-pinned federation peers to the config.
    for (node_id, peer) in &out.federation_peers {
        out.cfg
            .federation_peers
            .insert(node_id.clone(), peer.clone());
    }
    out
}

fn take_value(
    args: &mut std::iter::Peekable<std::iter::Skip<std::env::Args>>,
    flag: &str,
) -> String {
    args.next()
        .unwrap_or_else(|| panic!("{flag} needs a value"))
}

fn parse_value<T: std::str::FromStr>(
    args: &mut std::iter::Peekable<std::iter::Skip<std::env::Args>>,
    flag: &str,
) -> T {
    let raw = take_value(args, flag);
    raw.parse()
        .unwrap_or_else(|_| panic!("invalid value for {flag}: {raw}"))
}

/// Whether a `--listen ADDR:PORT` target is loopback (AME-37 gate for
/// `--no-tls`). A wildcard bind (`0.0.0.0`, `::`, empty host) is **not**
/// loopback and is therefore refused with plaintext.
fn is_loopback_bind(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        Some((h, _)) => h.trim_matches(|c| c == '[' || c == ']'),
        None => listen,
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "localhost:") || {
        // Any 127.x.x.x literal is loopback.
        let octets: Vec<&str> = host.split('.').collect();
        octets.len() == 4 && octets[0] == "127" && octets.iter().all(|o| o.parse::<u8>().is_ok())
    }
}

/// The id a node gives itself when `--id` is absent. `--advertise` is the
/// public address peers will actually dial, so it must win over `--listen`:
/// binding `0.0.0.0:8443` would otherwise bake an unreachable wildcard into the
/// id (and every `endpoint_from_id` consumer would dial `0.0.0.0:8443`).
fn default_server_id(listen: &str, advertise: Option<&str>) -> String {
    let endpoint = advertise
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .unwrap_or(listen);
    hdap_server::pyle::id_from_endpoint(endpoint)
}

/// Read the operator-owned 32-byte hex master key from `path`, creating it
/// with owner-only permissions when absent. On the first v2 boot of a v1 node
/// the key is migrated out of the DB so no sealed blob is orphaned.
fn load_or_create_master_key(
    path: &std::path::Path,
    db_path: &std::path::Path,
    ephemeral: bool,
) -> Result<[u8; 32], String> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read master key file {}: {e}", path.display()))?;
        let hex = raw.trim();
        let bytes = hex::decode(hex)
            .map_err(|e| format!("master key file {} is not valid hex: {e}", path.display()))?;
        return <[u8; 32]>::try_from(bytes).map_err(|v| {
            format!(
                "master key file {} must contain exactly 32 bytes (64 hex chars), got {}",
                path.display(),
                v.len()
            )
        });
    }

    // No key file yet: migrate the v1 key out of an existing DB, or generate a
    // fresh one for a brand-new node.
    let key = if ephemeral {
        let mut key = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
        key
    } else {
        match hdap_server::db::Db::peek_master_key(db_path)
            .map_err(|e| format!("cannot inspect database for master key: {e}"))?
        {
            Some(key) => key,
            None => {
                let mut key = [0u8; 32];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
                key
            }
        }
    };

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create key directory {}: {e}", dir.display()))?;
        }
    }
    write_key_file(path, &key)?;
    hdap_server::hlog!(
        warn,
        "key",
        "master key created at {} — back it up; without it the archive is unreadable",
        path.display()
    );
    Ok(key)
}

fn write_key_file(path: &std::path::Path, key: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("cannot create master key file {}: {e}", path.display()))?;
    f.write_all(hex::encode(key).as_bytes())
        .map_err(|e| format!("cannot write master key file {}: {e}", path.display()))?;
    f.write_all(b"\n")
        .map_err(|e| format!("cannot write master key file {}: {e}", path.display()))?;
    Ok(())
}

fn main() -> ExitCode {
    hdap_server::log::init();
    let mut args = parse_args();
    let server_id = args
        .server_id
        .clone()
        .unwrap_or_else(|| default_server_id(&args.listen, args.advertise.as_deref()));
    args.cfg.server_id = server_id.clone();

    let db_path = std::path::Path::new(&args.data_dir).join("hdap.db");

    // Resolve the master key BEFORE opening the DB: when a key file is
    // configured the DB row is redacted on every flush, so the file is the
    // single authority for decrypting sealed blobs.
    let external_key = match args.cfg.master_key_file.clone() {
        Some(path) => match load_or_create_master_key(&path, &db_path, args.ephemeral) {
            Ok(key) => Some(key),
            Err(e) => {
                hdap_server::hlog!(error, "startup", "{e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            hdap_server::hlog!(
                warn, "startup",
                "chave mestra dentro do banco (legado). Use --master-key-file FILE para mantê-la fora do banco."
            );
            None
        }
    };
    // Snapshot startup settings before `args.cfg` is moved into `Node`.
    let max_body_bytes = args.cfg.max_body_bytes;
    let max_connections = args.cfg.max_connections;
    let cleanup_interval = args.cfg.cleanup_interval_secs;

    let listener = match TcpListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            hdap_server::hlog!(error, "startup", "cannot bind {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };

    // TLS by default: a self-signed Ed25519 identity persisted in the data
    // directory, so its pin survives restarts (AME-09). A fresh cert per boot
    // would invalidate every pinned peer, mirror release and discovery
    // handshake; `--ephemeral` keeps the old in-memory behaviour explicitly.
    //
    // AME-37: `--no-tls` is a development convenience for loopback. Refuse it
    // on any other bind address instead of happily serving uploads, tokens and
    // the federation API in cleartext — the flag's own help text already says
    // "loopback/dev only".
    if args.no_tls && !is_loopback_bind(&args.listen) {
        hdap_server::hlog!(
            error, "startup",
            "--no-tls exige --listen em loopback (127.0.0.1, ::1 ou localhost); recusando HTTP em claro em {}",
            args.listen
        );
        return ExitCode::FAILURE;
    }
    let tls_cfg = if args.no_tls {
        None
    } else {
        let tls = if args.ephemeral {
            hdap_tls::self_signed(&server_id, &["localhost"])
        } else {
            let dir = std::path::Path::new(&args.data_dir);
            hdap_tls::TlsIdentity::load_or_create(
                &server_id,
                &["localhost"],
                &dir.join("tls.crt"),
                &dir.join("tls.key"),
            )
        };
        let tls = match tls {
            Ok(id) => {
                let pin = id.pin();
                hdap_server::hlog!(warn, "tls", "tls_pin={pin} (client TOFU anchor)");
                match id.server_config() {
                    Ok(cfg) => Some((pin, cfg)),
                    Err(e) => {
                        hdap_server::hlog!(error, "tls", "TLS config failed: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                hdap_server::hlog!(error, "tls", "TLS keygen failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        tls
    };

    let mut node = Node::new(args.cfg);
    node.advertise_endpoint = args
        .advertise
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            if args.listen.starts_with("0.0.0.0:") || args.listen.starts_with("[::]:") {
                None
            } else {
                Some(args.listen.clone())
            }
        });
    if let Some((pin, _)) = &tls_cfg {
        node.tls_pin = Some(pin.clone());
    }

    // Open the archive before serving a single request, so a broken or
    // unreadable database is a startup failure with a clear message rather
    // than a node that answers `200` while silently keeping nothing.
    if args.ephemeral {
        hdap_server::hlog!(
            warn,
            "startup",
            "--ephemeral: NADA será salvo, tudo morre com o processo"
        );
        let db = match hdap_server::db::Db::open_memory_with_master_key(external_key) {
            Ok(db) => db,
            Err(e) => {
                hdap_server::hlog!(error, "startup", "banco em memória falhou: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = node.with_db(std::sync::Arc::new(db)) {
            hdap_server::hlog!(error, "startup", "estado inicial falhou: {e}");
            return ExitCode::FAILURE;
        }
    } else {
        let db = match hdap_server::db::Db::open_with_master_key(&db_path, external_key) {
            Ok(db) => db,
            Err(e) => {
                hdap_server::hlog!(
                    error,
                    "startup",
                    "não consegui abrir {}: {e}",
                    db_path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        let db = std::sync::Arc::new(db);
        if let Err(e) = node.with_db(db.clone()) {
            hdap_server::hlog!(
                error,
                "startup",
                "estado gravado em {} é ilegível: {e}",
                db_path.display()
            );
            return ExitCode::FAILURE;
        }
        if let Err(e) = node.persist() {
            hdap_server::hlog!(error, "startup", "falha ao gravar o estado inicial: {e}");
            return ExitCode::FAILURE;
        }
        // Read the counts *after* the load, so "retomado" reflects the file.
        let n_users = node.lock_state().users.len();
        let resuming = n_users > 0;
        hdap_server::hlog!(
            info,
            "startup",
            "banco {} ({})",
            db_path.display(),
            if resuming {
                format!("retomado: {n_users} conta(s)")
            } else {
                "novo".to_string()
            }
        );
    }

    // `node` is moved into the handler below, so read the id out first.
    let server_id = node.cfg.server_id.clone();
    hdap_server::hlog!(
        info,
        "startup",
        "{} on {} node_id={}",
        if args.no_tls { "(plaintext)" } else { "(TLS)" },
        args.listen,
        server_id
    );

    let node = std::sync::Arc::new(node);
    let discovery = std::sync::Arc::clone(&node);
    std::thread::spawn(move || hdap_server::node::discovery::run_forever(discovery));
    if cleanup_interval > 0 {
        let cleanup_node = std::sync::Arc::clone(&node);
        std::thread::spawn(move || hdap_server::node::cleanup::run_forever(cleanup_node));
    } else {
        hdap_server::hlog!(
            warn,
            "cleanup",
            "limpeza periódica desativada (--cleanup-interval 0)"
        );
    }
    let limiter = hdap_server::http::ConnectionLimiter::new(max_connections);
    let handle = move |req: hdap_server::http::Request| node.handle(&req);
    let result = match tls_cfg {
        None => hdap_server::http::serve_with_limit(listener, max_body_bytes, limiter, handle),
        Some((_, cfg)) => {
            hdap_server::http::serve_tls_with_limit(listener, max_body_bytes, cfg, limiter, handle)
        }
    };
    if let Err(e) = result {
        hdap_server::hlog!(error, "serve", "serve error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{default_server_id, is_loopback_bind};

    /// The public address must define the self-id; otherwise a wildcard bind
    /// leaks `0.0.0.0` into every `endpoint_from_id` consumer.
    #[test]
    fn advertise_endpoint_defines_the_default_id() {
        assert_eq!(
            default_server_id("0.0.0.0:8443", Some("pyle1.hdap.hsyst.org:8443")),
            hdap_server::pyle::id_from_endpoint("pyle1.hdap.hsyst.org:8443")
        );
        assert_eq!(
            default_server_id("0.0.0.0:8443", Some("  pyle.thais.fyi:8443  ")),
            hdap_server::pyle::id_from_endpoint("pyle.thais.fyi:8443")
        );
    }

    #[test]
    fn listen_is_the_fallback_when_advertise_is_absent_or_blank() {
        let expected = hdap_server::pyle::id_from_endpoint("127.0.0.1:8443");
        assert_eq!(default_server_id("127.0.0.1:8443", None), expected);
        assert_eq!(default_server_id("127.0.0.1:8443", Some("   ")), expected);
    }

    #[test]
    fn loopback_binds_are_recognised() {
        for good in [
            "127.0.0.1:8443",
            "127.0.0.5:1",
            "localhost:8443",
            "[::1]:8443",
        ] {
            assert!(is_loopback_bind(good), "should be loopback: {good}");
        }
    }

    /// AME-37: `--no-tls` must never expose a node beyond the host.
    #[test]
    fn public_and_wildcard_binds_are_not_loopback() {
        for bad in [
            "0.0.0.0:8443",
            "[::]:8443",
            "192.168.1.10:8443",
            "10.0.0.1:8443",
            "example.org:8443",
        ] {
            assert!(!is_loopback_bind(bad), "should NOT be loopback: {bad}");
        }
    }
}
