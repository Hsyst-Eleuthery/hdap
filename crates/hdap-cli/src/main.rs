//! `hdap-cli` — thin HDAP client.
//!
//! Subcommands against a running `hdap-server` node. Identity lives in a
//! password-sealed `krypte.hdap` + public `prosopeion.hdap` (identity_store).
//! Use `--tls-pin` (sha256 of the node cert, AME-09) to speak TLS.

use std::path::{Path, PathBuf};

use hdap_cli::flow::FlowError;
use hdap_cli::identity_store::{self, load, save};
use hdap_cli::{
    accept_transfer, authenticate, band_mochthos, delete, download, fetch_health, fetch_prices,
    list_ktema, publish_alias, register, request_transfer, resolve, rotate_omphalos,
    transfer_inbox, transfer_owner, upload_with_band, HttpClient, Identity,
};
use hdap_core::{crypto::sha256_hex, RecoveryPhrase, RECOVERY_VERSION};

const KRYPTE: &str = "krypte.hdap";
const PROSOPEION: &str = "prosopeion.hdap";

struct CmdArgs {
    host: String,
    port: u16,
    tls_pin: Option<String>,
    pass: String,
    home: PathBuf,
}

fn print_usage() {
    println!(
        "hdap-cli — HDAP thin client\n\
         \n\
         USAGE:\n  \
           hdap-cli [GLOBAL] COMMAND [ARGS]\n\
         \n\
         GLOBAL:\n  \
           --host HOST     node host (default 127.0.0.1)\n  \
           --port PORT     node port (default 8443)\n  \
           --tls-pin PIN   sha256 hex of node cert (enables TLS)\n  \
           --pass-env VAR  read identity passphrase from an environment variable\n  \
           --pass-file FILE  read identity passphrase from a file (one line)\n  \
           --pass PASS     passphrase on argv (DISCOURAGED: visible in process list)\n  \
           --home DIR      identity dir (default ./)\n  \
           --help          show usage\n  \
           --version       show version\n\
         \n\
         COMMANDS:\n  \
           init NICKNAME            create identity (shows recovery phrase)\n  \
           recover PHRASE NICKNAME  recover identity from a recovery phrase\n  \
           register                 register identity on the node\n  \
           auth                     login (3FA) and print token\n  \
           whoami                   print this identity's global id\n  \
           band TOKEN TARGET_BITS   claim band credit via PoW\n  \
           health                   show node facts / Ángelma\n  \
           rotate TOKEN             rotate the OTP anchor with the identity key\n  \
           upload TOKEN OWNER PATH FILE   upload a file\n  \
           download TOKEN OWNER PATH OUT  download a file\n  \
           delete TOKEN OWNER PATH        delete a file\n  \
           list TOKEN OWNER [DIR]   list a directory (default root)\n  \
           alias ALIAS URI          publish alias -> URI\n  \
           resolve ALIAS            resolve alias\n  \
           prices                   show katallaxia price list\n  \
           transfer-request TOKEN KIND NEW_URI TARGET...  create/sign/deliver an offer\n  \
             (KIND is file, dir or identity; TARGET is relative to your space)\n  \
           transfer-inbox TOKEN             list pending transfer offers\n  \
           transfer-accept TOKEN REQUEST_ID accept an offer and copy the assets\n  \
           transfer-own TOKEN NEW_OWNER HOME PATH...  transfer assets (dual-signature)\n  \
             (NEW_OWNER is the assigning user_id; HOME holds that vault's secrets)"
    );
}

fn print_version() {
    println!("hdap-cli {}", env!("CARGO_PKG_VERSION"));
}

fn parse_global() -> (CmdArgs, Vec<String>) {
    parse_global_from(std::env::args().skip(1))
}

/// Global flags may appear before or after the command. This keeps the common
/// `hdap-cli upload ... --tls-pin PIN` form working without forcing the user to
/// remember a positional rule.
fn parse_global_from<I: Iterator<Item = String>>(mut args: I) -> (CmdArgs, Vec<String>) {
    let mut cmd_args = CmdArgs {
        host: "127.0.0.1".to_string(),
        port: 8443,
        tls_pin: None,
        pass: String::new(),
        home: PathBuf::from("."),
    };
    let mut rest = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => cmd_args.host = args.next().expect("--host needs a value"),
            "--port" => {
                cmd_args.port = args
                    .next()
                    .expect("--port needs a value")
                    .parse()
                    .expect("port")
            }
            "--tls-pin" => cmd_args.tls_pin = Some(args.next().expect("--tls-pin needs a value")),
            "--pass-env" => {
                let var = args.next().expect("--pass-env needs a variable name");
                cmd_args.pass = std::env::var(&var).unwrap_or_else(|_| {
                    eprintln!("hdap-cli: environment variable {var} is not set");
                    std::process::exit(2);
                });
            }
            "--pass-file" => {
                let path = args.next().expect("--pass-file needs a path");
                cmd_args.pass = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| {
                        eprintln!("hdap-cli: cannot read passphrase file {path}: {e}");
                        std::process::exit(2);
                    })
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
            }
            "--pass" => {
                eprintln!(
                    "hdap-cli: aviso — --pass expõe a senha na lista de processos; prefira --pass-env, --pass-file ou prompt"
                );
                cmd_args.pass = args.next().expect("--pass needs a value");
            }
            "--home" => cmd_args.home = PathBuf::from(args.next().expect("--home needs a value")),
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                print_version();
                std::process::exit(0);
            }
            _ => rest.push(a),
        }
    }
    (cmd_args, rest)
}

fn client(a: &CmdArgs) -> HttpClient {
    match &a.tls_pin {
        Some(pin) => HttpClient::new_tls(&a.host, a.port, pin.clone()),
        None => HttpClient::new(&a.host, a.port),
    }
}

fn identity_paths(home: &Path) -> (PathBuf, PathBuf) {
    (home.join(KRYPTE), home.join(PROSOPEION))
}

/// Read a passphrase without echoing it. `stty` is a small dependency-free way
/// to disable terminal echo; when stdin is not a TTY (pipes, CI) it simply
/// fails and we still read the line, never from argv.
fn prompt_passphrase(label: &str) -> String {
    use std::io::{BufRead, Write};
    eprint!("hdap-cli: {label}: ");
    let _ = std::io::stderr().flush();
    #[cfg(unix)]
    let _ = std::process::Command::new("stty").arg("-echo").status();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
    if read.is_err() || line.is_empty() {
        eprintln!("hdap-cli: could not read passphrase");
        std::process::exit(2);
    }
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// Fill `args.pass` from env/file/TTY, in that order of safety.
fn resolve_passphrase(args: &mut CmdArgs, confirm: bool) {
    if !args.pass.is_empty() {
        return;
    }
    args.pass = prompt_passphrase("identity passphrase");
    if confirm && args.pass != prompt_passphrase("confirm passphrase") {
        eprintln!("hdap-cli: passphrases do not match");
        std::process::exit(2);
    }
}

fn load_identity(a: &CmdArgs) -> Identity {
    let (k, p) = identity_paths(&a.home);
    load(a.pass.as_bytes(), &k, &p).expect("failed to open identity (init first)")
}

fn main() {
    let (mut args, rest) = parse_global();
    let Some(cmd) = rest.first().map(String::as_str) else {
        print_usage();
        std::process::exit(1);
    };
    let needs_identity = !matches!(
        cmd,
        "health" | "resolve" | "prices" | "download" | "delete" | "list"
    );
    if needs_identity {
        resolve_passphrase(&mut args, cmd == "init");
    }
    let tail: Vec<String> = rest[1..].to_vec();
    match cmd {
        "init" => cmd_init(&args, &tail),
        "recover" => cmd_recover(&args, &tail),
        "register" => cmd_register(&args),
        "auth" => cmd_auth(&args),
        "whoami" => cmd_whoami(&args),
        "band" => cmd_band(&args, &tail),
        "health" => cmd_health(&args),
        "rotate" => cmd_rotate(&args, &tail),
        "upload" => cmd_upload(&args, &tail),
        "download" => cmd_download(&args, &tail),
        "delete" => cmd_delete(&args, &tail),
        "list" => cmd_list(&args, &tail),
        "alias" => cmd_alias(&args, &tail),
        "resolve" => cmd_resolve(&args, &tail),
        "prices" => cmd_prices(&args),
        "transfer-request" => cmd_transfer_request(&args, &tail),
        "transfer-inbox" => cmd_transfer_inbox(&args, &tail),
        "transfer-accept" => cmd_transfer_accept(&args, &tail),
        "transfer-own" => cmd_transfer_own(&args, &tail),
        other => {
            eprintln!("hdap-cli: unknown command `{other}`");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn cmd_init(args: &CmdArgs, tail: &[String]) {
    let nickname = tail.first().map(String::as_str).unwrap_or("user");
    if args.pass.is_empty() {
        eprintln!("hdap-cli: init requires --pass");
        std::process::exit(1);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Derive the identity from a recovery phrase so the user can rebuild it
    // from the phrase alone if krypte.hdap is lost.
    let (recovery, seed) = RecoveryPhrase::generate();
    let identity = Identity::from_seed(nickname, now, &seed);
    let (k, p) = identity_paths(&args.home);
    save(&identity, args.pass.as_bytes(), &k, &p).expect("failed to save identity");
    println!(
        "identity {} created; registered on a node with `register`",
        identity.global_id()
    );
    println!();
    println!("  RECOVERY PHRASE (write this down, keep it offline):");
    println!("      {}", recovery.phrase());
    println!("  Do not screenshot or store this phrase digitally. Write it on paper.");
    println!("  With this phrase and your passphrase you can run:");
    println!("      hdap-cli recover <PHRASE> <NICKNAME>");
    println!();
    eprintln!(
        "hdap-cli: BACK UP NOW — copy `{}` to a second physical location and store the passphrase separately. \
         There is no central recovery: losing the vault or the passphrase loses the identity. \
         Your recovery phrase lets you rebuild the identity from the phrase alone.",
        k.display()
    );
}

fn cmd_recover(args: &CmdArgs, tail: &[String]) {
    let phrase = tail.first().map(String::as_str).unwrap_or("");
    let nickname = tail.get(1).map(String::as_str).unwrap_or("user");
    if phrase.is_empty() {
        eprintln!("hdap-cli: recover requires a recovery phrase (24 BIP-39 words)");
        std::process::exit(1);
    }
    // Strip the version prefix if present, then validate the 24 words.
    let words_only = phrase
        .strip_prefix(RECOVERY_VERSION)
        .map(|s| s.trim())
        .unwrap_or(phrase);
    let recovery = match RecoveryPhrase::from_words(words_only) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hdap-cli: invalid recovery phrase: {e:?}");
            std::process::exit(2);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seed = *recovery.seed;
    let identity = Identity::from_seed(nickname, now, &seed);
    let (k, p) = identity_paths(&args.home);
    // Ask for a passphrase to seal the recovered vault.
    let pass = if args.pass.is_empty() {
        prompt_passphrase("identity passphrase")
    } else {
        args.pass.clone()
    };
    save(&identity, pass.as_bytes(), &k, &p).expect("failed to save identity");
    println!("identity {} recovered from phrase", identity.global_id());
    eprintln!(
        "hdap-cli: BACK UP NOW — copy `{}` to a second physical location and store the passphrase separately. \
         There is no central recovery: losing the vault or the passphrase loses the identity.",
        k.display()
    );
}

fn cmd_register(args: &CmdArgs) {
    let identity = load_identity(args);
    let c = client(args);
    let r = register(&c, &identity).expect("register failed");
    println!("registered {}", r.user_id);
}

fn cmd_auth(args: &CmdArgs) {
    let identity = load_identity(args);
    let user_id = identity.global_id();
    let c = client(args);
    let mut step = identity_store::load_step(&args.home);
    let r = loop {
        match authenticate(&c, &identity, &user_id, step) {
            Ok(r) => break r,
            // The node is the authority on where the chain stands. When it
            // says which step it wants, take it — this is the case of a node
            // restored from its database, where the client lost its counter.
            Err(FlowError::Http {
                status: 401,
                ref body,
            }) => {
                match serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v.get("next").and_then(|n| n.as_u64()))
                {
                    Some(next) if next as usize >= step => {
                        step = next as usize;
                        continue;
                    }
                    _ => {
                        eprintln!("auth failed: {body}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("auth failed: {e}");
                std::process::exit(1);
            }
        }
    };
    // The chain moved one step past the one we just proved.
    identity_store::save_step(&args.home, step + 1).expect("could not record the otp step");
    println!("token {}", r.token);
}

fn cmd_whoami(args: &CmdArgs) {
    println!("{}", load_identity(args).global_id());
}

fn cmd_band(args: &CmdArgs, tail: &[String]) {
    let token = tail.first().map(String::as_str);
    let Some(token) = token else {
        eprintln!("hdap-cli: band requires TOKEN (from auth)");
        std::process::exit(1);
    };
    let target = tail.get(1).map(String::as_str).unwrap_or("14");
    let bits: usize = target.parse().expect("TARGET_BITS numeric");
    let identity = load_identity(args);
    let c = client(args);
    let bytes = band_mochthos(&c, token, &identity, bits).expect("band claim failed");
    println!("band {} bytes", bytes);
}

fn cmd_health(args: &CmdArgs) {
    let c = client(args);
    let v = fetch_health(&c).expect("health failed");
    println!("server_id={}", v["server_id"].as_str().unwrap_or(""));
    println!(
        "protocol=v{} ({})",
        v["protocol_version"].as_u64().unwrap_or(0),
        v["protocol_codename"].as_str().unwrap_or("")
    );
    println!("version={}", v["version"].as_str().unwrap_or(""));
    println!("node_enc_pub={}", v["node_enc_pub"].as_str().unwrap_or(""));
    println!("time_utc={}", v["time_utc"].as_u64().unwrap_or(0));
    println!("date_utc={}", v["date_utc"].as_str().unwrap_or(""));
    println!("uptime_secs={}", v["uptime_secs"].as_u64().unwrap_or(0));
    println!("users={}", v["users"].as_u64().unwrap_or(0));
    println!("files={}", v["files"].as_u64().unwrap_or(0));
    if let Some(motd) = v["motd"].as_str().filter(|s| !s.is_empty()) {
        println!("--- Ángelma ---");
        println!("{motd}");
    }
}

/// Rotate the OTP anchor and update the local vault/prosopeion in one step.
fn cmd_rotate(args: &CmdArgs, tail: &[String]) {
    let Some(token) = tail.first().map(String::as_str) else {
        eprintln!("hdap-cli: rotate requires TOKEN (from auth)");
        std::process::exit(1);
    };
    let identity = load_identity(args);
    let c = client(args);
    let rotated = rotate_omphalos(&c, token, &identity).expect("omphalos rotation failed");
    let updated = Identity {
        otp_k: rotated.seed_iter as usize,
        otp_anchor: rotated.otp_anchor,
        ..identity
    };
    let (k, p) = identity_paths(&args.home);
    save(&updated, args.pass.as_bytes(), &k, &p).expect("failed to save rotated identity");
    identity_store::save_step(&args.home, 1).expect("could not reset the otp step");
    println!(
        "omphalos rotated: seed_iter={} — run `auth` again",
        rotated.seed_iter
    );
}

fn cmd_upload(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 4 {
        eprintln!("hdap-cli: upload needs TOKEN OWNER PATH FILE");
        std::process::exit(1);
    }
    let token = &tail[0];
    let owner = &tail[1];
    let path = &tail[2];
    let file = &tail[3];
    let data = std::fs::read(file).expect("cannot read file");
    let identity = load_identity(args);
    let c = client(args);
    let hash = upload_with_band(&c, token, &identity, owner, path, &data).expect("upload failed");
    println!("hash {hash}");
    println!("sha256 {}", sha256_hex(&data));
}

fn cmd_download(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 4 {
        eprintln!("hdap-cli: download needs TOKEN OWNER PATH OUT");
        std::process::exit(1);
    }
    let token = &tail[0];
    let owner = &tail[1];
    let path = &tail[2];
    let out = &tail[3];
    let c = client(args);
    let (bytes, hash) = download(&c, token, owner, path).expect("download failed");
    std::fs::write(out, &bytes).expect("cannot write file");
    println!("wrote {} bytes, hash {hash}", bytes.len());
}

fn cmd_delete(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 3 {
        eprintln!("hdap-cli: delete needs TOKEN OWNER PATH");
        std::process::exit(1);
    }
    let token = &tail[0];
    let owner = &tail[1];
    let path = &tail[2];
    let c = client(args);
    delete(&c, token, owner, path).expect("delete failed");
    println!("deleted");
}

fn cmd_list(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 2 {
        eprintln!("hdap-cli: list needs TOKEN OWNER [DIR]");
        std::process::exit(1);
    }
    let token = &tail[0];
    let owner = &tail[1];
    let dir = tail.get(2).map(String::as_str).unwrap_or("");
    let c = client(args);
    let entries = list_ktema(&c, token, owner, dir).expect("list failed");
    for e in &entries {
        if e.is_dir {
            println!("{}/", e.name);
        } else {
            println!("{}\t{} bytes\t{}", e.name, e.size, e.hash);
        }
    }
    if entries.is_empty() {
        println!("(empty)");
    }
}

fn cmd_alias(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 3 {
        eprintln!("hdap-cli: alias needs TOKEN ALIAS URI");
        std::process::exit(1);
    }
    let token = &tail[0];
    let alias = &tail[1];
    let uri = &tail[2];
    let c = client(args);
    publish_alias(&c, token, alias, uri).expect("alias publish failed");
    println!("alias {alias} -> {uri}");
}

fn cmd_resolve(args: &CmdArgs, tail: &[String]) {
    let Some(alias) = tail.first() else {
        eprintln!("hdap-cli: resolve needs ALIAS");
        std::process::exit(1);
    };
    let c = client(args);
    let uri = resolve(&c, alias).expect("resolve failed");
    println!("{uri}");
}

fn cmd_prices(args: &CmdArgs) {
    let c = client(args);
    for q in fetch_prices(&c).expect("prices failed") {
        println!(
            "{} {}/GiB/day max {}d kairos {}",
            q.pyle, q.price_per_gib_day, q.max_duration_days, q.valid_kairos
        );
    }
}

fn cmd_transfer_request(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 3 {
        eprintln!("hdap-cli: transfer-request needs TOKEN KIND NEW_URI TARGET...");
        std::process::exit(1);
    }
    let token = &tail[0];
    let kind = &tail[1];
    let new_uri = &tail[2];
    let targets: Vec<String> = tail[3..]
        .iter()
        .map(|t| t.trim().trim_start_matches('/').to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let identity = load_identity(args);
    let c = client(args);
    match request_transfer(&c, token, &identity, new_uri, kind, &targets) {
        Ok(r) => println!(
            "request {} delivered {} -> {}",
            r.request_id, r.old_pyle, r.new_pyle
        ),
        Err(e) => {
            eprintln!("hdap-cli: transfer request failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_transfer_inbox(args: &CmdArgs, tail: &[String]) {
    if tail.is_empty() {
        eprintln!("hdap-cli: transfer-inbox needs TOKEN");
        std::process::exit(1);
    }
    let c = client(args);
    match transfer_inbox(&c, &tail[0]) {
        Ok(items) if items.is_empty() => println!("no pending transfers"),
        Ok(items) => {
            for i in items {
                println!(
                    "{} {} ({}) -> {} [{}] {} file(s) at {}",
                    i.request_id,
                    i.old_nickname,
                    i.old_owner,
                    i.new_uri,
                    i.target_kind,
                    i.assets,
                    i.created_at
                );
            }
        }
        Err(e) => {
            eprintln!("hdap-cli: transfer inbox failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_transfer_accept(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 2 {
        eprintln!("hdap-cli: transfer-accept needs TOKEN REQUEST_ID");
        std::process::exit(1);
    }
    let identity = load_identity(args);
    let c = client(args);
    match accept_transfer(&c, &tail[0], &identity, &tail[1]) {
        Ok(r) => {
            if r.record_path.is_empty() {
                println!("transfer {} accepted", r.status);
            } else {
                println!("transfer {} accepted; record {}", r.status, r.record_path);
            }
        }
        Err(e) => {
            eprintln!("hdap-cli: transfer accept failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `transfer-own TOKEN NEW_OWNER NEW_HOME PATH...` — hand assets to a second
/// identity this user controls (§11). The node verifies the *new owner's*
/// signature too, so the new identity's vault must be reachable locally and
/// its passphrase supplied via `--pass`.
fn cmd_transfer_own(args: &CmdArgs, tail: &[String]) {
    if tail.len() < 4 {
        eprintln!("hdap-cli: transfer-own needs TOKEN NEW_OWNER NEW_HOME PATH...");
        std::process::exit(1);
    }
    let token = &tail[0];
    let new_owner = &tail[1];
    let new_home = PathBuf::from(&tail[2]);
    let targets: Vec<String> = tail[3..].to_vec();
    let old_identity = load_identity(args);
    let (nk, np) = identity_paths(&new_home);
    let new_identity = load(args.pass.as_bytes(), &nk, &np).unwrap_or_else(|e| {
        eprintln!(
            "hdap-cli: cannot open the target identity at {} (need its vault): {e}",
            new_home.display()
        );
        std::process::exit(1);
    });
    let new_id = new_identity.global_id();
    if new_id != *new_owner {
        eprintln!(
            "hdap-cli: NEW_OWNER {new_owner} does not match the vault at {} ({new_id})",
            new_home.display()
        );
        std::process::exit(1);
    }
    let c = client(args);
    let record =
        transfer_owner(&c, token, &old_identity, &new_identity, &targets).expect("transfer failed");
    println!(
        "transferred {} -> {new_owner} (metabibasis {record})",
        targets.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> (CmdArgs, Vec<String>) {
        parse_global_from(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn global_flags_can_follow_the_command() {
        let (args, rest) = parse(&[
            "upload",
            "token",
            "alice_0123",
            "docs/a.txt",
            "a.txt",
            "--host",
            "node.example",
            "--port",
            "9443",
            "--tls-pin",
            "abc",
            "--home",
            "/tmp/id",
            "--pass",
            "secret",
        ]);
        assert_eq!(
            rest,
            vec!["upload", "token", "alice_0123", "docs/a.txt", "a.txt"]
        );
        assert_eq!(args.host, "node.example");
        assert_eq!(args.port, 9443);
        assert_eq!(args.tls_pin.as_deref(), Some("abc"));
        assert_eq!(args.home, PathBuf::from("/tmp/id"));
        assert_eq!(args.pass, "secret");
    }

    #[test]
    fn flags_before_the_command_are_unchanged() {
        let (args, rest) = parse(&["--no", "x"]);
        assert_eq!(args.port, 8443);
        assert_eq!(rest, vec!["--no", "x"]);
    }

    /// End-to-end recovery flow against a real in-process server:
    /// create identity from a recovery phrase → register → login → delete
    /// the vault → recover from the phrase → login again.
    #[test]
    fn recovery_phrase_full_flow_against_server() {
        use hdap_cli::flow::{authenticate, register};
        use hdap_cli::http_client::HttpClient;
        use hdap_core::identity::Identity;
        use hdap_core::vault::{Vault, VaultSecrets};
        use hdap_core::RecoveryPhrase;
        use hdap_server::http;
        use hdap_server::Node;
        use hdap_tls;
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;

        // Self-signed TLS node identity (AME-09); the client pins its cert.
        let tls_identity = hdap_tls::self_signed("node-a", &["127.0.0.1", "localhost"]).unwrap();
        let pin = tls_identity.pin();
        let tls = tls_identity.server_config().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = hdap_server::Config {
            server_id: "node-a".to_string(),
            choregia_per_mochthos: 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let mut node = Node::new(cfg);
        node.tls_pin = Some(pin.clone());
        let node_ref = Arc::new(node);
        let handle = Arc::clone(&node_ref);
        thread::spawn(move || {
            let _ = http::serve_tls(listener, 10 * 1024 * 1024, tls, move |req| {
                handle.handle(&req)
            });
        });
        let client = HttpClient::new_tls("127.0.0.1", port, pin.clone());

        let tmp = std::env::temp_dir().join(format!("hdap-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let krypte = tmp.join("krypte.hdap");
        let pros = tmp.join("prosopeion.hdap");

        // 1. Create identity from a recovery phrase.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (recovery, seed) = RecoveryPhrase::generate();
        let id = Identity::from_seed("recover_test", now, &seed);
        let words = recovery.words_only();

        // 2. Save vault + prosopeion to disk.
        identity_store::save(&id, b"passphrase", &krypte, &pros).unwrap();

        // 3. Register on the server.
        let reg = register(&client, &id).unwrap();
        assert!(!reg.user_id.is_empty());

        // 4. Login (first login uses OTP step 1).
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        assert!(!auth.token.is_empty());

        // 5. Simulate loss of the vault: delete krypte.hdap.
        std::fs::remove_file(&krypte).unwrap();

        // 6. Recover identity from the recovery phrase.
        let recovered = RecoveryPhrase::from_words(&words).unwrap();
        let recovered_id = Identity::from_seed("recover_test", now, &recovered.seed);
        let secrets = VaultSecrets {
            seed: recovered_id.seed(),
            sign_secret: recovered_id.sign_key.to_bytes(),
            enc_secret: recovered_id.enc_secret.to_bytes(),
            recovery_root: recovered_id.recovery_root,
        };
        let vault = Vault::seal(&secrets, b"passphrase");
        std::fs::write(&krypte, vault.to_bytes()).unwrap();

        // 7. Login again with the recovered identity. Step 2 because step 1
        // was already consumed by the first login.
        let auth2 = authenticate(&client, &recovered_id, &reg.user_id, 2).unwrap();
        assert!(!auth2.token.is_empty());
    }
}
