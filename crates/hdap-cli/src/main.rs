//! `hdap-cli` — thin HDAP client.
//!
//! Subcommands against a running `hdap-server` node. Identity lives in a
//! password-sealed `krypte.hdap` + public `prosopeion.hdap` (identity_store).
//! Use `--tls-pin` (sha256 of the node cert, AME-09) to speak TLS.

use std::path::{Path, PathBuf};

use hdap_cli::flow::FlowError;
use hdap_cli::identity_store::{self, load, save};
use hdap_cli::{
    accept_transfer, authenticate, band_mochthos, delete, download, fetch_node_facts, fetch_prices,
    list_ktema, publish_alias, register, request_transfer, resolve, transfer_inbox, transfer_owner,
    upload_with_band, HttpClient, Identity,
};
use hdap_core::crypto::sha256_hex;

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
           --pass PASS     identity passphrase\n  \
           --home DIR      identity dir (default ./)\n  \
           --help          show usage\n  \
           --version       show version\n\
         \n\
         COMMANDS:\n  \
           init NICKNAME            create identity\n  \
           register                 register identity on the node\n  \
           auth                     login (3FA) and print token\n  \
           whoami                   print this identity's global id\n  \
           band TOKEN TARGET_BITS   claim band credit via PoW\n  \
           health                   show node facts\n  \
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
            "--pass" => cmd_args.pass = args.next().expect("--pass needs a value"),
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

fn load_identity(a: &CmdArgs) -> Identity {
    let (k, p) = identity_paths(&a.home);
    load(a.pass.as_bytes(), &k, &p).expect("failed to open identity (init first)")
}

fn main() {
    let (args, rest) = parse_global();
    let Some(cmd) = rest.first().map(String::as_str) else {
        print_usage();
        std::process::exit(1);
    };
    let tail: Vec<String> = rest[1..].to_vec();
    match cmd {
        "init" => cmd_init(&args, &tail),
        "register" => cmd_register(&args),
        "auth" => cmd_auth(&args),
        "whoami" => cmd_whoami(&args),
        "band" => cmd_band(&args, &tail),
        "health" => cmd_health(&args),
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
    let identity = Identity::try_generate(nickname, now).unwrap_or_else(|e| {
        eprintln!("hdap-cli: invalid nickname: {e}");
        std::process::exit(2);
    });
    let (k, p) = identity_paths(&args.home);
    save(&identity, args.pass.as_bytes(), &k, &p).expect("failed to save identity");
    println!(
        "identity {} created; registered on a node with `register`",
        identity.global_id()
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
                    _ => panic!("auth failed: {body}"),
                }
            }
            Err(e) => panic!("auth failed: {e}"),
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
    let (server_id, node_enc_pub) = fetch_node_facts(&c).expect("health failed");
    println!("server_id={server_id}");
    println!("node_enc_pub={node_enc_pub}");
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
}
