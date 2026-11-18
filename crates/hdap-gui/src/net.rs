//! Network helpers used by the GUI application layer.
//!
//! Extracted from `app.rs` so the main application file stays focused on the
//! egui view layer. These functions perform HTTP calls against a pyle and
//! parse the responses into GUI state types.

use serde_json::Value;
use std::collections::BTreeMap;

use hdap_cli::http_client::HttpClient;
use hdap_core::identity::Identity;
use hdap_core::protocol::DiadosiDoc;

use crate::state::{BubblePeer, BubbleStatus, HashLookup};

/// Load a local identity from `krypte.hdap` + `prosopeion.hdap`.
pub fn load_local(
    password: &str,
    krypte: &std::path::Path,
    pros: &std::path::Path,
) -> Result<Identity, hdap_cli::IdentityStoreError> {
    hdap_cli::identity_store::load(password.as_bytes(), krypte, pros)
}

/// Bucket the flat snapshot `ktema` list into `dir -> entries`. A file at
/// `docs/sub/a.txt` lands in bucket `docs/sub`; the root-level files and dirs
/// land in bucket `""`. Directories appear in their *parent* bucket (the node
/// lists `docs` and `docs/sub` as `dir: true` entries with their full path).
pub fn build_tree(
    snapshot: &[hdap_cli::flow::KtemaEntry],
) -> std::collections::BTreeMap<String, Vec<hdap_cli::flow::KtemaEntry>> {
    let mut tree: std::collections::BTreeMap<String, Vec<hdap_cli::flow::KtemaEntry>> =
        std::collections::BTreeMap::new();
    for e in snapshot {
        let dir = match e.path.rfind('/') {
            Some(i) => e.path[..i].to_string(),
            None => String::new(),
        };
        tree.entry(dir).or_default().push(e.clone());
    }
    tree
}

/// Build the signed `diadosi.hdap` body. The document is signed by the owner
/// over its canonical bytes, and pins the current prosopeion/adeia hashes so
/// a fallback can only promote the exact identity it was authorized for.
pub fn build_diadosi(
    identity: &Identity,
    home: &str,
    fallbacks: &[String],
    properties: &str,
    adeia: &str,
    edition: u64,
    prev_hash: Option<String>,
) -> Result<Vec<u8>, String> {
    let adeia_doc = hdap_core::doc::parse(adeia).map_err(|e| e.to_string())?;
    if adeia_doc.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("adeia.hdap is not an adeia document".into());
    }
    let owner = identity.global_id();
    let proxy = DiadosiDoc {
        owner: owner.clone(),
        owner_pubkey: hex::encode(identity.sign_pubkey()),
        home_pyle: home.to_string(),
        fallbacks: fallbacks.to_vec(),
        adeia_edition: adeia_doc.edition,
        adeia_hash: hdap_core::crypto::sha256_hex(adeia.as_bytes()),
        properties_hash: hdap_core::crypto::sha256_hex(properties.as_bytes()),
        edition,
        prev_hash,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let mut doc = proxy.to_doc();
    doc.sigs.push(hdap_core::doc::Signature {
        signer: owner,
        signer_pubkey: Some(proxy.owner_pubkey.clone()),
        signature: String::new(),
    });
    let input = doc.signature_input(0).map_err(|e| e.to_string())?;
    doc.sigs[0].signature = hdap_core::sig_to_b64(&identity.sign_bytes(input.as_bytes()));
    Ok(doc.render().into_bytes())
}

pub fn post_diadosi(
    client: &HttpClient,
    token: &str,
    body: &[u8],
    edition: u64,
) -> Result<u64, String> {
    let resp = client
        .post_with_token("/diadosi", &BTreeMap::new(), token, body)
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("diadosi {}", resp.status)));
    }
    Ok(v["edition"].as_u64().unwrap_or(edition))
}

/// Build the signed `POST /house_move` body. `current` is the node-truth
/// `adeia`; the new edition is strictly newer and points `PREV_HASH` at it.
pub fn build_house_move(
    identity: &Identity,
    new_pyle: &str,
    edited_adeia: &str,
    current_adeia: &str,
    now: u64,
) -> Result<Vec<u8>, String> {
    let current = hdap_core::doc::parse(current_adeia)
        .map_err(|_| "current adeia is not a valid document".to_string())?;
    if current.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("current document is not an adeia".into());
    }
    let mut next =
        hdap_core::doc::parse(edited_adeia).map_err(|e| format!("new adeia is invalid: {e:?}"))?;
    if next.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("new document is not an adeia".into());
    }
    let edition = current.edition.saturating_add(1).max(next.edition);
    next.edition = edition;
    next.prev_hash = Some(hdap_core::crypto::sha256_hex(current_adeia.as_bytes()));
    if next.created_at == 0 {
        next.created_at = now;
    }
    let properties = identity.signed_prosopeion_doc().render();
    let adeia = next.render();
    let payload =
        hdap_core::house_move_payload(&identity.global_id(), new_pyle, &properties, &adeia);
    let signature = hdap_core::sig_to_b64(&identity.sign_bytes(payload.as_bytes()));
    Ok(serde_json::json!({
        "properties": properties,
        "adeia": adeia,
        "new_pyle": new_pyle,
        "signature": signature,
    })
    .to_string()
    .into_bytes())
}

pub fn post_house_move(client: &HttpClient, token: &str, body: &[u8]) -> Result<u64, String> {
    let resp = client
        .post_with_token("/house_move", &BTreeMap::new(), token, body)
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("house_move {}", resp.status)));
    }
    v["adeia_edition"]
        .as_u64()
        .ok_or_else(|| "house_move response has no edition".to_string())
}

/// `POST /resolve_hash` -> the cached/local location and provenance flag.
pub fn fetch_hash_lookup(
    client: &HttpClient,
    token: &str,
    body: &[u8],
) -> Result<HashLookup, String> {
    let resp = client
        .post_with_token("/resolve_hash", &BTreeMap::new(), token, body)
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("resolve_hash {}", resp.status)));
    }
    Ok(HashLookup {
        status: v["status"].as_str().unwrap_or("unknown").to_string(),
        owner: v["owner"].as_str().unwrap_or("").to_string(),
        path: v["path"].as_str().unwrap_or("").to_string(),
        source: v["source"]
            .as_str()
            .or_else(|| v["origin"]["server"].as_str())
            .unwrap_or("")
            .to_string(),
        verified: v["verified"].as_bool().unwrap_or(false),
        holders: v["holders"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        error: String::new(),
    })
}

/// Parse `GET /bubble` into the summary + peer rows.
pub fn fetch_bubble(client: &HttpClient, token: &str) -> Result<BubbleStatus, String> {
    let resp = client
        .get_with_token("/bubble", &BTreeMap::new(), token)
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("bubble status {}", resp.status));
    }
    let v: Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    let counts = &v["counts"];
    let mut peers = Vec::new();
    for p in v["peers"].as_array().cloned().unwrap_or_default() {
        peers.push(BubblePeer {
            node_id: p["node_id"].as_str().unwrap_or("").to_string(),
            endpoint: p["endpoint"].as_str().unwrap_or("").to_string(),
            tier: p["tier"].as_str().unwrap_or("untrusted").to_string(),
            verified: p["verified"].as_bool().unwrap_or(false),
            failures: p["failures"].as_u64().unwrap_or(0) as u32,
            last_seen: p["last_seen"].as_u64().unwrap_or(0),
        });
    }
    Ok(BubbleStatus {
        total: counts["total"].as_u64().unwrap_or(peers.len() as u64) as usize,
        core: counts["core"].as_u64().unwrap_or(0) as usize,
        extended: counts["extended"].as_u64().unwrap_or(0) as usize,
        untrusted: counts["untrusted"].as_u64().unwrap_or(0) as usize,
        peers,
    })
}

/// Recovery phrase placeholder — the GUI shows the phrase generated by
/// `hdap-cli init` / `RecoveryPhrase::generate`. Kept here so `app.rs` can
/// reference it without importing CLI internals.
pub fn recovery_phrase_help() -> &'static str {
    "A frase de recuperação (64 hex) recria a identidade sem krypte.hdap.\n\
     The recovery phrase (64 hex) rebuilds the identity without krypte.hdap."
}
