//! High-level HDAP client flows (thin layer): register, 3FA authenticate,
//! mochthos (band PoW), upload/download/delete and kerux (DDNS) resolution.
//! All protocol construction lives in `hdap-core`; this module only
//! marshals HTTP against the Greek routes of especificacao-hdap.md §14.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use base64::Engine;
use ed25519_dalek::Signer;
use serde_json::{json, Value};

use hdap_core::auth::{
    derive_shared_key, prove_knowledge, prove_possession, prove_session_secret, Challenge,
};
use hdap_core::crypto::{otp_chain, sha256, CryptoError};
use hdap_core::doc::{parse as parse_doc, ParseError, Signature};
use hdap_core::identity::Identity;
use hdap_core::pow::solve_pow_rand;
use hdap_core::protocol::{
    SyngrapheDoc, TransferAcceptDoc, TRANSFER_TARGET_DIR, TRANSFER_TARGET_FILE,
    TRANSFER_TARGET_IDENTITY,
};

pub use crate::http_client::{HttpClient, HttpResponse};

/// Errors from a flow step.
#[derive(Debug)]
pub enum FlowError {
    Io(io::Error),
    Doc(ParseError),
    #[allow(missing_docs)]
    Http {
        status: u16,
        body: String,
    },
    Proto(String),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::Io(e) => write!(f, "io: {e}"),
            FlowError::Doc(e) => write!(f, "doc: {e}"),
            FlowError::Http { status, body } => write!(f, "http {status}: {body}"),
            FlowError::Proto(s) => write!(f, "protocol: {s}"),
        }
    }
}

impl std::error::Error for FlowError {}

impl From<io::Error> for FlowError {
    fn from(e: io::Error) -> Self {
        FlowError::Io(e)
    }
}

impl From<ParseError> for FlowError {
    fn from(e: ParseError) -> Self {
        FlowError::Doc(e)
    }
}

impl From<CryptoError> for FlowError {
    fn from(e: CryptoError) -> Self {
        FlowError::Proto(format!("crypto: {e:?}"))
    }
}

fn ok_json(resp: HttpResponse) -> Result<Value, FlowError> {
    if !(200..300).contains(&resp.status) {
        return Err(FlowError::Http {
            status: resp.status,
            body: String::from_utf8_lossy(&resp.body).into_owned(),
        });
    }
    serde_json::from_slice(&resp.body).map_err(|_| FlowError::Proto("non-json response".into()))
}

fn token_headers(token: &str) -> BTreeMap<String, String> {
    let mut h = BTreeMap::new();
    h.insert("x-hdap-token".to_string(), token.to_string());
    h
}

/// Learn the node's `server_id` and ENC public key from `/health`.
pub fn fetch_node_facts(client: &HttpClient) -> Result<(String, String), FlowError> {
    let v = ok_json(client.get("/health", &BTreeMap::new())?)?;
    let server_id = v["server_id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("health missing server_id".into()))?;
    let node_enc_pub = v["node_enc_pub"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("health missing node_enc_pub".into()))?;
    Ok((server_id, node_enc_pub))
}

/// Result of a successful registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResult {
    pub user_id: String,
}

/// Publish the user's public identity to a node.
pub fn register(client: &HttpClient, identity: &Identity) -> Result<RegisterResult, FlowError> {
    let body = json!({ "properties": identity.signed_prosopeion_doc().render() }).to_string();
    let resp = client.request(
        "POST",
        "/register",
        &BTreeMap::new(),
        &BTreeMap::new(),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    let user_id = v["user_id"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing user_id".into()))?
        .to_string();
    Ok(RegisterResult { user_id })
}

/// Result of a successful 3-factor login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub token: String,
    pub exp: u64,
}

/// Run the full 3FA flow against the node. `otp_step` is the counter of the
/// OTP preimage being revealed (1 for the first login).
pub fn authenticate(
    client: &HttpClient,
    identity: &Identity,
    user_id: &str,
    otp_step: usize,
) -> Result<AuthResult, FlowError> {
    let (server_id, node_enc_pub) = fetch_node_facts(client)?;
    let node_enc_pub_bytes: [u8; 32] = hex::decode(&node_enc_pub)
        .map_err(|_| FlowError::Proto("bad node_enc_pub hex".into()))?
        .try_into()
        .map_err(|_| FlowError::Proto("bad node_enc_pub length".into()))?;

    // Factor-1 challenge (single-use, TTL-scoped).
    let mut q = BTreeMap::new();
    q.insert("user".to_string(), user_id.to_string());
    let v = ok_json(client.get("/proklesis", &q)?)?;
    let nonce = v["nonce"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing nonce".into()))?
        .to_string();
    let ts = v["ts"]
        .as_u64()
        .ok_or_else(|| FlowError::Proto("missing ts".into()))?;

    // Factor 1: possession.
    let ch = Challenge {
        nonce: nonce.clone(),
        ts,
    };
    let (_, sig) = prove_possession(&identity.sign_key, &ch);
    use base64::Engine;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    // Factor 2: OTP knowledge.
    let seed = sha256(&identity.sign_key.to_bytes());
    let (_, chain) = otp_chain(&seed, identity.otp_k);
    let witness = prove_knowledge(&chain, otp_step)
        .ok_or_else(|| FlowError::Proto("otp step out of range".into()))?;
    let otp_proof_b64 = base64::engine::general_purpose::STANDARD.encode(&witness.proof);

    // Factor 3: k = X25519(user_enc_priv, node_enc_pub), then HMAC-prove it.
    let k = derive_shared_key(&identity.enc_secret, &node_enc_pub_bytes);
    let code_proof = prove_session_secret(&k, user_id, &server_id, ts);

    // Entry toll (`pylaia`, §7.4). The node ships the challenge with the
    // `proklesis`, bound to its nonce, so this is fresh work per login and
    // only this node can honor it. `target_bits` is small by design: it is a
    // toll, not the band meter.
    let pylaia_nonce = if v["pylaia"]["required"].as_bool().unwrap_or(false) {
        let challenge = v["pylaia"]["challenge"]
            .as_str()
            .ok_or_else(|| FlowError::Proto("pylaia required but no challenge".into()))?;
        let target_bits = v["pylaia"]["target_bits"].as_u64().unwrap_or(12) as usize;
        solve_pow_rand(challenge.as_bytes(), target_bits, 1 << 22)
            .ok_or_else(|| FlowError::Proto("pylaia solver exhausted budget".into()))?
            .nonce
    } else {
        0
    };

    let body = json!({
        "user": user_id,
        "nonce": nonce,
        "ts": ts,
        "signature": signature_b64,
        "otp_step": otp_step,
        "otp_proof": otp_proof_b64,
        "code_proof": code_proof,
        "pylaia_nonce": pylaia_nonce,
    })
    .to_string();
    let resp = client.request(
        "POST",
        "/auth",
        &BTreeMap::new(),
        &BTreeMap::new(),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    let token = v["token"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing token".into()))?
        .to_string();
    let exp = v["exp"].as_u64().unwrap_or(0);
    Ok(AuthResult { token, exp })
}

/// The node's advertised mining policy, read from `/mochthos/proklesis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowPolicy {
    pub target_secs: u32,
    pub min_bits: usize,
    pub max_bits: usize,
}

impl PowPolicy {
    fn from_json(v: &serde_json::Value) -> Result<Self, FlowError> {
        let num = |k: &str, d: u64| v[k].as_u64().unwrap_or(d);
        let p = PowPolicy {
            target_secs: num("target_secs", 4).max(1) as u32,
            min_bits: num("min_bits", 18) as usize,
            max_bits: num("max_bits", 28) as usize,
        };
        if p.max_bits < p.min_bits {
            return Err(FlowError::Proto(
                "node advertised max_bits below min_bits".into(),
            ));
        }
        Ok(p)
    }
}

/// Solve a PoW challenge client-side and claim the band credit.
/// Returns the total credited band bytes.
///
/// `target_bits` is ignored except as an escape hatch for tests: the node owns
/// the difficulty. A client that could pick its own would simply ask for zero.
pub fn claim_choregia(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    challenge: &str,
    target_bits: usize,
) -> Result<u64, FlowError> {
    let policy = node_policy(client, token)?;
    // An explicit difficulty inside the node's range is honored so tests stay
    // cheap. Zero, or anything outside the range, defers to this machine's
    // measured hash rate.
    let bits = if (policy.min_bits..=policy.max_bits).contains(&target_bits) {
        target_bits
    } else {
        cheapest_consistent_claim(&policy).1
    };
    // State the hashrate that implies `bits`, so the node's own arithmetic
    // lands on exactly the difficulty we solved.
    let claim_hps = 2f64.powi(bits as i32) / f64::from(policy.target_secs.max(1));
    submit_claim(
        client,
        token,
        id,
        challenge,
        claim_hps,
        bits,
        solve_budget(&policy),
    )
}

/// Attempt budget for the non-cancellable solver: real machines can lawfully
/// need far more than the old fixed `1 << 26` — the adaptive difficulty is
/// `bits_for(measured_hps)`, so budget is sized from the measured hash rate
/// and `target_secs`. The `64x` factor is deliberate headroom: the difficulty
/// is the *ceiling* `ceil(log2(hps * secs))`, so the expected attempts can sit
/// just under a power of two and a smaller factor would fail a solve by chance.
/// Never below 2^20 so tiny test claims still solve instantly.
fn solve_budget(policy: &PowPolicy) -> u64 {
    let hps = hdap_core::pow::measure_hashrate(200_000)
        .map(|h| h.hps())
        .unwrap_or(1e6);
    let secs = f64::from(policy.target_secs.max(1));
    ((hps * secs * 64.0).ceil() as u64).max(1 << 20)
}

/// Measure this machine's real hash rate and pair it with the difficulty the
/// node's policy implies for that claim, so the two always agree.
fn cheapest_consistent_claim(policy: &PowPolicy) -> (f64, usize) {
    let hps = hdap_core::pow::measure_hashrate(200_000)
        .or_else(|| hdap_core::pow::Hashrate::new(1e6))
        .unwrap_or_else(|| hdap_core::pow::Hashrate::new(1e6).expect("1e6 is positive"));
    let secs = f64::from(policy.target_secs.max(1));
    let raw = (hps.hps() * secs).log2().ceil();
    let bits = (raw as isize).clamp(policy.min_bits as isize, policy.max_bits as isize);
    (hps.hps(), bits as usize)
}

fn submit_claim(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    challenge: &str,
    claim_hps: f64,
    bits: usize,
    budget: u64,
) -> Result<u64, FlowError> {
    let proof = solve_pow_rand(challenge.as_bytes(), bits, budget)
        .ok_or_else(|| FlowError::Proto("pow solver exhausted budget".into()))?;
    let body = json!({
        "challenge": challenge,
        "nonce": proof.nonce,
        "hashrate": claim_hps,
    })
    .to_string();
    let resp = client.request(
        "POST",
        "/mochthos/issue",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    // The issued proof is only half a band object: it becomes spendable when
    // the owner countersigns it. This is the prompt's dual signature, not an
    // optional flourish — skip it and the band cannot pay for an upload.
    let path = v["doc"]["path"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing doc path".into()))?;
    let doc_body = v["doc"]["body"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing doc body".into()))?;
    countersign_band(client, token, id, path, doc_body)?;
    v["total_choregia"]
        .as_u64()
        .ok_or_else(|| FlowError::Proto("missing total_choregia".into()))
}

/// Countersign a node-issued `.hdap.pow` as the owner, turning it into a live
/// band object (dual signature, §10). The client signs `signature_input(1)`
/// after appending its own signature slot, exactly as the node reconstructs.
pub fn countersign_band(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    path: &str,
    doc_body: &str,
) -> Result<(), FlowError> {
    let mut doc = parse_doc(doc_body)?;
    let mut sig = Signature {
        signer: id.global_id(),
        signer_pubkey: Some(hex::encode(id.sign_pubkey())),
        signature: String::new(),
    };
    doc.sigs.push(sig.clone());
    let idx = doc.sigs.len() - 1;
    let input = doc.signature_input(idx)?;
    sig.signature = base64::engine::general_purpose::STANDARD
        .encode(id.sign_key.sign(input.as_bytes()).to_bytes());
    let body = json!({
        "path": path,
        "signer_pubkey": sig.signer_pubkey,
        "signature": sig.signature,
    })
    .to_string();
    let v = ok_json(client.request(
        "POST",
        "/mochthos/countersign",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?)?;
    if v["countersigned"].as_bool() != Some(true) {
        return Err(FlowError::Proto(
            "node did not accept the countersignature".into(),
        ));
    }
    Ok(())
}

/// A live band object as reported by `GET /mochthos/band`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandInfo {
    pub id: String,
    pub path: String,
    pub issuer: String,
    pub granted: u64,
    pub remaining: u64,
    pub countersigned: bool,
    pub expires_at: u64,
}

/// List the live band objects for the authenticated user.
pub fn list_band(client: &HttpClient, token: &str) -> Result<Vec<BandInfo>, FlowError> {
    let v = ok_json(client.request(
        "GET",
        "/mochthos/band",
        &BTreeMap::new(),
        &token_headers(token),
        &[],
    )?)?;
    let entries = v["band"]
        .as_array()
        .ok_or_else(|| FlowError::Proto("missing band list".into()))?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(BandInfo {
            id: e["id"].as_str().unwrap_or_default().to_string(),
            path: e["path"].as_str().unwrap_or_default().to_string(),
            issuer: e["issuer"].as_str().unwrap_or_default().to_string(),
            granted: e["granted"].as_u64().unwrap_or(0),
            remaining: e["remaining"].as_u64().unwrap_or(0),
            countersigned: e["countersigned"].as_bool().unwrap_or(false),
            expires_at: e["expires_at"].as_u64().unwrap_or(0),
        });
    }
    Ok(out)
}

/// Build the `X-HDAP-Syngraphe` header that consumes a live band object for
/// `owner/path`, or `None` when no countersigned object has room left.
fn syngraphe_for_upload(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    owner: &str,
    path: &str,
    data: &[u8],
) -> Result<Option<String>, FlowError> {
    let need = data.len() as u64;
    let Some(band) = list_band(client, token)?
        .into_iter()
        .find(|b| b.countersigned && b.remaining >= need)
    else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = SyngrapheDoc {
        owner: owner.to_string(),
        issuer: band.issuer,
        pow_object_hash: band.id,
        used_for: path.to_string(),
        bandwidth_used: need,
        bandwidth_remaining: band.remaining - need,
        created_at: now,
    };
    let mut doc = s.to_doc();
    let mut sig = Signature {
        signer: id.global_id(),
        signer_pubkey: Some(hex::encode(id.sign_pubkey())),
        signature: String::new(),
    };
    doc.sigs.push(sig.clone());
    let input = doc.signature_input(0)?;
    sig.signature = base64::engine::general_purpose::STANDARD
        .encode(id.sign_key.sign(input.as_bytes()).to_bytes());
    doc.sigs[0].signature = sig.signature;
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(doc.render().as_bytes()),
    ))
}

/// Read the node's mining policy. Falls back to a conservative default when a
/// node does not advertise one, so an older server still gets an honest claim.
fn node_policy(client: &HttpClient, token: &str) -> Result<PowPolicy, FlowError> {
    let v = ok_json(client.request(
        "POST",
        "/mochthos/proklesis",
        &BTreeMap::new(),
        &token_headers(token),
        b"",
    )?)?;
    PowPolicy::from_json(&v)
}

/// Ask the node for its band-credit challenge (`/mochthos/proklesis`),
/// returning `(challenge, advertised_target_bits)` without solving.
pub fn proklesis_bits(client: &HttpClient, token: &str) -> Result<(String, usize), FlowError> {
    let v = ok_json(client.request(
        "POST",
        "/mochthos/proklesis",
        &BTreeMap::new(),
        &token_headers(token),
        b"",
    )?)?;
    let challenge = v["challenge"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing challenge".into()))?
        .to_string();
    let policy = PowPolicy::from_json(&v)?;
    // Report the difficulty this machine would actually pay, not a number the
    // node can be told to accept.
    let bits = cheapest_consistent_claim(&policy).1;
    Ok((challenge, bits))
}

/// Ask the node for its band-credit challenge (`/mochthos/proklesis`) and
/// claim band for it. The challenge is bound to this pyle's identity, so the
/// issued proof is only honored by that node (mochthos are honored by the
/// issuer only — the anti double-spend rule).
pub fn band_mochthos(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    target_bits: usize,
) -> Result<u64, FlowError> {
    let (challenge, _policy) = proklesis_challenge(client, token)?;
    claim_choregia(client, token, id, &challenge, target_bits)
}

/// Like [`band_mochthos`] but solves the PoW with a progress callback and a
/// cancellable solver, so a GUI can show a live "working" dialog like HPS did.
pub fn band_mochthos_progress<F>(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    target_bits: usize,
    canceller: &hdap_core::pow::Canceller,
    on_progress: F,
) -> Result<u64, FlowError>
where
    F: Fn(u64),
{
    let (challenge, policy) = proklesis_challenge(client, token)?;
    let bits = if (policy.min_bits..=policy.max_bits).contains(&target_bits) {
        target_bits
    } else {
        cheapest_consistent_claim(&policy).1
    };
    let claim_hps = 2f64.powi(bits as i32) / f64::from(policy.target_secs.max(1));
    // The GUI wants a live attempt counter, so it needs the progress solver
    // rather than the fire-and-forget one. Budget is unbounded: the progress
    // callback keeps the dialog honest and the `Canceller` aborts on demand,
    // exactly like `solve_pow_adaptive`. A fixed low budget would fail some
    // real machines, whose adaptive difficulty can legitimately need more
    // than 2^26 attempts.
    let proof = hdap_core::pow::solve_pow_progress(
        challenge.as_bytes(),
        bits,
        u64::MAX,
        canceller,
        on_progress,
    )
    .ok_or_else(|| FlowError::Proto("pow cancelled or budget exhausted".into()))?;
    let body = json!({
        "challenge": challenge,
        "nonce": proof.nonce,
        "hashrate": claim_hps,
    })
    .to_string();
    let resp = client.request(
        "POST",
        "/mochthos/issue",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    let path = v["doc"]["path"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing doc path".into()))?;
    let doc_body = v["doc"]["body"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing doc body".into()))?;
    countersign_band(client, token, id, path, doc_body)?;
    v["total_choregia"]
        .as_u64()
        .ok_or_else(|| FlowError::Proto("missing total_choregia".into()))
}

/// Ask the node for its band-credit challenge together with its mining policy.
pub fn proklesis_challenge(
    client: &HttpClient,
    token: &str,
) -> Result<(String, PowPolicy), FlowError> {
    let v = ok_json(client.request(
        "POST",
        "/mochthos/proklesis",
        &BTreeMap::new(),
        &token_headers(token),
        b"",
    )?)?;
    let challenge = v["challenge"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("missing challenge".into()))?
        .to_string();
    let policy = PowPolicy::from_json(&v)?;
    Ok((challenge, policy))
}

/// Upload bytes to `owner/path`. Returns the content hash.
pub fn upload(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    owner: &str,
    path: &str,
    data: &[u8],
) -> Result<String, FlowError> {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let mut headers = token_headers(token);
    headers.insert(
        "x-hdap-sphragis".to_string(),
        base64::engine::general_purpose::STANDARD.encode(id.sign_key.sign(data).to_bytes()),
    );
    let mut q = BTreeMap::new();
    q.insert("owner".to_string(), owner.to_string());
    q.insert("path".to_string(), path.to_string());
    let resp = client.request("POST", "/ktema", &q, &headers, data)?;
    let v = ok_json(resp)?;
    v["hash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("missing hash".into()))
}

/// Upload bytes to `owner/path`, consuming a live band object when one covers
/// the payload (the owner's own uploads). Returns the content hash.
///
/// This is the prompt's flow: the upload is paid by a `syngraphe` the client
/// signs, which deletes the `.hdap.pow` and records the remaining band. When
/// no band object covers it (a guest writing into someone else's space, or a
/// node that still credits the integer ledger), it falls back to the plain
/// upload.
pub fn upload_with_band(
    client: &HttpClient,
    token: &str,
    id: &Identity,
    owner: &str,
    path: &str,
    data: &[u8],
) -> Result<String, FlowError> {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let mut headers = token_headers(token);
    // `sphragis`: the author signs the raw bytes, so the node can prove who
    // wrote the content and not merely that the upload was authenticated.
    headers.insert(
        "x-hdap-sphragis".to_string(),
        base64::engine::general_purpose::STANDARD.encode(id.sign_key.sign(data).to_bytes()),
    );
    if owner == id.global_id() {
        if let Some(header) = syngraphe_for_upload(client, token, id, owner, path, data)? {
            headers.insert("x-hdap-syngraphe".to_string(), header);
        }
    }
    let mut q = BTreeMap::new();
    q.insert("owner".to_string(), owner.to_string());
    q.insert("path".to_string(), path.to_string());
    let resp = client.request("POST", "/ktema", &q, &headers, data)?;
    let v = ok_json(resp)?;
    v["hash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("missing hash".into()))
}

/// Download bytes from `owner/path`; returns `(bytes, stored_hash)`.
pub fn download(
    client: &HttpClient,
    token: &str,
    owner: &str,
    path: &str,
) -> Result<(Vec<u8>, String), FlowError> {
    let mut q = BTreeMap::new();
    q.insert("owner".to_string(), owner.to_string());
    q.insert("path".to_string(), path.to_string());
    let resp = client.request("GET", "/ktema", &q, &token_headers(token), &[])?;
    if !(200..300).contains(&resp.status) {
        return Err(FlowError::Http {
            status: resp.status,
            body: String::from_utf8_lossy(&resp.body).into_owned(),
        });
    }
    let hash = resp.headers.get("x-hdap-hash").cloned().unwrap_or_default();
    Ok((resp.body, hash))
}

/// Delete `owner/path`.
pub fn delete(
    client: &HttpClient,
    token: &str,
    owner: &str,
    path: &str,
) -> Result<bool, FlowError> {
    let mut q = BTreeMap::new();
    q.insert("owner".to_string(), owner.to_string());
    q.insert("path".to_string(), path.to_string());
    let resp = client.request("DELETE", "/ktema", &q, &token_headers(token), &[])?;
    let v = ok_json(resp)?;
    Ok(v["deleted"].as_bool().unwrap_or(false))
}

/// One entry of a directory listing. A `dir` entry has empty `size`/`hash`
/// (subdirectories are implicit — they exist as long as a file lives under
/// them, especificação §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtemaEntry {
    pub name: String,
    pub is_dir: bool,
    /// Full path (including the queried directory prefix).
    pub path: String,
    /// Plaintext size in bytes; `0` for directories.
    pub size: u64,
    /// SHA-256 of the plaintext; empty for directories.
    pub hash: String,
}

/// List the contents of `owner/dir` (`dir == ""` lists the root).
pub fn list_ktema(
    client: &HttpClient,
    token: &str,
    owner: &str,
    dir: &str,
) -> Result<Vec<KtemaEntry>, FlowError> {
    let mut q = BTreeMap::new();
    q.insert("owner".to_string(), owner.to_string());
    if !dir.is_empty() {
        q.insert("path".to_string(), dir.to_string());
    }
    let resp = client.request("GET", "/ktema/list", &q, &token_headers(token), &[])?;
    let v = ok_json(resp)?;
    let arr = v["entries"]
        .as_array()
        .ok_or_else(|| FlowError::Proto("list missing entries".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        out.push(KtemaEntry {
            name: e["name"]
                .as_str()
                .ok_or_else(|| FlowError::Proto("entry missing name".into()))?
                .to_string(),
            is_dir: e["dir"].as_bool().unwrap_or(false),
            path: e["path"]
                .as_str()
                .ok_or_else(|| FlowError::Proto("entry missing path".into()))?
                .to_string(),
            size: e["size"].as_u64().unwrap_or(0),
            hash: e["hash"].as_str().unwrap_or_default().to_string(),
        });
    }
    Ok(out)
}

/// Publish an alias -> URI mapping (DDNS).
pub fn publish_alias(
    client: &HttpClient,
    token: &str,
    alias: &str,
    uri: &str,
) -> Result<(), FlowError> {
    let body = json!({ "alias": alias, "uri": uri }).to_string();
    let resp = client.request(
        "POST",
        "/kerux",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?;
    let _ = ok_json(resp)?;
    Ok(())
}

/// Resolve an alias to its URI.
pub fn resolve(client: &HttpClient, alias: &str) -> Result<String, FlowError> {
    let v = ok_json(client.get(&format!("/kerux/{alias}"), &BTreeMap::new())?)?;
    v["uri"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("missing uri".into()))
}

/// A price announcement (`timi`, optional `katallaxia`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimiQuote {
    pub pyle: String,
    pub price_per_gib_day: u64,
    pub max_duration_days: u64,
    pub valid_kairos: u64,
}

/// Read the price list published by federated pyles (`GET /timi`).
pub fn fetch_prices(client: &HttpClient) -> Result<Vec<TimiQuote>, FlowError> {
    let v = ok_json(client.get("/timi", &BTreeMap::new())?)?;
    let mut out = Vec::new();
    for e in v["entries"].as_array().cloned().unwrap_or_default() {
        out.push(TimiQuote {
            pyle: e["pyle"].as_str().unwrap_or("").to_string(),
            price_per_gib_day: e["price_per_gib_day"].as_u64().unwrap_or(0),
            max_duration_days: e["max_duration_days"].as_u64().unwrap_or(0),
            valid_kairos: e["valid_kairos"].as_u64().unwrap_or(0),
        });
    }
    out.sort_by_key(|a| a.price_per_gib_day);
    Ok(out)
}

/// One `prytaneion` matrix row (§10.2): replication + deletion history for a
/// single content hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatrixEntry {
    pub content_hash: String,
    pub origin_server: String,
    pub origin_user: String,
    pub replicas: Vec<String>,
    pub deletions: Vec<String>,
}

/// A trust-score row from `pheme` (§12).
pub type TrustRow = (String, i64);

/// The full login snapshot (`GET /sync`): everything a fresh interface needs
/// in one round-trip, so no panel has to guess or page data lazily.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncSnapshot {
    pub server_id: String,
    pub node_enc_pub: String,
    pub user_id: String,
    /// Band credit still available on this node (§9).
    pub band: u64,
    /// Bytes stored on this node (moira usage, §16.4).
    pub stored: u64,
    /// Storage quota in bytes (0 = unlimited).
    pub moira_bytes: u64,
    /// Highest OTP step the node accepted (so the client can align its
    /// `omphalos.step` and never collide with a step consumed elsewhere).
    pub otp_step: usize,
    /// The user's own space, flattened (dirs + files, full paths).
    pub ktema: Vec<KtemaEntry>,
    /// Config documents at the `ktema` root (`adeia`, `kerux`, `timi`,
    /// `prytaneion`, `prosopeion`) rendered exactly as the node holds them.
    pub docs: BTreeMap<String, String>,
    /// Replication/deletion matrix entries known to this node.
    pub prytaneion: Vec<MatrixEntry>,
    /// Published aliases (`alias`, `uri`).
    pub kerux: Vec<(String, String)>,
    /// Price announcements (`katallaxia`, §16).
    pub timi: Vec<TimiQuote>,
    /// Distributed trust scores (§12).
    pub pheme: Vec<TrustRow>,
}

impl SyncSnapshot {
    fn from_value(v: &Value) -> Result<Self, FlowError> {
        let ktema = v["ktema"].as_array().cloned().unwrap_or_default();
        let mut ktema_out = Vec::with_capacity(ktema.len());
        for e in &ktema {
            ktema_out.push(KtemaEntry {
                name: e["name"].as_str().unwrap_or_default().to_string(),
                is_dir: e["dir"].as_bool().unwrap_or(false),
                path: e["path"].as_str().unwrap_or_default().to_string(),
                size: e["size"].as_u64().unwrap_or(0),
                hash: e["hash"].as_str().unwrap_or_default().to_string(),
            });
        }
        let mut docs = BTreeMap::new();
        if let Some(map) = v["docs"].as_object() {
            for (k, val) in map {
                if let Some(s) = val.as_str() {
                    docs.insert(k.clone(), s.to_string());
                }
            }
        }
        let mut prytaneion = Vec::new();
        for e in v["prytaneion"].as_array().cloned().unwrap_or_default() {
            prytaneion.push(MatrixEntry {
                content_hash: e["content_hash"].as_str().unwrap_or_default().to_string(),
                origin_server: e["origin_server"].as_str().unwrap_or_default().to_string(),
                origin_user: e["origin_user"].as_str().unwrap_or_default().to_string(),
                replicas: e["replicas"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                deletions: e["deletions"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
            });
        }
        let kerux = v["kerux"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                Some((
                    e["alias"].as_str()?.to_string(),
                    e["uri"].as_str()?.to_string(),
                ))
            })
            .collect();
        let timi = v["timi"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|e| TimiQuote {
                pyle: e["pyle"].as_str().unwrap_or_default().to_string(),
                price_per_gib_day: e["price_per_gib_day"].as_u64().unwrap_or(0),
                max_duration_days: e["max_duration_days"].as_u64().unwrap_or(0),
                valid_kairos: e["valid_kairos"].as_u64().unwrap_or(0),
            })
            .collect();
        let pheme = v["pheme"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                Some((
                    e["target"].as_str()?.to_string(),
                    e["score"].as_i64().unwrap_or(0),
                ))
            })
            .collect();
        Ok(SyncSnapshot {
            server_id: v["server_id"].as_str().unwrap_or_default().to_string(),
            node_enc_pub: v["node_enc_pub"].as_str().unwrap_or_default().to_string(),
            user_id: v["user_id"].as_str().unwrap_or_default().to_string(),
            band: v["band"].as_u64().unwrap_or(0),
            stored: v["stored"].as_u64().unwrap_or(0),
            moira_bytes: v["moira_bytes"].as_u64().unwrap_or(0),
            otp_step: v["otp_step"].as_u64().unwrap_or(0) as usize,
            ktema: ktema_out,
            docs,
            prytaneion,
            kerux,
            timi,
            pheme,
        })
    }
}

/// Synchronize *everything* at login, in both directions (especificação §7),
/// through a single round-trip:
///
/// - client -> node: `POST /sync` mirrors the local identity (idempotent
///   register; rotates when the local vault is a newer edition) and any config
///   documents the client last saw (`docs`, reconciled forward-only by the
///   node), so the server holds the same truth as the client.
/// - node -> client: the same response carries the full snapshot (band, the
///   complete recursive `ktema` tree, config docs, matrix, aliases, prices and
///   trust), so the interface starts fully up to date.
pub fn sync_all(
    client: &HttpClient,
    token: &str,
    identity: &Identity,
    docs: &BTreeMap<String, String>,
) -> Result<SyncSnapshot, FlowError> {
    let properties = identity.signed_prosopeion_doc().render();
    let mut body = json!({ "properties": properties });
    if !docs.is_empty() {
        body["docs"] = json!(docs);
    }
    let resp = client.request(
        "POST",
        "/sync",
        &BTreeMap::new(),
        &token_headers(token),
        body.to_string().as_bytes(),
    )?;
    let v = ok_json(resp)?;
    SyncSnapshot::from_value(&v)
}

/// Public nickname -> `user_id` lookup (§14 `GET /registry`). A nickname is
/// not a secret — it only names a folder — so browsers can open another
/// user's space without ever learning a suffix.
pub fn resolve_user(client: &HttpClient, nickname: &str) -> Result<String, FlowError> {
    let mut q = BTreeMap::new();
    q.insert("nickname".to_string(), nickname.to_string());
    let v = ok_json(client.get("/registry", &q)?)?;
    v["user_id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("nickname not found".into()))
}

/// Outcome of `POST /resolve`: where an access URI is served from after the
/// node pulls a remote pyle's namespace locally when needed (apographon on
/// demand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossPyle {
    /// `"local"` when the content was already here, `"mirrored"` when pulled.
    pub status: String,
    /// The pyle now serving it — the node that answered our request.
    pub pyle: String,
    pub owner: String,
    pub path: String,
    /// Entries copied by this call (0 when the mirror already existed).
    pub copied: u64,
    /// Files the source withheld because the requester's `adeia` grants no read
    /// (public config docs excluded). `copied: 0, denied: N` means the mirror
    /// exists but the owner authorized none of their files.
    pub denied: u64,
}

/// Ask our node to resolve an access URI, pulling another pyle's namespace
/// locally when the URI names one (`POST /resolve`). This is the client half
/// of cross-pyle browsing: the node does the federated fetch and mirroring,
/// the client just learns where the content now lives.
pub fn resolve_cross_pyle(
    client: &HttpClient,
    token: &str,
    uri: &str,
) -> Result<CrossPyle, FlowError> {
    let body = json!({ "uri": uri }).to_string();
    let resp = client.request(
        "POST",
        "/resolve",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    Ok(CrossPyle {
        status: v["status"].as_str().unwrap_or("").to_string(),
        pyle: v["pyle"].as_str().unwrap_or("").to_string(),
        owner: v["owner"].as_str().unwrap_or("").to_string(),
        path: v["path"].as_str().unwrap_or("").to_string(),
        copied: v["copied"].as_u64().unwrap_or(0),
        denied: v["denied"].as_u64().unwrap_or(0),
    })
}

/// Transfer ownership of `targets` to another identity (`metabibasis`, §11).
/// The node demands a dual signature — the assignor *and* the assignee sign
/// the same payload — so both identities must be available to the caller.
/// This is how a user hands an asset to a second identity they control; a
/// handshake for a remote party is a future server flow, per §11.
pub fn transfer_owner(
    client: &HttpClient,
    token: &str,
    old_identity: &Identity,
    new_identity: &Identity,
    targets: &[String],
) -> Result<String, FlowError> {
    if targets.is_empty() {
        return Err(FlowError::Proto("at least one target required".into()));
    }
    let old_owner = old_identity.global_id();
    let new_owner = new_identity.global_id();
    let payload = hdap_core::transfer_payload(&old_owner, &new_owner, targets);
    let old_sig = hdap_core::crypto::ed25519_sign(&old_identity.sign_key, payload.as_bytes());
    let new_sig = hdap_core::crypto::ed25519_sign(&new_identity.sign_key, payload.as_bytes());
    let body = json!({
        "new_owner": new_owner,
        "targets": targets,
        "old_signature": hdap_core::sig_to_b64(&old_sig.to_bytes()),
        "new_signature": hdap_core::sig_to_b64(&new_sig.to_bytes()),
    })
    .to_string();
    let resp = client.request(
        "POST",
        "/metabibasis",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?;
    let v = ok_json(resp)?;
    v["record_hash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| FlowError::Proto("missing record hash".into()))
}

/// Result of creating a transfer request (draft + cedente signature + source
/// pyle countersignature, already delivered to the destination inbox).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequestResult {
    pub request_id: String,
    pub request: String,
    pub request_hash: String,
    pub old_pyle: String,
    pub new_pyle: String,
}

/// One pending offer in the authenticated user's transfer inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInboxItem {
    pub request_id: String,
    pub old_owner: String,
    pub old_nickname: String,
    pub old_uri: String,
    pub new_uri: String,
    pub target_kind: String,
    pub assets: u64,
    pub created_at: u64,
    pub request: String,
}

/// Result of accepting an offer (the destination pyle countersigns and, when
/// the source is remote, forwards it so the bytes can be copied).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAcceptResult {
    pub status: String,
    pub record_path: String,
    pub accept: String,
}

fn sign_slot0(doc: &mut hdap_core::Doc, identity: &Identity) -> Result<(), FlowError> {
    let pubkey = hex::encode(identity.sign_key.verifying_key().to_bytes());
    doc.sigs.push(Signature {
        signer: identity.global_id(),
        signer_pubkey: Some(pubkey),
        signature: String::new(),
    });
    let input = doc.signature_input(0)?;
    let sig = hdap_core::crypto::ed25519_sign(&identity.sign_key, input.as_bytes());
    doc.sigs[0].signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    Ok(())
}

fn endpoint_from_pyle_id(id: &str) -> Option<String> {
    let rest = id.strip_prefix("pyle-")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(rest)
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    if text.is_empty() || !text.contains(':') {
        return None;
    }
    Some(text)
}

fn split_endpoint(endpoint: &str) -> Option<(String, u16)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = endpoint.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn discover_remote_pyle(
    pyle_id: &str,
    user_id: &str,
) -> Result<(String, String, String), FlowError> {
    let endpoint = endpoint_from_pyle_id(pyle_id)
        .ok_or_else(|| FlowError::Proto("destination pyle is not endpoint-addressed".into()))?;
    let (host, port) = split_endpoint(&endpoint)
        .ok_or_else(|| FlowError::Proto("invalid pyle endpoint".into()))?;

    let plain = HttpClient::new(&host, port).with_timeouts(
        std::time::Duration::from_millis(800),
        std::time::Duration::from_secs(3),
    );
    let mut client = plain.clone();
    let health = match plain
        .get("/health", &BTreeMap::new())
        .ok()
        .filter(|r| (200..300).contains(&r.status))
    {
        Some(r) => ok_json(r)?,
        None => {
            let tls = HttpClient::new_tls(&host, port, String::new()).with_timeouts(
                std::time::Duration::from_secs(3),
                std::time::Duration::from_secs(5),
            );
            let v = ok_json(tls.get("/health", &BTreeMap::new())?)?;
            client = tls;
            v
        }
    };
    let node_pub = health["node_sign_pub"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("health missing node_sign_pub".into()))?
        .to_string();
    let pin = health["tls_pin"].as_str().unwrap_or("").to_string();
    if !pin.is_empty() {
        client = HttpClient::new_tls(&host, port, pin.clone());
    }
    let mut q = BTreeMap::new();
    q.insert("user_id".to_string(), user_id.to_string());
    let reg = ok_json(client.get("/registry", &q)?)?;
    let user_pub = reg["sign_pub"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("registry missing sign_pub".into()))?
        .to_string();
    Ok((pin, node_pub, user_pub))
}

/// Create an asynchronous ownership-transfer request (§11). The cedente signs
/// the draft locally; the source pyle countersigns and delivers it to the
/// destination inbox. No second vault is needed, unlike `transfer_owner`.
pub fn request_transfer(
    client: &HttpClient,
    token: &str,
    identity: &Identity,
    new_uri: &str,
    target_kind: &str,
    targets: &[String],
) -> Result<TransferRequestResult, FlowError> {
    if !matches!(
        target_kind,
        TRANSFER_TARGET_FILE | TRANSFER_TARGET_DIR | TRANSFER_TARGET_IDENTITY
    ) {
        return Err(FlowError::Proto(
            "target kind must be file, dir or identity".into(),
        ));
    }
    let (new_pyle, new_owner, _path) = hdap_core::parse_access_uri(new_uri)
        .ok_or_else(|| FlowError::Proto("new URI must be HDAP!pyle@user/path".into()))?;
    let (local_pyle, _) = fetch_node_facts(client)?;
    let mut draft = json!({
        "new_owner": new_owner,
        "new_pyle": new_pyle,
        "new_uri": new_uri,
        "target_kind": target_kind,
        "targets": targets,
    });
    if new_pyle != local_pyle {
        let (pin, node_pub, user_pub) = discover_remote_pyle(&new_pyle, &new_owner)?;
        draft["new_pyle_pubkey"] = json!(node_pub);
        draft["new_pyle_tls_pin"] = json!(pin);
        draft["new_owner_pubkey"] = json!(user_pub);
    }
    let body = json!({ "draft": draft }).to_string();
    let v = ok_json(client.request(
        "POST",
        "/transfer/request",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?)?;
    let text = v["request"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("draft missing request".into()))?;
    let mut doc = parse_doc(text)?;
    sign_slot0(&mut doc, identity)?;
    let signed = doc.render();
    let body = json!({ "request": signed }).to_string();
    let v = ok_json(client.request(
        "POST",
        "/transfer/request",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?)?;
    Ok(TransferRequestResult {
        request_id: v["request_id"].as_str().unwrap_or("").to_string(),
        request: v["request"].as_str().unwrap_or("").to_string(),
        request_hash: v["request_hash"].as_str().unwrap_or("").to_string(),
        old_pyle: v["old_pyle"].as_str().unwrap_or("").to_string(),
        new_pyle: v["new_pyle"].as_str().unwrap_or("").to_string(),
    })
}

/// List pending offers addressed to the authenticated user.
pub fn transfer_inbox(
    client: &HttpClient,
    token: &str,
) -> Result<Vec<TransferInboxItem>, FlowError> {
    let v = ok_json(client.request(
        "GET",
        "/transfer/inbox",
        &BTreeMap::new(),
        &token_headers(token),
        &[],
    )?)?;
    let items = v["inbox"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .map(|i| TransferInboxItem {
            request_id: i["request_id"].as_str().unwrap_or("").to_string(),
            old_owner: i["old_owner"].as_str().unwrap_or("").to_string(),
            old_nickname: i["old_nickname"].as_str().unwrap_or("").to_string(),
            old_uri: i["old_uri"].as_str().unwrap_or("").to_string(),
            new_uri: i["new_uri"].as_str().unwrap_or("").to_string(),
            target_kind: i["target_kind"].as_str().unwrap_or("").to_string(),
            assets: i["assets"].as_u64().unwrap_or(0),
            created_at: i["created_at"].as_u64().unwrap_or(0),
            request: i["request"].as_str().unwrap_or("").to_string(),
        })
        .collect())
}

/// Accept an offer by signing the destination pyle's draft. When the source is
/// on another pyle, the destination forwards the acceptance and the source
/// copies the bytes before answering.
pub fn accept_transfer(
    client: &HttpClient,
    token: &str,
    identity: &Identity,
    request_id: &str,
) -> Result<TransferAcceptResult, FlowError> {
    let body = json!({ "draft": request_id }).to_string();
    let v = ok_json(client.request(
        "POST",
        "/transfer/accept",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?)?;
    let text = v["accept"]
        .as_str()
        .ok_or_else(|| FlowError::Proto("draft missing accept".into()))?;
    let mut doc = parse_doc(text)?;
    let accept = TransferAcceptDoc::from_doc(&doc)
        .ok_or_else(|| FlowError::Proto("draft is not an acceptance".into()))?;
    if accept.new_owner != identity.global_id() {
        return Err(FlowError::Proto(
            "acceptance belongs to another identity".into(),
        ));
    }
    sign_slot0(&mut doc, identity)?;
    let signed = doc.render();
    let body = json!({ "accept": signed }).to_string();
    let v = ok_json(client.request(
        "POST",
        "/transfer/accept",
        &BTreeMap::new(),
        &token_headers(token),
        body.as_bytes(),
    )?)?;
    Ok(TransferAcceptResult {
        status: v["status"].as_str().unwrap_or("").to_string(),
        record_path: v["record_path"].as_str().unwrap_or("").to_string(),
        accept: v["accept"].as_str().unwrap_or("").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdap_server::http;
    use hdap_server::node::Node;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn spawn_server_with_id(server_id: &str) -> HttpClient {
        spawn_server_with_policy(server_id, false)
    }

    fn spawn_server_with_policy(server_id: &str, entry_pow: bool) -> HttpClient {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = hdap_server::Config {
            server_id: server_id.to_string(),
            choregia_per_mochthos: 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: entry_pow,
            require_content_signature: false,
            // These are in-process integration tests: the shared "local" bucket
            // would throttle a whole 20+ request script in release-speed runs.
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let node = Arc::new(Node::new(cfg));
        let node_ref = Arc::clone(&node);
        thread::spawn(move || {
            let _ = http::serve(listener, 10 * 1024 * 1024, move |req| node_ref.handle(&req));
        });
        HttpClient::new("127.0.0.1", port)
    }

    fn spawn_endpoint_server() -> (HttpClient, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = hdap_server::pyle::id_from_endpoint(&format!("127.0.0.1:{port}"));
        let cfg = hdap_server::Config {
            server_id: id.clone(),
            choregia_per_mochthos: 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let node = Arc::new(Node::new(cfg));
        let node_ref = Arc::clone(&node);
        thread::spawn(move || {
            let _ = http::serve(listener, 10 * 1024 * 1024, move |req| node_ref.handle(&req));
        });
        (HttpClient::new("127.0.0.1", port), id)
    }

    fn spawn_server() -> HttpClient {
        spawn_server_with_id("node-a")
    }

    fn spawn_server_tls() -> (HttpClient, String) {
        // Self-signed TLS node identity (AME-09); the client pins its cert.
        let identity = hdap_tls::self_signed("node-a", &["127.0.0.1", "localhost"]).unwrap();
        let pin = identity.pin();
        let tls = identity.server_config().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = hdap_server::Config {
            server_id: "node-a".to_string(),
            choregia_per_mochthos: 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            // These are in-process integration tests: the shared "local" bucket
            // would throttle a whole 20+ request script in release-speed runs.
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
        (HttpClient::new_tls("127.0.0.1", port, pin.clone()), pin)
    }

    #[test]
    fn login_solves_the_pylaia_challenge_advertised_by_proklesis() {
        let client = spawn_server_with_policy("node-a", true);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("pylaia_user", now);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1)
            .expect("a node requiring entry PoW must issue a solvable challenge");
        assert!(!auth.token.is_empty());
    }

    #[test]
    fn full_cycle_over_pinned_tls_and_health_reports_pin() {
        let (client, pin) = spawn_server_tls();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("tls_user", now);

        // /health exposes the node's TLS pin so a first-time client can pin it.
        let v: serde_json::Value =
            serde_json::from_slice(&client.get("/health", &BTreeMap::new()).unwrap().body).unwrap();
        assert_eq!(v["server_id"], "node-a");
        assert_eq!(v["tls_pin"], pin);

        // Full register + auth + upload + download cycle over TLS.
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        assert_eq!(band_mochthos(&client, &auth.token, &id, 6).unwrap(), 1024);
        let data = b"tls payload".to_vec();
        let hash = upload(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "tls/segredo.txt",
            &data,
        )
        .unwrap();
        let (down, down_hash) =
            download(&client, &auth.token, &reg.user_id, "tls/segredo.txt").unwrap();
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);
    }

    fn tuple(identity: &Identity) -> (String, String) {
        (identity.global_id(), identity.otp_anchor.clone())
    }

    #[test]
    fn full_register_auth_upload_download_cycle() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("jose", now);

        let (sid, node_enc_pub) = fetch_node_facts(&client).unwrap();
        assert_eq!(sid, "node-a");
        assert_eq!(node_enc_pub.len(), 64);

        let reg = register(&client, &id).unwrap();
        assert_eq!(reg.user_id, id.global_id());
        let (uid, _anchor) = tuple(&id);
        assert_eq!(reg.user_id, uid);

        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        assert!(!auth.token.is_empty());
        assert!(auth.exp > 0);

        // Reusing OTP step 1 on a fresh challenge must fail (replay guard).
        assert!(authenticate(&client, &id, &reg.user_id, 1).is_err());

        assert_eq!(band_mochthos(&client, &auth.token, &id, 6).unwrap(), 1024);

        let data = b"ola hdap".to_vec();
        let hash = upload(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "docs/oi.txt",
            &data,
        )
        .unwrap();
        assert_eq!(hash.len(), 64);

        let (down, down_hash) =
            download(&client, &auth.token, &reg.user_id, "docs/oi.txt").unwrap();
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);

        assert!(delete(&client, &auth.token, &reg.user_id, "docs/oi.txt").unwrap());
        assert!(download(&client, &auth.token, &reg.user_id, "docs/oi.txt").is_err());
    }

    #[test]
    fn upload_without_band_is_rejected() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("bob", now);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        let err = upload(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "a.txt",
            b"sem banda",
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::Http { status: 403, .. }));
    }

    #[test]
    fn dns_publish_and_resolve() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("carol", now);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        publish_alias(&client, &auth.token, "carol.hdap", "HDAP!node-a@carol").unwrap();
        let uri = resolve(&client, "carol.hdap").unwrap();
        assert_eq!(uri, "HDAP!node-a@carol");
    }

    #[test]
    fn prices_list_is_empty_when_no_pyle_announced() {
        let client = spawn_server();
        let prices = fetch_prices(&client).unwrap();
        assert!(prices.is_empty());
    }

    #[test]
    fn list_lists_subdirs_and_files_with_metadata() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("dir_user", now);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        band_mochthos(&client, &auth.token, &id, 6).unwrap();

        let _h1 = upload(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "docs/a.txt",
            b"aaaa",
        )
        .unwrap();
        let h2 = upload(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "docs/sub/b.txt",
            b"bb",
        )
        .unwrap();
        let h3 = upload(&client, &auth.token, &id, &reg.user_id, "raiz.txt", b"root").unwrap();

        // Root listing: docs/ (dir), raiz.txt, plus the `hestia` documents the
        // node seeds at register time (especificacao §3.2).
        let root = list_ktema(&client, &auth.token, &reg.user_id, "").unwrap();
        let names: Vec<(&str, bool)> = root.iter().map(|e| (e.name.as_str(), e.is_dir)).collect();
        assert_eq!(
            names,
            vec![
                ("docs", true),
                ("pow", true),
                ("adeia.hdap", false),
                ("prosopeion.hdap", false),
                ("raiz.txt", false),
            ]
        );
        let file = root.iter().find(|e| e.name == "raiz.txt").unwrap();
        assert_eq!(file.size, 4);
        assert_eq!(file.hash, h3);

        // docs/ lists sub/ (dir) + a.txt.
        let docs = list_ktema(&client, &auth.token, &reg.user_id, "docs").unwrap();
        let dnames: Vec<(&str, bool)> = docs.iter().map(|e| (e.name.as_str(), e.is_dir)).collect();
        assert_eq!(dnames, vec![("sub", true), ("a.txt", false)]);
        let sub = docs.iter().find(|e| e.is_dir).unwrap();
        assert_eq!(sub.path, "docs/sub");

        // Documented content hashes for the nested file are reachable too.
        let nested = docs.iter().find(|e| e.name == "sub").unwrap();
        assert!(list_ktema(&client, &auth.token, &reg.user_id, &nested.path).is_ok());
        let _ = h2;
    }

    #[test]
    fn upload_with_band_consumes_the_issued_pow_object() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("band_user", now);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        assert_eq!(band_mochthos(&client, &auth.token, &id, 6).unwrap(), 1024);

        // The client countersigned the issued proof, so a live band object with
        // room for our payload exists.
        let bands = list_band(&client, &auth.token).unwrap();
        assert!(bands.iter().any(|b| b.countersigned && b.remaining >= 10));

        let data = b"band bytes";
        let hash = upload_with_band(
            &client,
            &auth.token,
            &id,
            &reg.user_id,
            "docs/band.txt",
            data,
        )
        .unwrap();
        assert_eq!(hash.len(), 64);

        // The upload consumed `pow/N.hdap.pow`, leaving `pow/N.hdap.syngraphe`.
        let listing = list_ktema(&client, &auth.token, &reg.user_id, "pow").unwrap();
        let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        assert!(names.iter().any(|n| n.ends_with(".hdap.syngraphe")));
        assert!(!names.iter().any(|n| n.ends_with(".hdap.pow")));

        // The stored treaty carries two signatures: the owner's (slot 0) and
        // the node's ack (slot 1). Both must verify against their advertised
        // keys — that is what makes a syngraphe portable evidence.
        let syn_entry = listing
            .iter()
            .find(|e| e.name.ends_with(".hdap.syngraphe"))
            .unwrap();
        let (syn_bytes, _) = download(&client, &auth.token, &reg.user_id, &syn_entry.path).unwrap();
        let syn_doc = parse_doc(&String::from_utf8_lossy(&syn_bytes)).unwrap();
        assert_eq!(syn_doc.sigs.len(), 2);
        let decode_sig = |b64: &str| {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            ed25519_dalek::Signature::from_slice(&raw).unwrap()
        };
        let owner_in = syn_doc.signature_input(0).unwrap();
        assert!(hdap_core::crypto::ed25519_verify(
            &id.sign_pubkey(),
            owner_in.as_bytes(),
            &decode_sig(&syn_doc.sigs[0].signature),
        )
        .is_ok());
        let health = ok_json(client.get("/health", &BTreeMap::new()).unwrap()).unwrap();
        let node_pub: [u8; 32] = hex::decode(health["node_sign_pub"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let node_in = syn_doc.signature_input(1).unwrap();
        assert!(hdap_core::crypto::ed25519_verify(
            &node_pub,
            node_in.as_bytes(),
            &decode_sig(&syn_doc.sigs[1].signature),
        )
        .is_ok());

        let (down, down_hash) =
            download(&client, &auth.token, &reg.user_id, "docs/band.txt").unwrap();
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);

        // The same band object keeps paying for further uploads until its
        // remaining credit runs out.
        let hash2 = upload_with_band(&client, &auth.token, &id, &reg.user_id, "raiz.txt", b"raiz")
            .expect("second upload with the same band");
        assert_eq!(hash2.len(), 64);
        let (down2, _) = download(&client, &auth.token, &reg.user_id, "raiz.txt").unwrap();
        assert_eq!(down2, b"raiz");
    }

    /// Serve a node backed by an on-disk database, returning the client and the
    /// shared `Db` handle so a test can checkpoint and "restart".
    fn spawn_server_with_db(path: &std::path::Path) -> (HttpClient, Arc<hdap_server::db::Db>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = hdap_server::Config {
            server_id: "node-a".to_string(),
            choregia_per_mochthos: 65536,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            // These are in-process integration tests: the shared "local" bucket
            // would throttle a whole 20+ request script in release-speed runs.
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let db = Arc::new(hdap_server::db::Db::open(path).unwrap());
        let mut node = Node::new(cfg);
        node.with_db(Arc::clone(&db)).unwrap();
        let node = Arc::new(node);
        thread::spawn(move || {
            let _ = http::serve(listener, 10 * 1024 * 1024, move |req| node.handle(&req));
        });
        (HttpClient::new("127.0.0.1", port), db)
    }

    /// AME-35 end-to-end: an account and an upload made through the real HTTP
    /// surface must survive a restart that reloads the same database file. This
    /// is the regression that broke the two-pyle manual test: handlers answered
    /// `200` while nothing was ever written to disk.
    #[test]
    fn state_survives_a_server_restart() {
        let dir = std::env::temp_dir().join(format!("hdap-dur-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hdap.db");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("duravel", now);
        let data = b"persistente".to_vec();

        let (user_id, token, hash) = {
            let (client, db) = spawn_server_with_db(&path);
            let reg = register(&client, &id).unwrap();
            let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
            band_mochthos(&client, &auth.token, &id, 6).unwrap();
            let hash =
                upload(&client, &auth.token, &id, &reg.user_id, "docs/p.txt", &data).unwrap();
            db.checkpoint().unwrap();
            (reg.user_id, auth.token, hash)
        };

        // "Restart": a brand-new node loading the same file.
        let (client2, db2) = spawn_server_with_db(&path);
        // The account and the session are both on disk.
        let reg = ok_json(
            client2
                .get("/registry?nickname=duravel", &BTreeMap::new())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reg["user_id"], user_id, "account must survive a restart");

        let (down, down_hash) = download(&client2, &token, &user_id, "docs/p.txt")
            .expect("the persisted session must still authenticate and read the blob");
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);
        assert!(db2.blob_count().unwrap() >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn async_transfer_request_accept_copies_and_locks_the_source() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = Identity::generate("cedente", now);
        let recipient = Identity::generate("cessionario", now + 1);
        let owner_id = register(&client, &owner).unwrap().user_id;
        let recipient_id = register(&client, &recipient).unwrap().user_id;
        let owner_auth = authenticate(&client, &owner, &owner_id, 1).unwrap();
        let recipient_auth = authenticate(&client, &recipient, &recipient_id, 1).unwrap();
        band_mochthos(&client, &owner_auth.token, &owner, 6).unwrap();
        let data = b"segredo transferido".to_vec();
        let hash = upload(
            &client,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/segredo.txt",
            &data,
        )
        .unwrap();

        let new_uri = format!("HDAP!node-a@{recipient_id}/");
        let request = request_transfer(
            &client,
            &owner_auth.token,
            &owner,
            &new_uri,
            TRANSFER_TARGET_FILE,
            &["docs/segredo.txt".to_string()],
        )
        .unwrap();
        assert!(!request.request_id.is_empty());

        let retry_body = json!({ "request": request.request }).to_string();
        let retry = ok_json(
            client
                .request(
                    "POST",
                    "/transfer/request",
                    &BTreeMap::new(),
                    &token_headers(&owner_auth.token),
                    retry_body.as_bytes(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            retry["request_id"], request.request_id,
            "reposting the same signed request must be idempotent"
        );

        let inbox = transfer_inbox(&client, &recipient_auth.token).unwrap();
        assert_eq!(inbox.len(), 1, "the offer must reach the recipient inbox");
        assert_eq!(inbox[0].request_id, request.request_id);

        let accepted = accept_transfer(
            &client,
            &recipient_auth.token,
            &recipient,
            &request.request_id,
        )
        .unwrap();
        assert_eq!(accepted.status, "completed");
        assert!(!accepted.record_path.is_empty());

        let (down, down_hash) = download(
            &client,
            &recipient_auth.token,
            &recipient_id,
            "docs/segredo.txt",
        )
        .unwrap();
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);

        let rewrite = upload(
            &client,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/segredo.txt",
            &data,
        );
        assert!(
            rewrite.is_err(),
            "a completed metabibasis must leave the cedente read-only"
        );

        // Deleting the cessionário's copy must also retract the old owner's
        // read-only copy and release the cession; otherwise the source path is
        // locked forever and the mirrors keep a file nobody owns.
        assert!(delete(
            &client,
            &recipient_auth.token,
            &recipient_id,
            "docs/segredo.txt"
        )
        .unwrap());
        assert!(
            download(&client, &owner_auth.token, &owner_id, "docs/segredo.txt").is_err(),
            "the source copy must be removed when the new owner deletes theirs"
        );
        band_mochthos(&client, &owner_auth.token, &owner, 6).unwrap();
        upload(
            &client,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/segredo.txt",
            b"reaberto",
        )
        .expect("the cession must be released after the transferred copy is gone");

        // A folder cession covers files created under it later, not only the
        // manifest snapshot that was copied at acceptance time.
        let folder_data = b"dentro da pasta".to_vec();
        upload(
            &client,
            &owner_auth.token,
            &owner,
            &owner_id,
            "pasta/a.txt",
            &folder_data,
        )
        .unwrap();
        let folder_req = request_transfer(
            &client,
            &owner_auth.token,
            &owner,
            &new_uri,
            TRANSFER_TARGET_DIR,
            &["pasta".to_string()],
        )
        .unwrap();
        let accepted = accept_transfer(
            &client,
            &recipient_auth.token,
            &recipient,
            &folder_req.request_id,
        )
        .unwrap();
        assert_eq!(accepted.status, "completed");
        let (down, _) =
            download(&client, &recipient_auth.token, &recipient_id, "pasta/a.txt").unwrap();
        assert_eq!(down, folder_data);
        assert!(
            upload(
                &client,
                &owner_auth.token,
                &owner,
                &owner_id,
                "pasta/novo.txt",
                b"x"
            )
            .is_err(),
            "the whole transferred folder must stay read-only"
        );
    }

    #[test]
    fn identity_transfer_copies_the_whole_space_under_a_namespaced_prefix() {
        let client = spawn_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = Identity::generate("arquivo", now);
        let recipient = Identity::generate("herdeiro", now + 1);
        let owner_id = register(&client, &owner).unwrap().user_id;
        let recipient_id = register(&client, &recipient).unwrap().user_id;
        let owner_auth = authenticate(&client, &owner, &owner_id, 1).unwrap();
        let recipient_auth = authenticate(&client, &recipient, &recipient_id, 1).unwrap();
        band_mochthos(&client, &owner_auth.token, &owner, 6).unwrap();
        let data = b"acervo inteiro".to_vec();
        upload(
            &client,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/a.txt",
            &data,
        )
        .unwrap();

        let new_uri = format!("HDAP!node-a@{recipient_id}/");
        let request = request_transfer(
            &client,
            &owner_auth.token,
            &owner,
            &new_uri,
            TRANSFER_TARGET_IDENTITY,
            &[],
        )
        .unwrap();
        let accepted = accept_transfer(
            &client,
            &recipient_auth.token,
            &recipient,
            &request.request_id,
        )
        .unwrap();
        assert_eq!(accepted.status, "completed");

        let dest = format!("{owner_id}@node-a/docs/a.txt");
        let (down, _) = download(&client, &recipient_auth.token, &recipient_id, &dest).unwrap();
        assert_eq!(down, data);
        assert!(
            upload(
                &client,
                &owner_auth.token,
                &owner,
                &owner_id,
                "outro.txt",
                b"x"
            )
            .is_err(),
            "an identity cession must freeze the cedente's whole space"
        );
    }

    #[test]
    fn transfer_between_two_endpoint_addressed_pyles_round_trips() {
        let (source, source_id) = spawn_endpoint_server();
        let (destination, destination_id) = spawn_endpoint_server();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = Identity::generate("remetente", now);
        let recipient = Identity::generate("destino", now + 1);
        let owner_id = register(&source, &owner).unwrap().user_id;
        let recipient_id = register(&destination, &recipient).unwrap().user_id;
        let owner_auth = authenticate(&source, &owner, &owner_id, 1).unwrap();
        let recipient_auth = authenticate(&destination, &recipient, &recipient_id, 1).unwrap();
        band_mochthos(&source, &owner_auth.token, &owner, 6).unwrap();
        let data = b"atravessa pyles".to_vec();
        let hash = upload(
            &source,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/r.txt",
            &data,
        )
        .unwrap();

        // Mirror the source namespace on the destination first, exactly like
        // the manual test: after the transfer and delete, the mirror must not
        // keep resurrecting the old path.
        {
            use hdap_core::protocol::{adeia_doc, Permission, Right, Scope};
            let perms = vec![Permission {
                scope: Scope::User(recipient_id.clone()),
                right: Right::Read,
            }];
            let text = adeia_doc(&owner_id, 1, None, now, &perms, None).render();
            upload(
                &source,
                &owner_auth.token,
                &owner,
                &owner_id,
                "adeia.hdap",
                text.as_bytes(),
            )
            .unwrap();
            let mirror_uri = format!("HDAP!{source_id}@{owner_id}/");
            resolve_cross_pyle(&destination, &recipient_auth.token, &mirror_uri).unwrap();
            assert!(
                download(&destination, &recipient_auth.token, &owner_id, "docs/r.txt").is_ok(),
                "the destination must hold a mirror of the source before the delete"
            );
        }

        let new_uri = format!("HDAP!{destination_id}@{recipient_id}/");
        let request = request_transfer(
            &source,
            &owner_auth.token,
            &owner,
            &new_uri,
            TRANSFER_TARGET_FILE,
            &["docs/r.txt".to_string()],
        )
        .unwrap();
        let inbox = transfer_inbox(&destination, &recipient_auth.token).unwrap();
        assert_eq!(
            inbox.len(),
            1,
            "the offer must be delivered to the other pyle"
        );

        let accepted = accept_transfer(
            &destination,
            &recipient_auth.token,
            &recipient,
            &request.request_id,
        )
        .unwrap();
        assert_eq!(accepted.status, "completed");
        let (down, down_hash) = download(
            &destination,
            &recipient_auth.token,
            &recipient_id,
            "docs/r.txt",
        )
        .unwrap();
        assert_eq!(down, data);
        assert_eq!(down_hash, hash);
        assert!(
            upload(
                &source,
                &owner_auth.token,
                &owner,
                &owner_id,
                "docs/r.txt",
                &data
            )
            .is_err(),
            "source pyle must stay read-only after the remote accept"
        );

        // The destination pyle signs a release with its node key; the source
        // deletes the old copy and drops the cession without needing a prior
        // federation handshake.
        assert!(delete(
            &destination,
            &recipient_auth.token,
            &recipient_id,
            "docs/r.txt"
        )
        .unwrap());
        assert!(
            download(&source, &owner_auth.token, &owner_id, "docs/r.txt").is_err(),
            "the source pyle must drop the ceded copy after the remote delete"
        );
        assert!(
            download(&destination, &recipient_auth.token, &owner_id, "docs/r.txt").is_err(),
            "the deletion at the source must retract the destination's mirror too"
        );
        band_mochthos(&source, &owner_auth.token, &owner, 6).unwrap();
        upload(
            &source,
            &owner_auth.token,
            &owner,
            &owner_id,
            "docs/r.txt",
            b"reaberto",
        )
        .expect("the remote release must clear the source cession");
        assert!(!source_id.is_empty());
    }

    /// Concurrent mutating requests must all reach disk. `persist()` holds the
    /// state lock across the flush, so a slow writer can never overwrite a
    /// newer snapshot with a stale one (a lost-update race would drop uploads).
    #[test]
    fn concurrent_uploads_all_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hdap-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hdap.db");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("concorrente", now);
        let n = 8usize;

        let (client, db) = spawn_server_with_db(&path);
        let reg = register(&client, &id).unwrap();
        let auth = authenticate(&client, &id, &reg.user_id, 1).unwrap();
        band_mochthos(&client, &auth.token, &id, 6).unwrap();

        let uploaded: Vec<(String, Vec<u8>, String)> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let c = client.clone();
                    let t = auth.token.clone();
                    let u = reg.user_id.clone();
                    let idr = &id;
                    s.spawn(move || {
                        let p = format!("docs/f{i}.txt");
                        let data = format!("payload {i}").into_bytes();
                        let h = upload_with_band(&c, &t, idr, &u, &p, &data).unwrap();
                        (p, data, h)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(uploaded.len(), n);
        db.checkpoint().unwrap();
        drop(db);

        let (client2, _db2) = spawn_server_with_db(&path);
        for (p, data, hash) in &uploaded {
            let (down, down_hash) = download(&client2, &auth.token, &reg.user_id, p)
                .unwrap_or_else(|e| panic!("{p} lost across restart: {e}"));
            assert_eq!(&down, data, "{p} content mismatch");
            assert_eq!(&down_hash, hash, "{p} hash mismatch");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
