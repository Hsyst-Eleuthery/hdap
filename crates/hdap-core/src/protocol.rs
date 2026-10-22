//! Protocol documents building on the canonical `.hdap` doc format:
//! adeia, mochthos, syngraphe, metabibasis, prytaneion, pheme_candidate
//! (especificacao-hdap.md §8–§12).

use crate::doc::{Doc, DocType};
use crate::pow::PowProof;
use base64::Engine as _;
use hex;

/// The canonical bytes both parties sign for a `metabibasis` transfer
/// (especificacao §11.2 — "dupla assinatura"). The node verifies the old
/// owner's signature *and* the new owner's signature over this exact text,
/// so the CLI/GUI and the server must build it identically.
pub fn transfer_payload(old_owner: &str, new_owner: &str, targets: &[String]) -> String {
    let mut t: Vec<String> = targets.to_vec();
    t.sort();
    format!(
        "hdap:transfer_own:{}:>{}:{}",
        old_owner,
        new_owner,
        t.join(",")
    )
}

/// Canonical bytes a user signs to move their "house" (home pyle) and publish
/// a new edition of their `adeia` there. Public content already replicated
/// under an older `adeia` stays available on those replicas; this document only
/// authorizes the *new* home/edition going forward.
pub fn house_move_payload(user_id: &str, new_pyle: &str, properties: &str, adeia: &str) -> String {
    format!(
        "hdap:house_move:{}:>{}:{}:{}",
        user_id,
        new_pyle,
        crate::crypto::sha256_hex(properties.as_bytes()),
        crate::crypto::sha256_hex(adeia.as_bytes())
    )
}

/// base64 (std) of an Ed25519 signature's 64 bytes, the wire form the node
/// expects for `metabibasis` (and anything else carrying signatures).
pub fn sig_to_b64(sig_bytes: &[u8; 64]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(sig_bytes)
}

/// Rights available in an ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    Deny,
    Read,
    Write,
    Own,
}

impl Right {
    pub fn as_str(self) -> &'static str {
        match self {
            Right::Deny => "deny",
            Right::Read => "read",
            Right::Write => "write",
            Right::Own => "own",
        }
    }
}

/// Scope of an ACL grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Applies to everyone.
    All,
    /// Applies to a single user (guest id).
    User(String),
    /// Applies to a top-level path (relative to the owner's doc space).
    Path(String),
}

/// A fully-qualified permission line, e.g.
/// `PERM user:<guest> <path> read` or `ALLOW <user> <path> <right>`.
///
/// Canonical serialization:
/// `PERM <scope> <path> <right>`
/// where scope is `all`, `user:<id>`, or `path:<path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub scope: Scope,
    pub right: Right,
}

impl Permission {
    pub fn to_line(&self, owner: &str) -> String {
        let scope_str = match &self.scope {
            Scope::All => "all".to_string(),
            Scope::User(u) => format!("user:{u}"),
            Scope::Path(p) => format!("path:{p}"),
        };
        format!("PERM {owner} {scope_str} {}", self.right.as_str())
    }
}

/// Build a `adeia.hdap` document (unsigned in construction). `uuid` is an
/// optional stable identifier that survives editions (especificacao §4.3);
/// when `None`, the canonical form only carries ACL lines.
pub fn adeia_doc(
    owner: &str,
    edition: u64,
    prev_hash: Option<String>,
    created_at: u64,
    perms: &[Permission],
    uuid: Option<&str>,
) -> Doc {
    let mut d = Doc::new(DocType::Adeia, edition, prev_hash, created_at);
    if let Some(uuid) = uuid {
        d.body.insert("UUID".into(), uuid.to_string());
    }
    for (i, p) in perms.iter().enumerate() {
        d.body.insert(format!("PERM{i:04}"), p.to_line(owner));
    }
    d
}

/// Body key carrying the replication/read boundary inside `adeia.hdap`.
/// Canonical value: `white:pyle-a;pyle-b;` or `black:pyle-a;pyle-b;`.
pub const DIADOSI_KEY: &str = "DIADOSI";

/// `white` is an allowlist (only listed pyles may replicate/serve); `black`
/// is a denylist (every pyle except the listed ones may).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiadosiMode {
    White,
    Black,
}

impl DiadosiMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DiadosiMode::White => "white",
            DiadosiMode::Black => "black",
        }
    }
}

/// The `DIADOSI` permission embedded in `adeia.hdap`. It is deliberately part
/// of the signed ACL document instead of a separate table: moving the adeia to
/// a new edition atomically changes both who may read and where copies may go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiadosiPolicy {
    pub mode: DiadosiMode,
    pub pyles: Vec<String>,
}

impl DiadosiPolicy {
    /// Parse the canonical one-line value. Whitespace around the mode and the
    /// pyle ids is ignored; a trailing `;` is optional on input and always
    /// emitted on output.
    pub fn parse(text: &str) -> Option<Self> {
        let (mode, rest) = text.trim().split_once(':')?;
        let mode = match mode.trim().to_ascii_lowercase().as_str() {
            "white" => DiadosiMode::White,
            "black" => DiadosiMode::Black,
            _ => return None,
        };
        let mut pyles = Vec::new();
        for raw in rest.split(';') {
            let pyle = raw.trim();
            if pyle.is_empty() {
                continue;
            }
            if pyle.chars().any(char::is_whitespace) || pyles.iter().any(|p| p == pyle) {
                return None;
            }
            pyles.push(pyle.to_string());
        }
        Some(Self { mode, pyles })
    }

    pub fn render(&self) -> String {
        let mut out = format!("{}:", self.mode.as_str());
        for pyle in &self.pyles {
            out.push_str(pyle);
            out.push(';');
        }
        out
    }

    /// Whether `pyle` may replicate and serve content governed by this ACL.
    /// The owner's own operations are handled separately and are never
    /// restricted by this list.
    pub fn allows(&self, pyle: &str) -> bool {
        let listed = self.pyles.iter().any(|p| p == pyle);
        match self.mode {
            DiadosiMode::White => listed,
            DiadosiMode::Black => !listed,
        }
    }

    pub fn from_doc(d: &Doc) -> Option<Self> {
        d.body.get(DIADOSI_KEY).and_then(|v| Self::parse(v))
    }

    pub fn set_on(&self, d: &mut Doc) {
        d.body.insert(DIADOSI_KEY.into(), self.render());
    }
}

/// Build an `adeia.hdap` carrying an optional `DIADOSI` boundary.
pub fn adeia_doc_with_diadosi(
    owner: &str,
    edition: u64,
    prev_hash: Option<String>,
    created_at: u64,
    perms: &[Permission],
    uuid: Option<&str>,
    diadosi: Option<&DiadosiPolicy>,
) -> Doc {
    let mut d = adeia_doc(owner, edition, prev_hash, created_at, perms, uuid);
    if let Some(policy) = diadosi {
        policy.set_on(&mut d);
    }
    d
}

/// Signed fallback proxy (`diadosi.hdap`). The owner pre-authorizes a bounded,
/// ordered list of backup pyles; if the current home stops answering, the
/// first reachable fallback that holds this document may promote itself and
/// keep serving the identity without asking for a new `house_move` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiadosiDoc {
    pub owner: String,
    pub owner_pubkey: String,
    pub home_pyle: String,
    pub fallbacks: Vec<String>,
    pub adeia_edition: u64,
    pub adeia_hash: String,
    pub properties_hash: String,
    pub edition: u64,
    pub prev_hash: Option<String>,
    pub created_at: u64,
}

impl DiadosiDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(
            DocType::Diadosi,
            self.edition,
            self.prev_hash.clone(),
            self.created_at,
        );
        d.body.insert("OWNER".into(), self.owner.clone());
        d.body
            .insert("OWNER_PUBKEY".into(), self.owner_pubkey.clone());
        d.body.insert("HOME_PYLE".into(), self.home_pyle.clone());
        d.body
            .insert("FALLBACK_COUNT".into(), self.fallbacks.len().to_string());
        for (i, pyle) in self.fallbacks.iter().enumerate() {
            d.body.insert(format!("FALLBACK{i:04}"), pyle.clone());
        }
        d.body
            .insert("ADEIA_EDITION".into(), self.adeia_edition.to_string());
        d.body.insert("ADEIA_HASH".into(), self.adeia_hash.clone());
        d.body
            .insert("PROPERTIES_HASH".into(), self.properties_hash.clone());
        d
    }

    pub fn from_doc(d: &Doc) -> Option<Self> {
        if d.doc_type != DocType::Diadosi {
            return None;
        }
        let count: usize = d.body.get("FALLBACK_COUNT")?.parse().ok()?;
        let mut fallbacks = Vec::with_capacity(count);
        for i in 0..count {
            fallbacks.push(d.body.get(&format!("FALLBACK{i:04}"))?.clone());
        }
        Some(Self {
            owner: d.body.get("OWNER")?.clone(),
            owner_pubkey: d.body.get("OWNER_PUBKEY")?.clone(),
            home_pyle: d.body.get("HOME_PYLE")?.clone(),
            fallbacks,
            adeia_edition: d.body.get("ADEIA_EDITION")?.parse().ok()?,
            adeia_hash: d.body.get("ADEIA_HASH")?.clone(),
            properties_hash: d.body.get("PROPERTIES_HASH")?.clone(),
            edition: d.edition,
            prev_hash: d.prev_hash.clone(),
            created_at: d.created_at,
        })
    }

    /// Verify the owner's signature over the canonical document bytes. The
    /// caller must still check that `owner_pubkey` matches the identity on
    /// file; the document cannot vouch for its own root of trust.
    pub fn verify_signature(&self, d: &Doc) -> bool {
        let Some(sig) = d.sigs.first() else {
            return false;
        };
        let Some(key) = hex_pk32(Some(&self.owner_pubkey)) else {
            return false;
        };
        let Some(sig) = sig64(&sig.signature) else {
            return false;
        };
        let Ok(input) = d.signature_input(0) else {
            return false;
        };
        crate::crypto::ed25519_verify(&key, input.as_bytes(), &sig).is_ok()
    }
}

/// A `pow.hdap` object (band proof). `Status` transitions: `unused` →
/// `reserved` → `consumed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MochthosDoc {
    pub owner: String,
    pub issuer: String,
    pub proof: PowProof,
    pub target_bits: usize,
    /// Bytes of storage that this proof authorizes according to the issuer.
    pub bandwidth_bytes: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: String,
}

impl MochthosDoc {
    /// Canonical `.hdap` document form.
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Mochthos, 1, None, self.issued_at);
        d.body.insert("OWNER".into(), self.owner.clone());
        d.body.insert("ISSUER".into(), self.issuer.clone());
        d.body
            .insert("TARGET_BITS".into(), self.target_bits.to_string());
        d.body.insert("NONCE".into(), self.proof.nonce.to_string());
        d.body
            .insert("SOLUTION_HASH".into(), self.proof.solution_hex.clone());
        d.body
            .insert("BANDWIDTH_BYTES".into(), self.bandwidth_bytes.to_string());
        d.body.insert("STATUS".into(), self.status.clone());
        d.body.insert(
            "CHALLENGE".into(),
            "hdap-pow-object".to_string(), // challenge is carried in context
        );
        d.body
            .insert("EXPIRES_AT".into(), self.expires_at.to_string());
        d
    }

    /// Parse a canonical `.hdap.pow` BODY back into a band proof. Returns
    /// `None` when a required field is missing or malformed; a verifier must
    /// not treat a truncated proof as sponsorable.
    pub fn from_doc(d: &Doc) -> Option<MochthosDoc> {
        if d.doc_type != DocType::Mochthos {
            return None;
        }
        let owner = d.body.get("OWNER")?.clone();
        let issuer = d.body.get("ISSUER")?.clone();
        let target_bits = d.body.get("TARGET_BITS")?.parse::<usize>().ok()?;
        let nonce = d.body.get("NONCE")?.parse::<u64>().ok()?;
        let solution_hex = d.body.get("SOLUTION_HASH")?.clone();
        let bandwidth_bytes = d.body.get("BANDWIDTH_BYTES")?.parse::<u64>().ok()?;
        let status = d.body.get("STATUS")?.clone();
        let expires_at = d.body.get("EXPIRES_AT")?.parse::<u64>().ok()?;
        Some(MochthosDoc {
            owner,
            issuer,
            proof: PowProof {
                nonce,
                solution_hex,
                leading_bits: target_bits,
                attempts: 0,
            },
            target_bits,
            bandwidth_bytes,
            issued_at: d.created_at,
            expires_at,
            status,
        })
    }
}

/// A single-use storage grant consumed by an upload — **consumes** a band
/// proof (especificacao-hdap.md §9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyngrapheDoc {
    pub owner: String,
    pub issuer: String,
    /// Hash of the consumed `.hdap.pow`.
    pub pow_object_hash: String,
    pub used_for: String,
    pub bandwidth_used: u64,
    pub bandwidth_remaining: u64,
    pub created_at: u64,
}

impl SyngrapheDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Syngraphe, 1, None, self.created_at);
        d.body.insert("OWNER".into(), self.owner.clone());
        d.body.insert("ISSUER".into(), self.issuer.clone());
        d.body
            .insert("MOCHTHOS_HASH".into(), self.pow_object_hash.clone());
        d.body.insert("USED_FOR".into(), self.used_for.clone());
        d.body
            .insert("BANDWIDTH_USED".into(), self.bandwidth_used.to_string());
        d.body.insert(
            "BANDWIDTH_REMAINING".into(),
            self.bandwidth_remaining.to_string(),
        );
        d
    }

    /// Parse the canonical BODY back into a treaty. Returns `None` when a
    /// required field is missing or malformed, so a caller cannot mistake a
    /// truncated treaty for a valid one.
    pub fn from_doc(d: &Doc) -> Option<SyngrapheDoc> {
        if d.doc_type != DocType::Syngraphe {
            return None;
        }
        let owner = d.body.get("OWNER")?.clone();
        let issuer = d.body.get("ISSUER")?.clone();
        let pow_object_hash = d.body.get("MOCHTHOS_HASH")?.clone();
        let used_for = d.body.get("USED_FOR")?.clone();
        let bandwidth_used = d.body.get("BANDWIDTH_USED")?.parse::<u64>().ok()?;
        let bandwidth_remaining = d.body.get("BANDWIDTH_REMAINING")?.parse::<u64>().ok()?;
        Some(SyngrapheDoc {
            owner,
            issuer,
            pow_object_hash,
            used_for,
            bandwidth_used,
            bandwidth_remaining,
            created_at: d.created_at,
        })
    }
}

/// Transfer of ownership: both parties sign the target
/// (especificacao-hdap.md §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetabibasisDoc {
    pub old_owner: String,
    pub new_owner: String,
    /// Absolute target paths (`HDAP!server@owner/path`).
    pub targets: Vec<String>,
    pub created_at: u64,
}

impl MetabibasisDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Metabibasis, 1, None, self.created_at);
        d.body.insert("OLD_OWNER".into(), self.old_owner.clone());
        d.body.insert("NEW_OWNER".into(), self.new_owner.clone());
        for (i, t) in self.targets.iter().enumerate() {
            d.body.insert(format!("TARGET{i:04}"), t.clone());
        }
        d
    }
}

/// One asset copied by an ownership transfer. `source` is the path in the
/// cedente's space; `dest` is where the copy is written in the cessionário's
/// space (the same path for a file/folder, a namespaced prefix for an
/// identity transfer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTarget {
    pub source: String,
    pub dest: String,
    pub hash: String,
    pub size: u64,
}

/// Canonical transfer request (`metabibasis`, kind `request`).
///
/// The request is signed by the cedente and countersigned by its pyle. It is
/// deliberately self-contained: the cessionário's pyle can display and verify
/// the offer without knowing anything about the source pyle, and the source
/// pyle can later verify that the acceptance refers to *this* exact manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequestDoc {
    pub request_id: String,
    pub old_owner: String,
    pub new_owner: String,
    pub old_nickname: String,
    pub new_nickname: String,
    pub old_uri: String,
    pub new_uri: String,
    pub old_pyle: String,
    pub new_pyle: String,
    pub old_owner_pubkey: String,
    pub new_owner_pubkey: String,
    pub old_pyle_pubkey: String,
    pub new_pyle_pubkey: String,
    pub old_pyle_tls_pin: String,
    pub new_pyle_tls_pin: String,
    pub target_kind: String,
    /// Original selection scopes (`docs/`, `docs/a.txt`, or `""` for a whole
    /// identity). Kept separate from the asset manifest so a folder cession
    /// covers files created under that folder later.
    pub scopes: Vec<String>,
    pub targets: Vec<TransferTarget>,
    pub created_at: u64,
}

pub const TRANSFER_KIND_REQUEST: &str = "request";
pub const TRANSFER_KIND_ACCEPT: &str = "accept";
pub const TRANSFER_TARGET_FILE: &str = "file";
pub const TRANSFER_TARGET_DIR: &str = "dir";
pub const TRANSFER_TARGET_IDENTITY: &str = "identity";

impl TransferRequestDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Metabibasis, 1, None, self.created_at);
        d.body.insert("KIND".into(), TRANSFER_KIND_REQUEST.into());
        d.body.insert("REQUEST_ID".into(), self.request_id.clone());
        d.body.insert("OLD_OWNER".into(), self.old_owner.clone());
        d.body.insert("NEW_OWNER".into(), self.new_owner.clone());
        d.body
            .insert("OLD_NICKNAME".into(), self.old_nickname.clone());
        d.body
            .insert("NEW_NICKNAME".into(), self.new_nickname.clone());
        d.body.insert("OLD_URI".into(), self.old_uri.clone());
        d.body.insert("NEW_URI".into(), self.new_uri.clone());
        d.body.insert("OLD_PYLE".into(), self.old_pyle.clone());
        d.body.insert("NEW_PYLE".into(), self.new_pyle.clone());
        d.body
            .insert("OLD_OWNER_PUBKEY".into(), self.old_owner_pubkey.clone());
        d.body
            .insert("NEW_OWNER_PUBKEY".into(), self.new_owner_pubkey.clone());
        d.body
            .insert("OLD_PYLE_PUBKEY".into(), self.old_pyle_pubkey.clone());
        d.body
            .insert("NEW_PYLE_PUBKEY".into(), self.new_pyle_pubkey.clone());
        d.body
            .insert("OLD_PYLE_TLS_PIN".into(), self.old_pyle_tls_pin.clone());
        d.body
            .insert("NEW_PYLE_TLS_PIN".into(), self.new_pyle_tls_pin.clone());
        d.body
            .insert("TARGET_KIND".into(), self.target_kind.clone());
        d.body
            .insert("SCOPE_COUNT".into(), self.scopes.len().to_string());
        for (i, scope) in self.scopes.iter().enumerate() {
            d.body.insert(format!("SCOPE{i:04}"), scope.clone());
        }
        d.body
            .insert("TARGET_COUNT".into(), self.targets.len().to_string());
        for (i, t) in self.targets.iter().enumerate() {
            d.body.insert(format!("TARGET{i:04}"), t.source.clone());
            d.body.insert(format!("DEST{i:04}"), t.dest.clone());
            d.body.insert(format!("HASH{i:04}"), t.hash.clone());
            d.body.insert(format!("SIZE{i:04}"), t.size.to_string());
        }
        d
    }

    pub fn from_doc(d: &Doc) -> Option<Self> {
        if d.doc_type != DocType::Metabibasis
            || d.body.get("KIND").map(String::as_str) != Some(TRANSFER_KIND_REQUEST)
        {
            return None;
        }
        let field = |k: &str| d.body.get(k).cloned().unwrap_or_default();
        let scope_count: usize = field("SCOPE_COUNT").parse().unwrap_or(0);
        let scopes = (0..scope_count)
            .map(|i| field(&format!("SCOPE{i:04}")))
            .collect();
        let count: usize = field("TARGET_COUNT").parse().ok()?;
        let mut targets = Vec::with_capacity(count);
        for i in 0..count {
            targets.push(TransferTarget {
                source: field(&format!("TARGET{i:04}")),
                dest: field(&format!("DEST{i:04}")),
                hash: field(&format!("HASH{i:04}")),
                size: field(&format!("SIZE{i:04}")).parse().ok()?,
            });
        }
        Some(Self {
            request_id: field("REQUEST_ID"),
            old_owner: field("OLD_OWNER"),
            new_owner: field("NEW_OWNER"),
            old_nickname: field("OLD_NICKNAME"),
            new_nickname: field("NEW_NICKNAME"),
            old_uri: field("OLD_URI"),
            new_uri: field("NEW_URI"),
            old_pyle: field("OLD_PYLE"),
            new_pyle: field("NEW_PYLE"),
            old_owner_pubkey: field("OLD_OWNER_PUBKEY"),
            new_owner_pubkey: field("NEW_OWNER_PUBKEY"),
            old_pyle_pubkey: field("OLD_PYLE_PUBKEY"),
            new_pyle_pubkey: field("NEW_PYLE_PUBKEY"),
            old_pyle_tls_pin: field("OLD_PYLE_TLS_PIN"),
            new_pyle_tls_pin: field("NEW_PYLE_TLS_PIN"),
            target_kind: field("TARGET_KIND"),
            scopes,
            targets,
            created_at: d.created_at,
        })
    }
}

/// Canonical acceptance (`metabibasis`, kind `accept`). It embeds the exact
/// request bytes in base64, so the source pyle can verify the acceptance
/// without trusting a mutable side table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAcceptDoc {
    pub request_id: String,
    pub request_hash: String,
    pub request_doc: String,
    pub old_owner: String,
    pub new_owner: String,
    pub old_nickname: String,
    pub new_nickname: String,
    pub old_uri: String,
    pub new_uri: String,
    pub old_pyle: String,
    pub new_pyle: String,
    pub target_kind: String,
    pub targets: Vec<TransferTarget>,
    pub created_at: u64,
}

impl TransferAcceptDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Metabibasis, 1, None, self.created_at);
        d.body.insert("KIND".into(), TRANSFER_KIND_ACCEPT.into());
        d.body.insert("REQUEST_ID".into(), self.request_id.clone());
        d.body
            .insert("REQUEST_HASH".into(), self.request_hash.clone());
        d.body.insert(
            "REQUEST_DOC_B64".into(),
            base64::engine::general_purpose::STANDARD.encode(self.request_doc.as_bytes()),
        );
        d.body.insert("OLD_OWNER".into(), self.old_owner.clone());
        d.body.insert("NEW_OWNER".into(), self.new_owner.clone());
        d.body
            .insert("OLD_NICKNAME".into(), self.old_nickname.clone());
        d.body
            .insert("NEW_NICKNAME".into(), self.new_nickname.clone());
        d.body.insert("OLD_URI".into(), self.old_uri.clone());
        d.body.insert("NEW_URI".into(), self.new_uri.clone());
        d.body.insert("OLD_PYLE".into(), self.old_pyle.clone());
        d.body.insert("NEW_PYLE".into(), self.new_pyle.clone());
        d.body
            .insert("TARGET_KIND".into(), self.target_kind.clone());
        d.body
            .insert("TARGET_COUNT".into(), self.targets.len().to_string());
        for (i, t) in self.targets.iter().enumerate() {
            d.body.insert(format!("TARGET{i:04}"), t.source.clone());
            d.body.insert(format!("DEST{i:04}"), t.dest.clone());
            d.body.insert(format!("HASH{i:04}"), t.hash.clone());
            d.body.insert(format!("SIZE{i:04}"), t.size.to_string());
        }
        d
    }

    pub fn from_doc(d: &Doc) -> Option<Self> {
        if d.doc_type != DocType::Metabibasis
            || d.body.get("KIND").map(String::as_str) != Some(TRANSFER_KIND_ACCEPT)
        {
            return None;
        }
        let field = |k: &str| d.body.get(k).cloned().unwrap_or_default();
        let request_doc = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(field("REQUEST_DOC_B64"))
                .ok()?,
        )
        .ok()?;
        let count: usize = field("TARGET_COUNT").parse().ok()?;
        let mut targets = Vec::with_capacity(count);
        for i in 0..count {
            targets.push(TransferTarget {
                source: field(&format!("TARGET{i:04}")),
                dest: field(&format!("DEST{i:04}")),
                hash: field(&format!("HASH{i:04}")),
                size: field(&format!("SIZE{i:04}")).parse().ok()?,
            });
        }
        Some(Self {
            request_id: field("REQUEST_ID"),
            request_hash: field("REQUEST_HASH"),
            request_doc,
            old_owner: field("OLD_OWNER"),
            new_owner: field("NEW_OWNER"),
            old_nickname: field("OLD_NICKNAME"),
            new_nickname: field("NEW_NICKNAME"),
            old_uri: field("OLD_URI"),
            new_uri: field("NEW_URI"),
            old_pyle: field("OLD_PYLE"),
            new_pyle: field("NEW_PYLE"),
            target_kind: field("TARGET_KIND"),
            targets,
            created_at: d.created_at,
        })
    }
}

/// `Prytaneion` entry: replication + deletion ledger for a single content hash
/// (especificacao-hdap.md §10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrytaneionDoc {
    pub content_hash: String,
    pub origin_server: String,
    pub origin_user: String,
    pub replicas: Vec<String>,
    pub deletions: Vec<String>,
    pub created_at: u64,
}

impl PrytaneionDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Prytaneion, 1, None, self.created_at);
        d.body
            .insert("CONTENT_HASH".into(), self.content_hash.clone());
        d.body
            .insert("ORIGIN_SERVER".into(), self.origin_server.clone());
        d.body
            .insert("ORIGIN_USER".into(), self.origin_user.clone());
        for (i, r) in self.replicas.iter().enumerate() {
            d.body.insert(format!("REPLICA{i:04}"), r.clone());
        }
        for (i, del) in self.deletions.iter().enumerate() {
            d.body.insert(format!("DELETION{i:04}"), del.clone());
        }
        d
    }
}

/// A TCD update proposal (especificacao-hdap.md §12). Proposer signs it; peers
/// validate the evidence and apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhemeCandidateDoc {
    pub target_id: String,
    pub score_delta: i64,
    pub reason: String,
    pub evidence: Vec<String>,
    pub created_at: u64,
}

impl PhemeCandidateDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::PhemeCandidate, 1, None, self.created_at);
        d.body.insert("TARGET_ID".into(), self.target_id.clone());
        d.body
            .insert("SCORE_DELTA".into(), self.score_delta.to_string());
        d.body.insert("REASON".into(), self.reason.clone());
        for (i, e) in self.evidence.iter().enumerate() {
            d.body.insert(format!("EVIDENCE{i:04}"), e.clone());
        }
        d
    }
}

/// Sync/discovery document (`sync_{username}.hdap`, especificacao-hdap.md §X).
/// Users recommend known servers to the system user's sync directory.
/// Only creation and reading are allowed; deletion is forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDoc {
    /// Username of the recommender.
    pub recommender: String,
    /// List of recommended server endpoints (host:port).
    pub servers: Vec<String>,
    /// Optional description/notes about the recommendation.
    pub description: Option<String>,
    pub created_at: u64,
}

impl SyncDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Sync, 1, None, self.created_at);
        d.body
            .insert("RECOMMENDER".into(), self.recommender.clone());
        for (i, s) in self.servers.iter().enumerate() {
            d.body.insert(format!("SERVER{i:04}"), s.clone());
        }
        if let Some(desc) = &self.description {
            d.body.insert("DESCRIPTION".into(), desc.clone());
        }
        d
    }
}

/// Delegated capability (`exousia.hdap`, especificacao-hdap.md §18).
/// A chain of delegated authorities: the namespace owner signs the root
/// capability; each intermediate delegate signs the re-delegation that follows,
/// forming a chain the node can verify end-to-end without being an authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExousiaDoc {
    /// Namespace owner (root authority).
    pub owner: String,
    /// Owner sign pubkey (hex, 32 bytes). Must match the owner's `prosopeion`.
    pub owner_pubkey: String,
    /// Target user receiving the capability.
    pub delegate: String,
    /// Delegate sign pubkey (hex, 32 bytes), proving key control.
    pub delegate_pubkey: String,
    /// Intermediate delegators between owner and delegate, outermost first.
    /// Each entry is `(user_id, sign_pubkey_hex)`; length == `depth`.
    pub chain: Vec<(String, String)>,
    /// Capability scope (e.g., "read", "write", "list" on a path).
    pub scope: String,
    /// Resource path relative to owner's space.
    pub path: String,
    /// Expiry timestamp (unix seconds), 0 = no expiry.
    pub expires_at: u64,
    /// Nonce for replay protection on this capability instance.
    pub nonce: String,
    /// Delegation depth (0 = direct from owner, 1 = delegated once, etc.).
    pub depth: usize,
    /// Parent capability hash (required when `depth > 0`).
    pub parent_hash: Option<String>,
    pub created_at: u64,
}

impl ExousiaDoc {
    /// Canonical `.hdap` document form.
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Exousia, 1, None, self.created_at);
        d.body.insert("OWNER".into(), self.owner.clone());
        d.body
            .insert("OWNER_PUBKEY".into(), self.owner_pubkey.clone());
        d.body.insert("DELEGATE".into(), self.delegate.clone());
        d.body
            .insert("DELEGATE_PUBKEY".into(), self.delegate_pubkey.clone());
        for (i, (who, pk)) in self.chain.iter().enumerate() {
            d.body.insert(format!("CHAIN{i:04}"), who.clone());
            d.body.insert(format!("CHAIN{i:04}_PUBKEY"), pk.clone());
        }
        d.body.insert("SCOPE".into(), self.scope.clone());
        d.body.insert("PATH".into(), self.path.clone());
        d.body
            .insert("EXPIRES_AT".into(), self.expires_at.to_string());
        d.body.insert("NONCE".into(), self.nonce.clone());
        d.body.insert("DEPTH".into(), self.depth.to_string());
        if let Some(h) = &self.parent_hash {
            d.body.insert("PARENT_HASH".into(), h.clone());
        }
        d
    }

    /// Parse the canonical BODY back into a capability. Returns `None` when
    /// a required field is missing or malformed.
    pub fn from_doc(d: &Doc) -> Option<ExousiaDoc> {
        if d.doc_type != DocType::Exousia {
            return None;
        }
        let owner = d.body.get("OWNER")?.clone();
        let owner_pubkey = d.body.get("OWNER_PUBKEY")?.clone();
        let delegate = d.body.get("DELEGATE")?.clone();
        let delegate_pubkey = d.body.get("DELEGATE_PUBKEY")?.clone();
        let depth = d.body.get("DEPTH")?.parse::<usize>().ok()?;
        let mut chain = Vec::with_capacity(depth);
        for i in 0..depth {
            let who = d.body.get(&format!("CHAIN{i:04}"))?.clone();
            let pk = d.body.get(&format!("CHAIN{i:04}_PUBKEY"))?.clone();
            chain.push((who, pk));
        }
        let scope = d.body.get("SCOPE")?.clone();
        let path = d.body.get("PATH")?.clone();
        let expires_at = d.body.get("EXPIRES_AT")?.parse::<u64>().ok()?;
        let nonce = d.body.get("NONCE")?.clone();
        let parent_hash = d.body.get("PARENT_HASH").cloned();
        Some(ExousiaDoc {
            owner,
            owner_pubkey,
            delegate,
            delegate_pubkey,
            chain,
            scope,
            path,
            expires_at,
            nonce,
            depth,
            parent_hash,
            created_at: d.created_at,
        })
    }

    /// Verify the co-signature chain of a capability document.
    ///
    /// The chain is self-contained: one signature per delegation link, in
    /// order from the namespace owner outwards. Link `i` is signed by the
    /// principal that granted the capability at that level:
    ///
    /// * link `0` — `OWNER` grants to `CHAIN0000` (or `DELEGATE` when `depth == 0`)
    /// * link `i > 0` — `CHAIN{i-1}` grants to `CHAIN{i}` (or `DELEGATE` at the last link)
    ///
    /// Each signer must present the pubkey recorded for it in the body, and
    /// `OWNER_PUBKEY` must equal `owner_pubkey` (taken from the owner's
    /// `prosopeion`, so the root of trust is not self-asserted by the doc).
    /// This proves possession of the whole chain but says nothing about
    /// containment — [`ExousiaDoc::is_covered_by`] checks that separately
    /// against the parent capability.
    pub fn verify_chain(doc: &Doc, owner_pubkey: &[u8; 32]) -> bool {
        let Some(cap) = ExousiaDoc::from_doc(doc) else {
            return false;
        };
        // The chain must be self-consistent: one principal per depth level.
        if cap.chain.len() != cap.depth {
            return false;
        }
        if cap.depth > 0 && cap.parent_hash.is_none() {
            return false;
        }
        // No duplicate principals, and the delegate must not also appear as a
        // delegator (that would let a delegate widen its own grant).
        let mut seen: Vec<&str> = vec![cap.owner.as_str()];
        for (who, _) in &cap.chain {
            if seen.contains(&who.as_str()) {
                return false;
            }
            seen.push(who.as_str());
        }
        if seen.contains(&cap.delegate.as_str()) {
            return false;
        }
        // Exactly one signature per link.
        if doc.sigs.len() != cap.depth + 1 {
            return false;
        }
        // Root of trust: the owner's pubkey must be the one on file.
        if hex::decode(&cap.owner_pubkey).ok().as_deref() != Some(owner_pubkey.as_slice()) {
            return false;
        }
        for i in 0..=cap.depth {
            // Grantor at link i, grantee at link i.
            let (grantor, grantor_pk_hex) = if i == 0 {
                (cap.owner.as_str(), cap.owner_pubkey.as_str())
            } else {
                let (who, pk) = &cap.chain[i - 1];
                (who.as_str(), pk.as_str())
            };
            let sig = &doc.sigs[i];
            if sig.signer != grantor {
                return false;
            }
            let Some(pk) = hex_pk32(sig.signer_pubkey.as_deref()) else {
                return false;
            };
            // The presented pubkey must be the recorded one (no key swap).
            if hex_pk32(Some(grantor_pk_hex)) != Some(pk) {
                return false;
            }
            let Ok(input) = doc.signature_input(i) else {
                return false;
            };
            let Some(tag) = sig64(&sig.signature) else {
                return false;
            };
            if crate::crypto::ed25519_verify(&pk, input.as_bytes(), &tag).is_err() {
                return false;
            }
            // The grantee's recorded key must be a usable 32-byte key that
            // differs from the grantor's (no self-delegation at this link).
            let grantee_pk_hex = cap
                .chain
                .get(i)
                .map(|(_, pk)| pk.as_str())
                .unwrap_or(cap.delegate_pubkey.as_str());
            if hex_pk32(Some(grantee_pk_hex)) == Some(pk) {
                return false;
            }
        }
        true
    }

    /// Whether this capability is contained by `parent`: same owner, a scope
    /// the parent's scope covers, and a path inside the parent's path.
    /// A child may never widen scope or escape the parent's subtree.
    pub fn is_covered_by(&self, parent: &ExousiaDoc) -> bool {
        if self.owner != parent.owner || self.depth != parent.depth + 1 {
            return false;
        }
        // Scope containment: "read" ⊆ "readwrite", exact match required
        // otherwise. A child cannot invent a scope the parent lacks.
        let (child_read, child_write) = scope_bits(&self.scope);
        let (parent_read, parent_write) = scope_bits(&parent.scope);
        if child_read && !parent_read {
            return false;
        }
        if child_write && !parent_write {
            return false;
        }
        if !child_read && !child_write {
            return false;
        }
        // Path containment. A capability path is relative and must not escape
        // its own subtree: `..` segments would satisfy a prefix match while
        // addressing a sibling, so they are rejected outright.
        let parent_path = parent.path.trim_end_matches('/');
        let child_path = self.path.trim_end_matches('/');
        if self.path.starts_with('/')
            || self.path.split('/').any(|seg| seg == ".." || seg == ".")
            || parent.path.split('/').any(|seg| seg == ".." || seg == ".")
        {
            return false;
        }
        child_path == parent_path || child_path.starts_with(&format!("{}/", parent_path))
    }

    /// Whether a child capability is allowed to outlive `parent`.
    ///
    /// `expires_at == 0` means "never expires", so a parent that does expire
    /// cannot delegate into a permanent grant — that would silently defeat the
    /// parent's expiry. Kept separate from [`ExousiaDoc::is_covered_by`] because
    /// it is a property of two documents, not of `self` alone.
    pub fn may_outlive(&self, parent: &ExousiaDoc) -> bool {
        if parent.expires_at == 0 {
            return true;
        }
        self.expires_at != 0 && self.expires_at <= parent.expires_at
    }

    /// True when the capability is past its expiry (`expires_at == 0` never
    /// expires).
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }
}

/// Decode a 32-byte hex pubkey.
fn hex_pk32(hex_str: Option<&str>) -> Option<[u8; 32]> {
    hex::decode(hex_str?).ok()?.try_into().ok()
}

/// Decode a base64 Ed25519 signature (64 bytes).
fn sig64(b64: &str) -> Option<ed25519_dalek::Signature> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let arr: [u8; 64] = bytes.try_into().ok()?;
    Some(ed25519_dalek::Signature::from_bytes(&arr))
}

/// Parse a capability scope into (read, write) bits. Unknown scopes grant
/// nothing, so an unrecognised scope can never widen a grant.
fn scope_bits(scope: &str) -> (bool, bool) {
    match scope {
        "read" => (true, false),
        "write" => (false, true),
        "readwrite" => (true, true),
        _ => (false, false),
    }
}

/// Price announcement from a `pyle` (`timi.hdap`, optional `katallaxia`
/// module, especificacao-hdap.md §16). Signed by the announcing node so peers
/// can verify who priced what (AME-27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimiDoc {
    /// Announcing pyle (node id).
    pub pyle: String,
    /// Price in `obolos` per GiB per day.
    pub price_per_gib_day: u64,
    /// Maximum storage duration the node accepts (days).
    pub max_duration_days: u64,
    /// Validity window in seconds (`kairos`).
    pub valid_kairos: u64,
    pub created_at: u64,
}

impl TimiDoc {
    pub fn to_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Timi, 1, None, self.created_at);
        d.body.insert("PYLE".into(), self.pyle.clone());
        d.body.insert(
            "PRICE_PER_GIB_DAY".into(),
            self.price_per_gib_day.to_string(),
        );
        d.body.insert(
            "MAX_DURATION_DAYS".into(),
            self.max_duration_days.to_string(),
        );
        d.body
            .insert("VALID_KAIROS".into(), self.valid_kairos.to_string());
        d
    }
}

/// Parse the canonical rights/scope from a stored `PERM ...` body value.
pub fn parse_perm_line(line: &str) -> Option<(String, Result<Scope, ()>, Right)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 4 || parts[0] != "PERM" {
        return None;
    }
    let owner = parts[1].to_string();
    let scope = match parts[2] {
        "all" => Ok(Scope::All),
        s if s.starts_with("user:") => Ok(Scope::User(s[5..].to_string())),
        s if s.starts_with("path:") => Ok(Scope::Path(s[5..].to_string())),
        _ => Err(()),
    };
    let right = match parts[3] {
        "deny" => Right::Deny,
        "read" => Right::Read,
        "write" => Right::Write,
        "own" => Right::Own,
        _ => return None,
    };
    Some((owner, scope, right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::parse;

    #[test]
    fn permissions_roundtrip() {
        let perms = vec![
            Permission {
                scope: Scope::All,
                right: Right::Read,
            },
            Permission {
                scope: Scope::User("guest_aaaa".into()),
                right: Right::Write,
            },
            Permission {
                scope: Scope::Path("/docs/videos".into()),
                right: Right::Deny,
            },
        ];
        let doc = adeia_doc("jose_x", 1, None, 1_700_000_000, &perms, Some("u-4f8a"));
        let text = doc.render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Adeia);
        assert_eq!(back.body.get("UUID"), Some(&"u-4f8a".to_string()));
        // canonical roundtrip
        assert_eq!(back.render(), text);
        // parse a line back
        let l = back.body.get("PERM0000").unwrap();
        let (owner, scope, right) = parse_perm_line(l).unwrap();
        assert_eq!(owner, "jose_x");
        assert_eq!(scope, Ok(Scope::All));
        assert_eq!(right, Right::Read);
    }

    #[test]
    fn diadosi_white_and_black_lists_roundtrip_and_decide_membership() {
        let white = DiadosiPolicy::parse(" white:pyle-a; pyle-b ; ").unwrap();
        assert_eq!(white.mode, DiadosiMode::White);
        assert_eq!(white.render(), "white:pyle-a;pyle-b;");
        assert!(white.allows("pyle-a"));
        assert!(!white.allows("pyle-c"));
        let black = DiadosiPolicy::parse("black:pyle-a;;pyle-b").unwrap();
        assert_eq!(black.render(), "black:pyle-a;pyle-b;");
        assert!(!black.allows("pyle-b"));
        assert!(black.allows("pyle-c"));

        let policy = DiadosiPolicy {
            mode: DiadosiMode::White,
            pyles: vec!["pyle-a".into()],
        };
        let doc = adeia_doc_with_diadosi(
            "jose_x",
            1,
            None,
            1_700_000_000,
            &[Permission {
                scope: Scope::All,
                right: Right::Read,
            }],
            None,
            Some(&policy),
        );
        let back = parse(&doc.render()).unwrap();
        assert_eq!(DiadosiPolicy::from_doc(&back), Some(policy));
    }

    #[test]
    fn diadosi_proxy_roundtrips_and_verifies_the_owner_signature() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let proxy = DiadosiDoc {
            owner: "jose_0123456789abcdef".into(),
            owner_pubkey: hex::encode(key.verifying_key().to_bytes()),
            home_pyle: "pyle-a".into(),
            fallbacks: vec!["pyle-b".into(), "pyle-c".into()],
            adeia_edition: 2,
            adeia_hash: "aa".repeat(32),
            properties_hash: "bb".repeat(32),
            edition: 1,
            prev_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = proxy.to_doc();
        doc.sigs.push(crate::doc::Signature {
            signer: proxy.owner.clone(),
            signer_pubkey: Some(proxy.owner_pubkey.clone()),
            signature: String::new(),
        });
        let input = doc.signature_input(0).unwrap();
        doc.sigs[0].signature =
            base64::engine::general_purpose::STANDARD.encode(key.sign(input.as_bytes()).to_bytes());
        let back = parse(&doc.render()).unwrap();
        let parsed = DiadosiDoc::from_doc(&back).unwrap();
        assert_eq!(parsed, proxy);
        assert!(parsed.verify_signature(&back));
        let mut tampered = back.clone();
        tampered.body.insert("HOME_PYLE".into(), "pyle-evil".into());
        assert!(!DiadosiDoc::from_doc(&tampered)
            .unwrap()
            .verify_signature(&tampered));
    }

    #[test]
    fn adeia_uuid_is_optional_stable_across_editions() {
        let perms = vec![Permission {
            scope: Scope::All,
            right: Right::Read,
        }];
        // Edition 1 carries a UUID.
        let d1 = adeia_doc("jose_x", 1, None, 1_700_000_000, &perms, Some("u-4f8a"));
        // Edition 2 references edition 1 and keeps the same UUID.
        let h1 = crate::crypto::sha256_hex(d1.render().as_bytes());
        let d2 = adeia_doc(
            "jose_x",
            2,
            Some(h1.clone()),
            1_700_000_100,
            &perms,
            Some("u-4f8a"),
        );
        let back = parse(&d2.render()).unwrap();
        assert_eq!(back.body.get("UUID"), Some(&"u-4f8a".to_string()));
        assert_eq!(back.prev_hash.as_deref(), Some(h1.as_str()));
        // Without a UUID the field is simply absent (canonical form).
        let d3 = adeia_doc("jose_x", 1, None, 1_700_000_000, &perms, None);
        let back = parse(&d3.render()).unwrap();
        assert!(!back.body.contains_key("UUID"));
    }

    #[test]
    fn pow_doc_and_treaty_doc_render_parse() {
        use crate::pow::solve_pow;
        let proof = solve_pow(b"ctx", 4, 0, 100_000).unwrap();
        let pd = MochthosDoc {
            owner: "jose_x".into(),
            issuer: "server-a".into(),
            proof,
            target_bits: 4,
            bandwidth_bytes: 2 * 1024 * 1024,
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_000 + 3600,
            status: "unused".into(),
        };
        let doc = pd.to_doc();
        let text = doc.render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Mochthos);
        assert_eq!(back.body["STATUS"], "unused");

        let td = SyngrapheDoc {
            owner: "jose_x".into(),
            issuer: "server-a".into(),
            pow_object_hash: crate::crypto::sha256_hex(doc.render().as_bytes()),
            used_for: "/docs/a.txt".into(),
            bandwidth_used: 1024,
            bandwidth_remaining: 2 * 1024 * 1024 - 1024,
            created_at: 1_700_000_001,
        };
        let text = td.to_doc().render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Syngraphe);
        assert_eq!(back.body["BANDWIDTH_REMAINING"], "2096128");
    }

    #[test]
    fn from_doc_roundtrips_pow_and_treaty() {
        use crate::pow::solve_pow;
        let proof = solve_pow(b"ctx", 4, 0, 100_000).unwrap();
        let pd = MochthosDoc {
            owner: "jose_x".into(),
            issuer: "server-a".into(),
            proof,
            target_bits: 4,
            bandwidth_bytes: 4096,
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_000 + 3600,
            status: "unused".into(),
        };
        let back = parse(&pd.to_doc().render()).unwrap();
        let parsed = MochthosDoc::from_doc(&back).expect("parses");
        assert_eq!(parsed.owner, pd.owner);
        assert_eq!(parsed.issuer, pd.issuer);
        assert_eq!(parsed.target_bits, pd.target_bits);
        assert_eq!(parsed.bandwidth_bytes, pd.bandwidth_bytes);
        assert_eq!(parsed.proof.nonce, pd.proof.nonce);
        assert_eq!(parsed.expires_at, pd.expires_at);

        let td = SyngrapheDoc {
            owner: "jose_x".into(),
            issuer: "server-a".into(),
            pow_object_hash: "ab".repeat(32),
            used_for: "docs/a.txt".into(),
            bandwidth_used: 1024,
            bandwidth_remaining: 3072,
            created_at: 1_700_000_001,
        };
        let back = parse(&td.to_doc().render()).unwrap();
        let parsed = SyngrapheDoc::from_doc(&back).expect("parses");
        assert_eq!(parsed, td);

        // A treaty missing a field must parse as `None`, never as a zeroed
        // treaty that could be spent.
        let text = td.to_doc().render().replace("# BANDWIDTH_USED: 1024\n", "");
        let back = parse(&text).unwrap();
        assert!(SyngrapheDoc::from_doc(&back).is_none());
    }

    #[test]
    fn transfer_own_matrix_tcd_roundtrip() {
        let t = MetabibasisDoc {
            old_owner: "alice_x".into(),
            new_owner: "bob_y".into(),
            targets: vec!["HDAP!server@alice_x/docs/report.pdf?hash".into()],
            created_at: 1_700_000_001,
        };
        let text = t.to_doc().render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Metabibasis);

        let m = PrytaneionDoc {
            content_hash: "ab".repeat(32),
            origin_server: "server-a".into(),
            origin_user: "alice_x".into(),
            replicas: vec!["server-b:/hdap/alice_x/docs/a.txt".into()],
            deletions: vec![],
            created_at: 1_700_000_001,
        };
        let text = m.to_doc().render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Prytaneion);
        assert_eq!(
            back.body["REPLICA0000"],
            "server-b:/hdap/alice_x/docs/a.txt"
        );

        let c = PhemeCandidateDoc {
            target_id: "server-b".into(),
            score_delta: -5,
            reason: "retencao de conteudo deletado".into(),
            evidence: vec!["prytaneion:abc123".into()],
            created_at: 1_700_000_002,
        };
        let text = c.to_doc().render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::PhemeCandidate);
        assert_eq!(back.body["SCORE_DELTA"], "-5");
    }

    #[test]
    fn timi_doc_roundtrip() {
        let t = TimiDoc {
            pyle: "node-a".into(),
            price_per_gib_day: 42,
            max_duration_days: 30,
            valid_kairos: 86_400,
            created_at: 1_700_000_000,
        };
        let text = t.to_doc().render();
        let back = parse(&text).unwrap();
        assert_eq!(back.doc_type, DocType::Timi);
        assert_eq!(back.body["PYLE"], "node-a");
        assert_eq!(back.body["PRICE_PER_GIB_DAY"], "42");
        assert_eq!(back.body["MAX_DURATION_DAYS"], "30");
        assert_eq!(back.body["VALID_KAIROS"], "86400");
        assert_eq!(back.render(), text);
    }

    // ---- exousia: delegated capability chain -----------------------------

    use crate::crypto::ed25519_keygen;
    use ed25519_dalek::Signer;
    use rand_core::OsRng;

    struct Party {
        id: String,
        key: ed25519_dalek::SigningKey,
    }

    impl Party {
        fn new(id: &str) -> Party {
            Party {
                id: id.to_string(),
                key: ed25519_keygen(&mut OsRng),
            }
        }
        fn pk_hex(&self) -> String {
            hex::encode(self.key.verifying_key().to_bytes())
        }
    }

    /// Co-sign every link in order: link 0 by the owner, link `i > 0` by the
    /// intermediate delegator at `chain[i-1]`.
    fn sign_links(d: &mut Doc, cap: &ExousiaDoc, signers: &[&Party]) {
        for signer in signers.iter().take(cap.depth + 1) {
            d.sigs.push(crate::doc::Signature {
                signer: signer.id.clone(),
                signer_pubkey: Some(signer.pk_hex()),
                signature: String::new(),
            });
            let idx = d.sigs.len() - 1;
            let input = d.signature_input(idx).unwrap();
            d.sigs[idx].signature = base64::engine::general_purpose::STANDARD
                .encode(Signer::sign(&signer.key, input.as_bytes()).to_bytes());
        }
    }

    /// A parent that expires cannot delegate into a permanent grant: doing so
    /// would silently outlive the parent. `expires_at == 0` means "never".
    #[test]
    fn a_child_may_not_outlive_its_parent() {
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let parent = |expires_at| ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let child = |expires_at| ExousiaDoc {
            depth: 1,
            parent_hash: Some("bb".into()),
            expires_at,
            ..parent(0)
        };

        let expiring = parent(1_700_000_500);
        assert!(
            !child(0).may_outlive(&expiring),
            "permanent must not outlive an expiring parent"
        );
        assert!(
            !child(1_700_000_501).may_outlive(&expiring),
            "an expiry one second later still outlives the parent"
        );
        assert!(
            child(1_700_000_500).may_outlive(&expiring),
            "the same instant is allowed: it expires exactly with the parent"
        );
        assert!(
            child(1_700_000_100).may_outlive(&expiring),
            "an earlier expiry is a narrowing"
        );
        assert!(
            child(0).may_outlive(&parent(0)),
            "a parent that never expires imposes no bound"
        );
    }

    #[test]
    fn exousia_depth0_chain_verifies() {
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        sign_links(&mut doc, &cap, &[&owner]);
        assert!(ExousiaDoc::verify_chain(
            &doc,
            &owner.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_rejects_wrong_root_key() {
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let impostor = Party::new("owner_z");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        sign_links(&mut doc, &cap, &[&owner]);
        // Verified against a different identity's key: the chain must not pass.
        assert!(!ExousiaDoc::verify_chain(
            &doc,
            &impostor.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_rejects_tampered_body() {
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        sign_links(&mut doc, &cap, &[&owner]);
        // Escalate the scope after signing: the owner's signature must fail.
        doc.body.insert("SCOPE".into(), "readwrite".into());
        assert!(!ExousiaDoc::verify_chain(
            &doc,
            &owner.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_rejects_missing_link_signature() {
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        doc.sigs.push(crate::doc::Signature {
            signer: owner.id.clone(),
            signer_pubkey: Some(owner.pk_hex()),
            signature: String::new(),
        });
        // Unsigned link: signature_input exists but the tag is empty.
        assert!(!ExousiaDoc::verify_chain(
            &doc,
            &owner.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_depth2_chain_verifies_and_depth1_parent_hash_required() {
        let owner = Party::new("owner_a");
        let mid = Party::new("guest_b");
        let last = Party::new("guest_c");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: last.id.clone(),
            delegate_pubkey: last.pk_hex(),
            chain: vec![(mid.id.clone(), mid.pk_hex())],
            scope: "write".into(),
            path: "docs/private".into(),
            expires_at: 1_800_000_000,
            nonce: "bb".into(),
            depth: 1,
            parent_hash: Some("deadbeef".into()),
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        sign_links(&mut doc, &cap, &[&owner, &mid]);
        assert!(ExousiaDoc::verify_chain(
            &doc,
            &owner.key.verifying_key().to_bytes()
        ));

        // A depth>0 capability without a parent commitment is invalid.
        let mut orphan = cap.clone();
        orphan.parent_hash = None;
        let mut odoc = orphan.to_doc();
        sign_links(&mut odoc, &orphan, &[&owner, &mid]);
        assert!(!ExousiaDoc::verify_chain(
            &odoc,
            &owner.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_rejects_delegate_signing_its_own_chain() {
        // The delegate cannot co-sign the link that grants it the capability:
        // link 0 must come from the owner.
        let owner = Party::new("owner_a");
        let delegate = Party::new("guest_b");
        let cap = ExousiaDoc {
            owner: owner.id.clone(),
            owner_pubkey: owner.pk_hex(),
            delegate: delegate.id.clone(),
            delegate_pubkey: delegate.pk_hex(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "cc".into(),
            depth: 0,
            parent_hash: None,
            created_at: 1_700_000_000,
        };
        let mut doc = cap.to_doc();
        sign_links(&mut doc, &cap, &[&delegate]);
        assert!(!ExousiaDoc::verify_chain(
            &doc,
            &owner.key.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn exousia_scope_and_path_containment() {
        let parent = ExousiaDoc {
            owner: "owner_a".into(),
            owner_pubkey: String::new(),
            delegate: "guest_b".into(),
            delegate_pubkey: String::new(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 0,
        };
        let mut child = parent.clone();
        child.depth = 1;
        child.delegate = "guest_c".into();
        child.scope = "read".into();
        child.path = "docs/inner".into();
        assert!(child.is_covered_by(&parent));
        // Scope escalation is refused.
        child.scope = "readwrite".into();
        assert!(!child.is_covered_by(&parent));
        // Path escape is refused.
        child.scope = "read".into();
        child.path = "other".into();
        assert!(!child.is_covered_by(&parent));
        child.path = "docs/../secrets".into();
        assert!(!child.is_covered_by(&parent));
        // Unknown scope grants nothing and is therefore never contained.
        child.path = "docs/inner".into();
        child.scope = "admin".into();
        assert!(!child.is_covered_by(&parent));
    }

    #[test]
    fn exousia_expiry() {
        let mut cap = ExousiaDoc {
            owner: "owner_a".into(),
            owner_pubkey: String::new(),
            delegate: "guest_b".into(),
            delegate_pubkey: String::new(),
            chain: Vec::new(),
            scope: "read".into(),
            path: "docs".into(),
            expires_at: 0,
            nonce: "aa".into(),
            depth: 0,
            parent_hash: None,
            created_at: 0,
        };
        assert!(!cap.is_expired(u64::MAX)); // 0 = never expires
        cap.expires_at = 1_000;
        assert!(!cap.is_expired(999));
        assert!(cap.is_expired(1_000));
        assert!(cap.is_expired(1_001));
    }
}
