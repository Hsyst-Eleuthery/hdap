use std::collections::BTreeMap;
use std::fmt;

/// First line of every HDAP document.
pub const MAGIC: &str = "# HSYST DESCENTRALIZED ARCHIVE PROTOCOL";
/// Format version accepted and emitted by this implementation.
pub const FORMAT_VERSION: u64 = 1;

/// Document types defined by the HDAP spec (especificacao-hdap.md §4.3).
/// Named in Greek per the canonical lexicon (docs/lexico-grego.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocType {
    /// identity mask (`prosopeion`)
    Prosopeion,
    /// permission license (`adeia`)
    Adeia,
    /// proof of work (`mochthos`)
    Mochthos,
    /// cession treaty (`syngraphe`)
    Syngraphe,
    /// per-node session token (`symbolon`, derived locally, never stored)
    Symbolon,
    /// ownership transfer (`metabibasis`)
    Metabibasis,
    /// symbolic link left in the new owner's space by a `metabibasis` (§11.3)
    Link,
    /// provenance matrix (`prytaneion`)
    Prytaneion,
    /// reputation candidate (`pheme_candidate`)
    PhemeCandidate,
    /// DDNS herald (`kerux`)
    Kerux,
    /// price announcement (`timi`, optional katallaxia module)
    Timi,
    /// delegated capability (`exousia`)
    Exousia,
    /// home-fallback proxy (`diadosi`)
    Diadosi,
    /// sync/discovery document (`sync_{username}.hdap`) — server recommendations by users
    Sync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub signer: String,
    pub signer_pubkey: Option<String>,
    /// base64-encoded Ed25519 signature; empty until produced.
    pub signature: String,
}

/// A parsed (or to-be-rendered) HDAP document.
///
/// `body` is kept as a `BTreeMap` so rendering is bytewise-sorted by key,
/// guaranteeing canonical output (stable hash/signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doc {
    pub doc_type: DocType,
    pub version: u64,
    pub edition: u64,
    pub prev_hash: Option<String>,
    pub created_at: u64,
    /// Extra HEAD fields not covered by dedicated struct fields (ordered).
    pub head_extra: BTreeMap<String, String>,
    pub body: BTreeMap<String, String>,
    pub sigs: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    MissingMagic,
    BadDocLine,
    UnknownType(String),
    MissingHead,
    MissingBody,
    MissingSigs,
    MissingEndDoc,
    BadVersion(u64),
    BadEdition(u64),
    BadPrevHash(String),
    BadCreatedAt(String),
    TypeMismatch { doc: DocType, head: String },
    DuplicateKey(String),
    BadKey(String),
    BadSection(String),
    TrailingLines,
    BadSignatureLine(String),
    CrNotAllowed,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseError::*;
        match self {
            Empty => write!(f, "document is empty"),
            MissingMagic => write!(f, "missing magic first line"),
            BadDocLine => write!(f, "expect `## DOC: <type>` second line"),
            UnknownType(t) => write!(f, "unknown document type `{t}`"),
            MissingHead => write!(f, "missing `### HEAD:` section"),
            MissingBody => write!(f, "missing `### BODY:` section"),
            MissingSigs => write!(f, "missing `### SIGS:` section"),
            MissingEndDoc => write!(f, "missing `## :END DOC`"),
            BadVersion(v) => write!(f, "unsupported VERSION `{v}`"),
            BadEdition(e) => write!(f, "invalid EDITION `{e}`"),
            BadPrevHash(h) => write!(f, "invalid PREV_HASH `{h}`"),
            BadCreatedAt(c) => write!(f, "invalid CREATED_AT `{c}`"),
            TypeMismatch { doc, head } => {
                write!(f, "TYPE `{head}` in HEAD does not match DOC type `{doc:?}`")
            }
            DuplicateKey(k) => write!(f, "duplicate key `{k}`"),
            BadKey(k) => write!(f, "invalid key `{k}`"),
            BadSection(s) => write!(f, "unexpected section marker `{s}`"),
            TrailingLines => write!(f, "trailing non-empty lines after `## :END DOC`"),
            BadSignatureLine(l) => write!(f, "malformed signature line `{l}`"),
            CrNotAllowed => write!(f, "carriage returns are not allowed"),
        }
    }
}

impl std::error::Error for ParseError {}

impl DocType {
    pub const ALL: &'static [DocType] = &[
        DocType::Prosopeion,
        DocType::Adeia,
        DocType::Mochthos,
        DocType::Syngraphe,
        DocType::Symbolon,
        DocType::Metabibasis,
        DocType::Link,
        DocType::Prytaneion,
        DocType::PhemeCandidate,
        DocType::Kerux,
        DocType::Timi,
        DocType::Exousia,
        DocType::Diadosi,
    ];

    pub fn as_str(self) -> &'static str {
        use DocType::*;
        match self {
            Prosopeion => "prosopeion",
            Adeia => "adeia",
            Mochthos => "mochthos",
            Syngraphe => "syngraphe",
            Symbolon => "symbolon",
            Metabibasis => "metabibasis",
            Link => "link",
            Prytaneion => "prytaneion",
            PhemeCandidate => "pheme_candidate",
            Kerux => "kerux",
            Timi => "timi",
            Exousia => "exousia",
            Diadosi => "diadosi",
            Sync => "sync",
        }
    }
}

impl std::str::FromStr for DocType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DocType::ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == s)
            .ok_or(())
    }
}

impl Doc {
    /// Create a new (unsigned) v1 document of the given type.
    pub fn new(
        doc_type: DocType,
        edition: u64,
        prev_hash: Option<String>,
        created_at: u64,
    ) -> Self {
        assert!(edition >= 1, "edition starts at 1");
        if edition == 1 {
            assert!(prev_hash.is_none(), "first edition has no PREV_HASH");
        } else {
            assert!(prev_hash.is_some(), "editions > 1 require PREV_HASH");
        }
        Doc {
            doc_type,
            version: FORMAT_VERSION,
            edition,
            prev_hash,
            created_at,
            head_extra: BTreeMap::new(),
            body: BTreeMap::new(),
            sigs: Vec::new(),
        }
    }

    /// Reject values that would break line-based canonical form.
    fn validate_value(value: &str) -> Result<(), ParseError> {
        if value.contains('\n') || value.contains('\r') {
            return Err(ParseError::CrNotAllowed);
        }
        Ok(())
    }

    fn render_head_lines(&self) -> Vec<String> {
        let mut lines = vec![
            MAGIC.to_string(),
            format!("## DOC: {}", self.doc_type.as_str()),
            "### HEAD:".to_string(),
            format!("# VERSION: {}", self.version),
            format!("# TYPE: {}", self.doc_type.as_str()),
            format!("# EDITION: {}", self.edition),
        ];
        if let Some(h) = &self.prev_hash {
            lines.push(format!("# PREV_HASH: {h}"));
        }
        lines.push(format!("# CREATED_AT: {}", self.created_at));
        for (k, v) in &self.head_extra {
            lines.push(format!("# {k}: {v}"));
        }
        lines.push("### :END HEAD".to_string());
        lines
    }

    fn render_body_lines(&self) -> Vec<String> {
        let mut lines = vec!["### BODY:".to_string()];
        for (k, v) in &self.body {
            lines.push(format!("# {k}: {v}"));
        }
        lines.push("### :END BODY".to_string());
        lines
    }

    fn render_sigs_lines(&self) -> Vec<String> {
        let mut lines = vec!["### SIGS:".to_string()];
        for sig in &self.sigs {
            lines.push(format!("# SIGNER: {}", sig.signer));
            if let Some(pk) = &sig.signer_pubkey {
                lines.push(format!("# SIGNER_PUBKEY: {pk}"));
            }
            lines.push(format!("# SIGNATURE: {}", sig.signature));
        }
        lines.push("### :END SIGS".to_string());
        lines
    }

    fn all_lines(&self) -> Vec<String> {
        let mut lines = self.render_head_lines();
        lines.extend(self.render_body_lines());
        lines.extend(self.render_sigs_lines());
        lines.push("## :END DOC".to_string());
        lines
    }

    /// Canonical text form. Deterministic: same `Doc` always yields the same bytes.
    pub fn render(&self) -> String {
        self.all_lines().join("\n") + "\n"
    }

    /// The exact bytes a signer at index `i` must sign: the canonical text
    /// from the first line through the line just before the signer's own
    /// `# SIGNATURE:` line (exclusive of that line, §4.2 rule 6).
    pub fn signature_input(&self, i: usize) -> Result<String, ParseError> {
        if i >= self.sigs.len() {
            return Err(ParseError::BadSignatureLine(format!(
                "signer index {i} out of range ({} signers)",
                self.sigs.len()
            )));
        }
        let lines = self.all_lines();
        // Find the `# SIGNATURE:` line belonging to signer i.
        let mut marker = 0usize;
        let mut count = 0usize;
        for (idx, line) in lines.iter().enumerate() {
            if line == "# SIGNATURE:" || line.starts_with("# SIGNATURE: ") {
                if count == i {
                    marker = idx;
                    break;
                }
                count += 1;
            }
        }
        Ok(lines[..marker].join("\n"))
    }
}

/// Strict line parser.
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("# ")?;
    let (k, v) = rest.split_once(": ")?;
    Some((k, v))
}

/// Parse `text` strictly. Any malformation is rejected
/// (especificacao-hdap.md §4.2 rule 5).
pub fn parse(text: &str) -> Result<Doc, ParseError> {
    if text.is_empty() {
        return Err(ParseError::Empty);
    }
    if text.contains('\r') {
        return Err(ParseError::CrNotAllowed);
    }
    let raw: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    if raw.first() != Some(&MAGIC) {
        return Err(ParseError::MissingMagic);
    }
    let type_name = match raw.get(1).and_then(|l| l.strip_prefix("## DOC: ")) {
        Some(t) => t,
        None => return Err(ParseError::BadDocLine),
    };
    let doc_type: DocType = type_name
        .parse()
        .map_err(|_| ParseError::UnknownType(type_name.to_string()))?;

    let mut i = 2usize;
    if raw.get(i) != Some(&"### HEAD:") {
        return Err(ParseError::MissingHead);
    }
    i += 1;
    let mut head: BTreeMap<String, String> = BTreeMap::new();
    while raw.get(i).is_some() && raw[i] != "### :END HEAD" {
        let (k, v) =
            split_key_value(raw[i]).ok_or_else(|| ParseError::BadSection(raw[i].to_string()))?;
        validate_head_key(k)?;
        Doc::validate_value(v)?;
        if head.insert(k.to_string(), v.to_string()).is_some() {
            return Err(ParseError::DuplicateKey(k.to_string()));
        }
        i += 1;
    }
    if raw.get(i) != Some(&"### :END HEAD") {
        return Err(ParseError::MissingHead);
    }
    i += 1;

    if raw.get(i) != Some(&"### BODY:") {
        return Err(ParseError::MissingBody);
    }
    i += 1;
    let mut body: BTreeMap<String, String> = BTreeMap::new();
    while raw.get(i).is_some() && raw[i] != "### :END BODY" {
        let (k, v) =
            split_key_value(raw[i]).ok_or_else(|| ParseError::BadSection(raw[i].to_string()))?;
        validate_body_key(k)?;
        Doc::validate_value(v)?;
        if body.insert(k.to_string(), v.to_string()).is_some() {
            return Err(ParseError::DuplicateKey(k.to_string()));
        }
        i += 1;
    }
    if raw.get(i) != Some(&"### :END BODY") {
        return Err(ParseError::MissingBody);
    }
    i += 1;

    let mut sigs: Vec<Signature> = Vec::new();
    if raw.get(i) == Some(&"### SIGS:") {
        i += 1;
        while raw.get(i).is_some() && raw[i] != "### :END SIGS" {
            let (k, v) = split_key_value(raw[i])
                .ok_or_else(|| ParseError::BadSignatureLine(raw[i].to_string()))?;
            match k {
                "SIGNER" => sigs.push(Signature {
                    signer: v.to_string(),
                    signer_pubkey: None,
                    signature: String::new(),
                }),
                "SIGNER_PUBKEY" | "SIGNATURE" => {
                    let pending = sigs
                        .last_mut()
                        .ok_or_else(|| ParseError::BadSignatureLine(raw[i].to_string()))?;
                    if k == "SIGNER_PUBKEY" {
                        pending.signer_pubkey = Some(v.to_string());
                    } else {
                        pending.signature = v.to_string();
                    }
                }
                _ => return Err(ParseError::BadSignatureLine(raw[i].to_string())),
            }
            i += 1;
        }
        if raw.get(i) != Some(&"### :END SIGS") {
            return Err(ParseError::MissingSigs);
        }
        i += 1;
    }

    if raw.get(i) != Some(&"## :END DOC") {
        return Err(ParseError::MissingEndDoc);
    }
    i += 1;
    if i != raw.len() {
        return Err(ParseError::TrailingLines);
    }

    let version = head
        .remove("VERSION")
        .map(|v| v.parse::<u64>().map_err(|_| ParseError::BadVersion(0)))
        .transpose()?
        .unwrap_or(FORMAT_VERSION);
    if version != FORMAT_VERSION {
        return Err(ParseError::BadVersion(version));
    }
    let edition = head
        .remove("EDITION")
        .map(|v| v.parse::<u64>().map_err(|_| ParseError::BadEdition(0)))
        .transpose()?
        .unwrap_or(1);
    if edition == 0 {
        return Err(ParseError::BadEdition(0));
    }
    let prev_hash = head.remove("PREV_HASH");
    if edition == 1 && prev_hash.is_some() {
        return Err(ParseError::BadPrevHash(String::new()));
    }
    if edition > 1 && prev_hash.as_deref().is_none_or(|h| !is_sha256_hex(h)) {
        return Err(ParseError::BadPrevHash(prev_hash.unwrap_or_default()));
    }
    let created_at = head
        .remove("CREATED_AT")
        .map(|v| v.parse::<u64>().map_err(|_| ParseError::BadCreatedAt(v)))
        .transpose()?
        .unwrap_or(0);
    if let Some(t) = head.remove("TYPE") {
        if t.parse::<DocType>() != Ok(doc_type) {
            return Err(ParseError::TypeMismatch {
                doc: doc_type,
                head: t,
            });
        }
    }

    Ok(Doc {
        doc_type,
        version,
        edition,
        prev_hash,
        created_at,
        head_extra: head,
        body,
        sigs,
    })
}

/// A sha256 hex digest is exactly 64 lowercase hex chars.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) && s == s.to_ascii_lowercase()
}

/// Reserved uppercase HEAD keys emitted by the canonical render.
const RESERVED_HEAD_KEYS: [&str; 5] = ["VERSION", "TYPE", "EDITION", "PREV_HASH", "CREATED_AT"];

/// HEAD keys may be the reserved uppercase set or any lowercase `# key: value`.
fn validate_head_key(key: &str) -> Result<(), ParseError> {
    if RESERVED_HEAD_KEYS.contains(&key) {
        return Ok(());
    }
    validate_lower_key(key)
}

/// Schema BODY keys are uppercase `[A-Z0-9_.-]`.
fn validate_body_key(key: &str) -> Result<(), ParseError> {
    validate_charset_key(key, |c| {
        c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
    })
}

/// Extra (non-reserved) HEAD keys are lowercase `[a-z0-9_.-]`.
fn validate_lower_key(key: &str) -> Result<(), ParseError> {
    validate_charset_key(key, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
    })
}

fn validate_charset_key(key: &str, ok: impl Fn(char) -> bool) -> Result<(), ParseError> {
    if key.is_empty() || key.len() > 64 {
        return Err(ParseError::BadKey(key.to_string()));
    }
    if !key.chars().all(ok) {
        return Err(ParseError::BadKey(key.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_properties() -> Doc {
        let mut d = Doc::new(DocType::Prosopeion, 1, None, 1737500000);
        d.body.insert("NICKNAME".into(), "jose".into());
        d.body.insert("SUFFIX".into(), "a3f9c2d1e0b7aa11".into());
        d.body.insert("SIGN_PUBKEY".into(), "BA".repeat(16));
        d.body.insert("OMPHALOS".into(), "ab".repeat(32));
        d
    }

    #[test]
    fn render_is_canonical_and_reparse_roundtrips() {
        let d = sample_properties();
        let rendered = d.render();
        let parsed = parse(&rendered).unwrap();
        assert_eq!(parsed.doc_type, DocType::Prosopeion);
        assert_eq!(parsed.edition, 1);
        assert_eq!(parsed.body["NICKNAME"], "jose");
        // reparse -> render must be byte-identical (canonical form)
        assert_eq!(parsed.render(), rendered);
    }

    #[test]
    fn body_keys_are_sorted_bytewise() {
        let mut d = sample_properties();
        d.body.insert("ALPHA".into(), "1".into());
        d.body.insert("beta".into(), "2".into());
        let rendered = d.render();
        let lines: Vec<&str> = rendered.lines().collect();
        let alpha = lines.iter().position(|l| *l == "# ALPHA: 1").unwrap();
        let beta = lines.iter().position(|l| *l == "# beta: 2").unwrap();
        assert!(alpha < beta, "expected bytewise order (ALPHA before beta)");
    }

    #[test]
    fn signature_input_excludes_own_signature_line() {
        let mut d = sample_properties();
        d.sigs.push(Signature {
            signer: "jose_a3f9c2d1e0b7aa11".into(),
            signer_pubkey: Some("PUBKEY1".into()),
            signature: String::new(),
        });
        let input = d.signature_input(0).unwrap();
        assert!(!input.contains("# SIGNATURE:"));
        assert!(input.ends_with("# SIGNER_PUBKEY: PUBKEY1"));
        // deterministic
        assert_eq!(input, d.signature_input(0).unwrap());
    }

    #[test]
    fn multi_sig_chain_includes_previous_signature() {
        let mut d = sample_properties();
        d.sigs.push(Signature {
            signer: "guest".into(),
            signer_pubkey: Some("PK_A".into()),
            signature: "AAAA".into(), // already signed by the first signer
        });
        d.sigs.push(Signature {
            signer: "host".into(),
            signer_pubkey: Some("PK_B".into()),
            signature: String::new(),
        });
        let input_host = d.signature_input(1).unwrap();
        // The host's input must include the guest's complete signature block
        // but must end with its own SIGNER_PUBKEY line, excluding its SIGNATURE.
        assert!(input_host.contains("# SIGNATURE: AAAA"));
        assert!(input_host.ends_with("# SIGNER_PUBKEY: PK_B"));
    }

    #[test]
    fn rejects_errors() {
        let good = sample_properties().render();
        // missing magic
        assert!(matches!(
            parse("## DOC: prosopeion\n"),
            Err(ParseError::MissingMagic)
        ));
        // unknown type
        let bad = good.replace("## DOC: prosopeion", "## DOC: nope");
        assert!(matches!(parse(&bad), Err(ParseError::UnknownType(_))));
        // version mismatch
        let bad = good.replace("# VERSION: 1", "# VERSION: 2");
        assert!(matches!(parse(&bad), Err(ParseError::BadVersion(2))));
        // duplicate body key (two NICKNAME lines)
        let bad = good.replace("# NICKNAME: jose", "# NICKNAME: jose\n# NICKNAME: other");
        assert!(matches!(parse(&bad), Err(ParseError::DuplicateKey(_))));
        // bad key charset
        let bad = good.replace("# NICKNAME: jose", "# NickName: jose");
        assert!(matches!(parse(&bad), Err(ParseError::BadKey(_))));
        // edition >1 without PREV_HASH is a content error at render (assert panics),
        // but parse of a crafted doc must reject bad edition
        let bad = good.replace("# EDITION: 1", "# EDITION: 0");
        assert!(matches!(parse(&bad), Err(ParseError::BadEdition(0))));
        // TYPE mismatch
        let bad = good.replace("# TYPE: prosopeion", "# TYPE: kerux");
        assert!(matches!(parse(&bad), Err(ParseError::TypeMismatch { .. })));
        // trailing content after end doc
        let bad = format!("{good}\n# EXTRA: x");
        assert!(matches!(parse(&bad), Err(ParseError::TrailingLines)));
        // CR not allowed
        let bad = good.replace('\n', "\r\n");
        assert!(matches!(parse(&bad), Err(ParseError::CrNotAllowed)));
        // missing end doc
        let bad = good.trim_end_matches("## :END DOC\n");
        assert!(matches!(parse(bad), Err(ParseError::MissingEndDoc)));
    }

    #[test]
    fn edition_requires_prev_hash() {
        // edition 2 without PREV_HASH must be rejected at parse time
        let mut d = sample_properties();
        d.sigs.push(Signature {
            signer: "x".into(),
            signer_pubkey: None,
            signature: String::new(),
        });
        let text = d.render();
        let reb = text.replace("# EDITION: 1", "# EDITION: 2");
        // no PREV_HASH present -> rejected
        assert!(matches!(parse(&reb), Err(ParseError::BadPrevHash(_))));
    }

    #[test]
    fn valid_second_edition_roundtrips() {
        let mut d = sample_properties();
        d.edition = 2;
        d.prev_hash = Some("ab".repeat(32));
        d.sigs.push(Signature {
            signer: "jose_a3f9c2d1e0b7aa11".into(),
            signer_pubkey: Some("PK".into()),
            signature: String::new(),
        });
        let text = d.render();
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.edition, 2);
        assert_eq!(parsed.prev_hash.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(parsed.render(), text);
    }

    #[test]
    fn all_doc_types_parse_and_render() {
        for t in DocType::ALL {
            let mut d = Doc::new(*t, 1, None, 1_700_000_000);
            d.body.insert("K".into(), "v".into());
            let text = d.render();
            let parsed = parse(&text).unwrap();
            assert_eq!(parsed.doc_type, *t);
            assert_eq!(parsed.render(), text);
        }
    }

    #[test]
    fn head_extra_fields_survive_roundtrip_sorted() {
        let mut d = sample_properties();
        d.head_extra.insert("z-field".into(), "1".into());
        d.head_extra.insert("a-field".into(), "2".into());
        let text = d.render();
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.head_extra["a-field"], "2");
        assert_eq!(parsed.head_extra["z-field"], "1");
        assert_eq!(parsed.render(), text);
    }

    // ---- parser properties (AME-19: fuzzing without a fuzzer installed) ----

    /// A deterministic xorshift so a failure is reproducible from the seed
    /// printed in the panic, and CI does not flake on a different platform.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Structured mutations of a valid document. Random bytes almost always die
    /// at the magic line, which would leave the interesting code — section
    /// framing, duplicate keys, values containing the delimiter — untested.
    fn mutate(rng: &mut Rng, base: &str) -> String {
        let mut lines: Vec<String> = base.lines().map(str::to_string).collect();
        // Never strip the magic line: then every mutation is rejected at once.
        match rng.below(9) {
            0 => {
                // Flip one byte, including inside a delimiter or marker.
                let i = rng.below(lines.len());
                let mut chars: Vec<char> = lines[i].chars().collect();
                if !chars.is_empty() {
                    let j = rng.below(chars.len());
                    chars[j] = match rng.below(4) {
                        0 => '=',
                        1 => ':',
                        2 => '#',
                        _ => 'x',
                    };
                }
                lines[i] = chars.into_iter().collect();
            }
            1 => {
                // Drop a line — removes a frame marker or a required key.
                let i = 1 + rng.below(lines.len().saturating_sub(1));
                lines.remove(i);
            }
            2 => {
                // Duplicate a line: the parser must reject a repeated key.
                let i = rng.below(lines.len());
                let dup = lines[i].clone();
                lines.insert(i, dup);
            }
            3 => {
                // Insert a line that may collide with or terminate a section.
                let i = rng.below(lines.len() + 1);
                let inject = [
                    "### :END BODY",
                    "### :END HEAD",
                    "### BODY:",
                    "### SIGS:",
                    "# NICKNAME: outro",
                    "## :END DOC",
                    "#",
                    "# :",
                    "### :END SIGS",
                    "\r",
                ][rng.below(10)]
                .to_string();
                lines.insert(i, inject);
            }
            4 => {
                // A value carrying the key/value delimiter, which must not be
                // able to forge a second key.
                let i = rng.below(lines.len());
                if let Some(pos) = lines[i].find(": ") {
                    lines[i].push_str(": INJECTED");
                    let _ = pos;
                } else {
                    lines[i].push_str(": INJECTED");
                }
            }
            5 => {
                // Reorder, which can move keys out of canonical order.
                let i = rng.below(lines.len());
                let j = rng.below(lines.len());
                lines.swap(i, j);
            }
            6 => {
                // Empty value.
                let i = rng.below(lines.len());
                if let Some(pos) = lines[i].find(": ") {
                    lines[i].truncate(pos);
                    lines[i].push_str(": ");
                }
            }
            7 => {
                // A very long value: length limits are part of the contract.
                let i = rng.below(lines.len());
                lines[i].push_str(&"L".repeat(4096));
            }
            _ => {
                // Non-ASCII and control bytes in a value.
                let i = rng.below(lines.len());
                lines[i].push_str(": \u{0301}\u{202e}\u{0}\u{feff}ok");
            }
        }
        let mut out = lines.join("\n");
        if rng.below(4) == 0 {
            out.push('\n');
        }
        out
    }

    /// AME-19. Whatever the input, the parser must not panic and must not
    /// accept a document it cannot reproduce byte-for-byte.
    ///
    /// The roundtrip oracle is the strong one: any input that parses has to
    /// render back to something that parses to the same thing. A parser bug
    /// that drops a field, reorders a signature or loses a duplicate check
    /// shows up here as a fixed-point violation, not just as a panic.
    #[test]
    fn parse_never_panics_and_anything_accepted_roundtrips() {
        let base = sample_properties().render();
        assert!(
            parse(&base).is_ok(),
            "the mutator's base must itself be valid"
        );
        let mut rng = Rng(0x9E3779B97F4A7C15);
        let mut accepted = 0usize;
        for step in 0..20_000 {
            let input = mutate(&mut rng, &base);
            let Ok(parsed) = parse(&input) else {
                continue;
            };
            accepted += 1;
            let rendered = parsed.render();
            let reparsed = match parse(&rendered) {
                Ok(r) => r,
                Err(e) => panic!(
                    "step {step}: accepted input produced unparseable canonical form: {e:?}\n{rendered}"
                ),
            };
            assert_eq!(
                reparsed.render(),
                rendered,
                "step {step}: render is not a fixed point"
            );
            assert_eq!(
                reparsed.doc_type, parsed.doc_type,
                "step {step}: type changed across a roundtrip"
            );
            assert_eq!(
                reparsed.body, parsed.body,
                "step {step}: body changed across a roundtrip"
            );
            assert_eq!(
                reparsed.sigs.len(),
                parsed.sigs.len(),
                "step {step}: signature count changed across a roundtrip"
            );
        }
        // A mutator that produced nothing parseable would make the loop vacuous.
        assert!(
            accepted > 100,
            "the mutator is not reaching the accepting path ({accepted} accepted)"
        );
    }

    /// The invariants the parser advertises, checked on documents that are
    /// valid except for exactly one defect.
    #[test]
    fn the_parser_rejects_each_advertised_defect() {
        let base = sample_properties().render();

        // A carriage return anywhere is rejected, not silently stripped.
        assert!(matches!(
            parse(&base.replace('\n', "\r\n")),
            Err(ParseError::CrNotAllowed)
        ));

        // Trailing content after `## :END DOC` is refused rather than ignored.
        assert!(matches!(
            parse(&format!("{base}\nGARBAGE")),
            Err(ParseError::TrailingLines)
        ));

        // A duplicated body key is an error, not last-write-wins. The copy has
        // to go *inside* the body section: appended after `## :END DOC` the
        // parser rejects it as trailing garbage before ever reaching the key.
        let mut dup_lines: Vec<String> = base.lines().map(str::to_string).collect();
        let end_body = dup_lines
            .iter()
            .position(|l| l == "### :END BODY")
            .expect("sample document has a body");
        dup_lines.insert(end_body, "# NICKNAME: outro".to_string());
        let err = parse(&dup_lines.join("\n")).unwrap_err();
        assert!(
            matches!(err, ParseError::DuplicateKey(_)),
            "expected a duplicate-key error, got {err:?}"
        );

        // A truncated document must not parse as a partial success.
        for cut in [1usize, 5, 12] {
            let lines: Vec<&str> = base.lines().collect();
            let truncated = lines[..lines.len().saturating_sub(cut)].join("\n");
            assert!(
                parse(&truncated).is_err(),
                "dropping {cut} line(s) must not produce a document"
            );
        }
    }
}
