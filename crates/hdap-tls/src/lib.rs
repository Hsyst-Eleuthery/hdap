//! Transport security for HDAP (AME-09): rustls on the wire, self-signed
//! Ed25519 certificate per `pyle`, and client-side pinning (TOFU).
//!
//! HDAP deliberately runs with **self-signed** TLS certificates. There is no
//! public CA in a private federation; trust is anchored by **pinning** a
//! per-node anchor computed from the node's certificate fingerprint (SHA-256
//! of the raw DER). The server exposes its pin on `/health` (and in the
//! federated handshake), and the client refuses any certificate whose pin is
//! not the expected one. A `None` pin performs TOFU on the first connection,
//! then requires subsequent connections to match.
//!
//! rustls 0.23 removed the blocking `TlsAcceptor` helper (it lives in
//! `tokio-rustls`), so the server wraps each accepted socket in a
//! [`StreamOwned`]; rustls drives the handshake lazily on the first I/O.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, StreamOwned};
use sha2::{Digest, Sha256};

/// A [rustls] server connection type owned alongside a TCP socket.
pub type ServerStream = StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

/// SHA-256 (hex, lowercase) of a certificate DER — the trust anchor pin.
pub fn cert_pin(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

/// A freshly generated TLS identity bound to a `pyle`.
pub struct TlsIdentity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    pub fn pin(&self) -> String {
        cert_pin(&self.cert)
    }

    pub fn server_config(&self) -> io::Result<Arc<rustls::ServerConfig>> {
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| io::Error::other(format!("tls server config: {e}")))?;
        Ok(Arc::new(cfg))
    }
}

/// Generate a self-signed Ed25519 certificate for `common_name` + SAN hosts.
pub fn self_signed(common_name: &str, san_hosts: &[&str]) -> io::Result<TlsIdentity> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| io::Error::other(format!("rcgen keygen: {e}")))?;
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names.push(rcgen::SanType::DnsName(
        common_name
            .try_into()
            .map_err(|_| io::Error::other("invalid common name"))?,
    ));
    for h in san_hosts {
        if let Ok(san) = rcgen::Ia5String::try_from(*h) {
            params.subject_alt_names.push(rcgen::SanType::DnsName(san));
        }
    }
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::other(format!("rcgen self-signed: {e}")))?;
    Ok(TlsIdentity {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
    })
}

/// Write `bytes` to a fresh temp file in the same directory, fsync it, then
/// rename over `path`. Rename is atomic on the same filesystem, so readers see
/// either the old complete file or the new complete file, never a truncated
/// one; the explicit mode keeps the private key at 0600 from creation.
#[cfg_attr(not(unix), allow(unused_variables))]
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("hdap-tls");
    let mut last = None;
    for _ in 0..8 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), n));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        match opts.open(&tmp) {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&tmp, path)?;
                    #[cfg(unix)]
                    if let Some(parent) = path.parent() {
                        if let Ok(dir) = std::fs::File::open(parent) {
                            let _ = dir.sync_all();
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&tmp);
                }
                return result;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a TLS temp file")))
}

const BUNDLE_MAGIC: &[u8; 8] = b"HDAPTLS1";

impl TlsIdentity {
    /// Authoritative on-disk bundle: cert length + DER cert + PKCS#8 key in a
    /// single file. Keeping the pair together makes an interrupted write
    /// impossible to observe as a mismatched cert/key (the two-file layout
    /// could leave a new cert next to an old key after a crash).
    fn bundle_path(cert_path: &Path) -> PathBuf {
        cert_path.with_file_name("tls.identity")
    }

    fn bundle_bytes(&self) -> Vec<u8> {
        let cert = self.cert.as_ref();
        let key = self.key.secret_der();
        let mut out = Vec::with_capacity(12 + cert.len() + key.len());
        out.extend_from_slice(BUNDLE_MAGIC);
        out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        out.extend_from_slice(cert);
        out.extend_from_slice(key);
        out
    }

    fn from_bundle(data: &[u8]) -> Option<Self> {
        if data.len() < 12 || &data[..8] != BUNDLE_MAGIC {
            return None;
        }
        let cert_len = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
        let cert_end = 12usize.checked_add(cert_len)?;
        if cert_end >= data.len() {
            return None;
        }
        let cert = data[12..cert_end].to_vec();
        let key = data[cert_end..].to_vec();
        if cert.is_empty() || key.is_empty() {
            return None;
        }
        Some(Self {
            cert: CertificateDer::from(cert),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        })
    }

    /// Persist the certificate (DER) and PKCS#8 private key so the pin stays
    /// stable across restarts. A rotating pin silently breaks every pinned
    /// peer, transfer release, mirror update and discovery handshake; the node
    /// identity is therefore on-disk state, like the signing seed.
    ///
    /// The atomic `tls.identity` bundle is authoritative. `tls.crt`/`tls.key`
    /// are still exported for tooling, but a crash between those two writes
    /// cannot corrupt the identity the server loads next boot.
    pub fn save(&self, cert_path: &Path, key_path: &Path) -> io::Result<()> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_atomic(&Self::bundle_path(cert_path), &self.bundle_bytes(), 0o600)?;
        // Informational exports: the bundle above is what `load` trusts.
        let _ = write_atomic(cert_path, self.cert.as_ref(), 0o644);
        let _ = write_atomic(key_path, self.key.secret_der(), 0o600);
        Ok(())
    }

    /// Load a previously saved identity. Returns `None` when the bundle and
    /// both legacy halves are absent/corrupt, so the caller can generate one.
    pub fn load(cert_path: &Path, key_path: &Path) -> Option<Self> {
        if let Ok(data) = std::fs::read(Self::bundle_path(cert_path)) {
            if let Some(id) = Self::from_bundle(&data) {
                return Some(id);
            }
        }
        let cert = std::fs::read(cert_path).ok()?;
        let key = std::fs::read(key_path).ok()?;
        if cert.is_empty() || key.is_empty() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }
        Some(Self {
            cert: CertificateDer::from(cert),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        })
    }

    /// Load the node's persistent TLS identity, generating and saving it on
    /// first boot. `cert_path`/`key_path` should live inside the node data
    /// directory so backups carry the transport identity too.
    pub fn load_or_create(
        common_name: &str,
        san_hosts: &[&str],
        cert_path: &Path,
        key_path: &Path,
    ) -> io::Result<Self> {
        if let Some(id) = Self::load(cert_path, key_path) {
            // Migrate installations that predate the atomic bundle, and repair
            // a corrupt bundle from the legacy pair. A failure here is not
            // fatal because `load` already succeeded.
            let bundle = Self::bundle_path(cert_path);
            let bundle_ok = std::fs::read(&bundle)
                .ok()
                .and_then(|d| Self::from_bundle(&d))
                .is_some();
            if !bundle_ok {
                let _ = id.save(cert_path, key_path);
            }
            return Ok(id);
        }
        let id = self_signed(common_name, san_hosts)?;
        id.save(cert_path, key_path)?;
        Ok(id)
    }
}

/// Server-side TLS from a bound TCP socket and an identity: performs the
/// handshake lazily (rustls drives it on first I/O) and returns a TLS stream.
pub fn accept(
    tls: &Arc<rustls::ServerConfig>,
    tcp: std::net::TcpStream,
) -> io::Result<ServerStream> {
    let conn = rustls::ServerConnection::new(Arc::clone(tls))
        .map_err(|e| io::Error::other(format!("tls server session: {e}")))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// A client certificate verifier that only accepts a known certificate pin.
/// When the pin is `Some`, it is authoritative. When `None`, the first
/// certificate seen is recorded (TOFU); later connections must match it.
#[derive(Debug, Clone)]
pub struct PinVerifier {
    expected: Arc<std::sync::Mutex<Option<String>>>,
    tofu: bool,
}

impl PinVerifier {
    /// `expected`: the certificate pin that must match (`None` → TOFU).
    pub fn new(expected: Option<String>) -> Self {
        let tofu = expected.is_none();
        PinVerifier {
            expected: Arc::new(std::sync::Mutex::new(expected)),
            tofu,
        }
    }

    /// The last-accepted pin (usable after a TOFU handshake).
    pub fn observed(&self) -> Option<String> {
        self.expected.lock().unwrap().clone()
    }

    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let pin = cert_pin(cert);
        let mut guard = self.expected.lock().unwrap();
        if let Some(exp) = guard.as_ref() {
            if *exp != pin {
                return Err(rustls::Error::General(
                    "HDAP pin mismatch: node changed its TLS cert (AME-09)".into(),
                ));
            }
            return Ok(());
        }
        if self.tofu {
            *guard = Some(pin);
            Ok(())
        } else {
            Err(rustls::Error::General(
                "HDAP: no trusted pin configured".into(),
            ))
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Open a TLS (pinned) client session over an already-connected TCP stream.
/// The client handshake is driven immediately so pin/verification failures
/// surface at this call rather than on the first application read/write.
pub fn connect(
    tcp: std::net::TcpStream,
    host: &str,
    verifier: PinVerifier,
) -> io::Result<ClientStream> {
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| io::Error::other("invalid TLS server name"))?;
    let stream = ClientConnection::new(Arc::new(cfg), name)
        .map_err(|e| io::Error::other(format!("tls client connect: {e}")))?;
    let mut stream = StreamOwned::new(stream, tcp);
    if stream.conn.complete_io(&mut stream.sock).is_err() {
        return Err(io::Error::other("tls handshake failed"));
    }
    Ok(stream)
}

/// A [rustls] client connection type owned alongside a TCP socket.
pub type ClientStream = StreamOwned<ClientConnection, std::net::TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[test]
    fn self_signed_cert_pin_is_stable_and_distinct() {
        let id = self_signed("node-a", &["127.0.0.1"]).unwrap();
        assert_eq!(id.pin(), id.pin());
        let id2 = self_signed("node-a", &["127.0.0.1"]).unwrap();
        assert_ne!(id.pin(), id2.pin(), "each node must mint its own key");
        assert_eq!(id.pin().len(), 64);
    }

    #[test]
    fn handshake_succeeds_with_matching_pin() {
        let id = self_signed("node-a", &["localhost", "127.0.0.1"]).unwrap();
        let cfg = id.server_config().unwrap();
        let pin = id.pin();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let server = thread::spawn(move || {
            use std::io::{Read, Write};
            let (tcp, _) = listener.accept().unwrap();
            let mut tls = accept(&cfg, tcp).unwrap();
            let _ = tls.read(&mut [0u8; 64]);
            let _ = tls.write_all(b"ok");
            s.store(true, Ordering::SeqCst);
        });

        use std::io::{Read, Write};
        let tcp = TcpStream::connect(addr).unwrap();
        let verifier = PinVerifier::new(Some(pin));
        let mut tls = connect(tcp, "localhost", verifier).unwrap();
        tls.write_all(b"ping").unwrap();
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
        assert!(stop.load(Ordering::SeqCst));
    }

    #[test]
    fn bad_pin_is_refused() {
        let good = self_signed("node-a", &["localhost", "127.0.0.1"]).unwrap();
        let cfg = good.server_config().unwrap();
        let attacker = self_signed("node-a", &["localhost", "127.0.0.1"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let _ = accept(&cfg, tcp).unwrap();
        });

        let tcp = TcpStream::connect(addr).unwrap();
        // Client pinned the *legitimate* node, but the server presents the
        // attacker's cert → handshake must fail.
        let verifier = PinVerifier::new(Some(attacker.pin()));
        assert!(connect(tcp, "localhost", verifier).is_err());
        server.join().unwrap();
    }

    #[test]
    fn tofu_pins_first_cert_seen() {
        use std::io::{Read, Write};
        let id = self_signed("node-a", &["localhost", "127.0.0.1"]).unwrap();
        let cfg = id.server_config().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut tls = accept(&cfg, tcp).unwrap();
            let _ = tls.read(&mut [0u8; 4]);
            let _ = tls.write_all(b"ok");
        });

        let tcp = TcpStream::connect(addr).unwrap();
        let verifier = PinVerifier::new(None);
        let mut tls = connect(tcp, "localhost", verifier.clone()).unwrap();
        tls.write_all(b"ping").unwrap();
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(verifier.observed(), Some(id.pin()));
        server.join().unwrap();
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    #[test]
    fn a_saved_identity_loads_with_the_same_pin() {
        let dir = std::env::temp_dir().join(format!("hdap-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cert = dir.join("tls.crt");
        let key = dir.join("tls.key");
        let first = TlsIdentity::load_or_create("node-a", &["localhost"], &cert, &key).unwrap();
        let pin = first.pin();
        let second = TlsIdentity::load_or_create("node-a", &["localhost"], &cert, &key).unwrap();
        assert_eq!(second.pin(), pin, "the pin must survive a restart");
        assert!(second.server_config().is_ok());
        assert_eq!(
            TlsIdentity::load(&cert, &key).unwrap().pin(),
            pin,
            "manual load must see the persisted DER"
        );
        assert!(
            dir.join("tls.identity").is_file(),
            "the atomic bundle is authoritative"
        );
        // The exported halves are informational; losing them must not rotate
        // the identity as long as the bundle is intact.
        std::fs::remove_file(&cert).unwrap();
        std::fs::remove_file(&key).unwrap();
        assert_eq!(TlsIdentity::load(&cert, &key).unwrap().pin(), pin);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
