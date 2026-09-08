#![allow(clippy::missing_errors_doc)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const CONFLICT_HISTORY_LIMIT: usize = 256;

const SYNC_KEY_BYTES: usize = 32;

/// User-owned sync key material. The recovery phrase is portable metadata;
/// encrypted records never contain it or the raw key.
pub struct SyncKeyMaterial {
    key: [u8; SYNC_KEY_BYTES],
    fingerprint: String,
}

impl SyncKeyMaterial {
    pub fn generate() -> Result<(Self, String), SyncCryptoError> {
        let mut key = [0_u8; SYNC_KEY_BYTES];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| SyncCryptoError::RandomnessUnavailable)?;
        let phrase = URL_SAFE_NO_PAD.encode(key);
        Ok((Self::from_key(key), phrase))
    }

    pub fn recover(recovery_phrase: &str) -> Result<Self, SyncCryptoError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(recovery_phrase.trim())
            .map_err(|_| SyncCryptoError::InvalidRecoveryPhrase)?;
        let key: [u8; SYNC_KEY_BYTES] = decoded
            .try_into()
            .map_err(|_| SyncCryptoError::InvalidRecoveryPhrase)?;
        Ok(Self::from_key(key))
    }

    #[must_use]
    pub const fn key(&self) -> [u8; SYNC_KEY_BYTES] {
        self.key
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[must_use]
    pub fn recovery_phrase(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key)
    }

    fn from_key(key: [u8; SYNC_KEY_BYTES]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&key);
        let fingerprint = hasher
            .finalize()
            .to_hex()
            .as_str()
            .chars()
            .take(16)
            .collect();
        Self { key, fingerprint }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncCryptoError {
    RandomnessUnavailable,
    InvalidEnvelope,
    AuthenticationFailed,
    InvalidRecoveryPhrase,
    SecureStorage(String),
    Transport(String),
}

pub struct EncryptedSyncCodec {
    key: [u8; 32],
    random: SystemRandom,
}

impl EncryptedSyncCodec {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            random: SystemRandom::new(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SyncCryptoError> {
        let mut nonce = [0_u8; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| SyncCryptoError::RandomnessUnavailable)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[ENVELOPE_VERSION],
                },
            )
            .map_err(|_| SyncCryptoError::AuthenticationFailed)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn decrypt(&self, envelope: &[u8]) -> Result<Vec<u8>, SyncCryptoError> {
        if envelope.len() <= 1 + NONCE_LEN || envelope[0] != ENVELOPE_VERSION {
            return Err(SyncCryptoError::InvalidEnvelope);
        }
        let nonce = Nonce::from_slice(&envelope[1..=NONCE_LEN]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &envelope[1 + NONCE_LEN..],
                    aad: &[ENVELOPE_VERSION],
                },
            )
            .map_err(|_| SyncCryptoError::AuthenticationFailed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncRecord {
    pub key: String,
    pub revision: u64,
    pub device_id: String,
    pub envelope: Vec<u8>,
}

/// A deterministic merge decision recorded when local and remote encrypted
/// records for the same logical key differ. The plaintext remains inside the
/// codec; callers can present this metadata without exposing credentials or
/// session contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncConflict {
    pub key: String,
    pub local_revision: u64,
    pub local_device_id: String,
    pub remote_revision: u64,
    pub remote_device_id: String,
    pub selected_device_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncConflictChoice {
    Local,
    Remote,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncTransportError {
    Unavailable(String),
}

/// User-owned synchronization boundary. Network, UMC, filesystem, and
/// self-hosted transports can implement this trait without receiving the
/// encryption key or plaintext.
pub trait SyncTransport {
    fn upload(&mut self, record: SyncRecord) -> Result<(), SyncTransportError>;
    fn download(&self) -> Result<Vec<SyncRecord>, SyncTransportError>;
}

#[derive(Clone, Default)]
pub struct MemorySyncTransport {
    records: BTreeMap<String, SyncRecord>,
}

impl SyncTransport for MemorySyncTransport {
    fn upload(&mut self, record: SyncRecord) -> Result<(), SyncTransportError> {
        let replace = self
            .records
            .get(&record.key)
            .is_none_or(|current| record_order(&record) >= record_order(current));
        if replace {
            self.records.insert(record.key.clone(), record);
        }
        Ok(())
    }

    fn download(&self) -> Result<Vec<SyncRecord>, SyncTransportError> {
        Ok(self.records.values().cloned().collect())
    }
}

/// A local user-owned transport for encrypted records. The transport never
/// sees plaintext; it only persists authenticated envelopes. It is suitable
/// for a local sync directory or a user-managed shared filesystem.
pub struct FileSyncTransport {
    path: PathBuf,
}

impl FileSyncTransport {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_records(&self) -> Result<Vec<SyncRecord>, SyncTransportError> {
        if !reject_symlink_if_present(&self.path)? {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&self.path).map_err(|error| io_error(&error))?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| SyncTransportError::Unavailable(format!("invalid sync file: {error}")))
    }

    fn write_records(&self, records: &[SyncRecord]) -> Result<(), SyncTransportError> {
        let parent = self.path.parent().ok_or_else(|| {
            SyncTransportError::Unavailable("sync path has no parent directory".into())
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
        reject_symlink(parent)?;
        reject_symlink_if_present(&self.path)?;
        let filename = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                SyncTransportError::Unavailable("sync path has no valid filename".into())
            })?;
        let temporary = parent.join(format!(".{filename}.{}.tmp", std::process::id()));
        reject_symlink_if_present(&temporary)?;
        let bytes = serde_json::to_vec(records).map_err(|error| {
            SyncTransportError::Unavailable(format!("serialize sync file: {error}"))
        })?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| io_error(&error))?;
        file.write_all(&bytes).map_err(|error| io_error(&error))?;
        file.sync_all().map_err(|error| io_error(&error))?;
        match fs::rename(&temporary, &self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&self.path).map_err(|error| io_error(&error))?;
                fs::rename(&temporary, &self.path).map_err(|error| io_error(&error))
            }
            Err(error) => Err(io_error(&error)),
        }
    }
}

impl SyncTransport for FileSyncTransport {
    fn upload(&mut self, record: SyncRecord) -> Result<(), SyncTransportError> {
        let mut records = self
            .read_records()?
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let replace = records
            .get(&record.key)
            .is_none_or(|current| record_order(&record) >= record_order(current));
        if replace {
            records.insert(record.key.clone(), record);
        }
        self.write_records(&records.into_values().collect::<Vec<_>>())
    }

    fn download(&self) -> Result<Vec<SyncRecord>, SyncTransportError> {
        self.read_records()
    }
}

fn reject_symlink(path: &Path) -> Result<(), SyncTransportError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(&error))?;
    if metadata.file_type().is_symlink() {
        return Err(SyncTransportError::Unavailable(
            "sync path cannot be a symlink".into(),
        ));
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<bool, SyncTransportError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            reject_symlink(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(&error)),
    }
}

fn io_error(error: &std::io::Error) -> SyncTransportError {
    SyncTransportError::Unavailable(error.to_string())
}

/// Encrypts records before handing them to a user-owned transport and merges
/// concurrent device updates deterministically by revision and device ID.
pub struct EncryptedSyncStore<T> {
    codec: EncryptedSyncCodec,
    device_id: String,
    next_revision: u64,
    records: BTreeMap<String, SyncRecord>,
    pending_uploads: BTreeMap<String, SyncRecord>,
    conflicts: Vec<SyncConflict>,
    pending_conflicts: BTreeMap<String, (SyncRecord, SyncRecord)>,
    pending_conflict_metadata: BTreeMap<String, SyncConflict>,
    transport: T,
}

impl<T: SyncTransport> EncryptedSyncStore<T> {
    pub fn new(key: [u8; 32], device_id: impl Into<String>, transport: T) -> Self {
        Self {
            codec: EncryptedSyncCodec::new(key),
            device_id: device_id.into(),
            next_revision: 1,
            records: BTreeMap::new(),
            pending_uploads: BTreeMap::new(),
            conflicts: Vec::new(),
            pending_conflicts: BTreeMap::new(),
            pending_conflict_metadata: BTreeMap::new(),
            transport,
        }
    }

    pub fn publish(
        &mut self,
        key: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<SyncRecord, SyncCryptoError> {
        let record = SyncRecord {
            key: key.into(),
            revision: self.next_revision,
            device_id: self.device_id.clone(),
            envelope: self.codec.encrypt(plaintext)?,
        };
        self.next_revision = self.next_revision.saturating_add(1);
        self.records.insert(record.key.clone(), record.clone());
        if let Err(error) = self.transport.upload(record.clone()) {
            self.pending_uploads
                .insert(record.key.clone(), record.clone());
            return Err(SyncCryptoError::Transport(format!("{error:?}")));
        }
        self.pending_uploads.remove(&record.key);
        Ok(record)
    }

    /// Retry records whose transport upload failed. A failed retry remains in
    /// the queue so callers can safely invoke this after reconnecting.
    pub fn retry_pending(&mut self) -> Result<usize, SyncCryptoError> {
        let pending = self.pending_uploads.values().cloned().collect::<Vec<_>>();
        let mut uploaded = 0;
        for record in pending {
            if let Err(error) = self.transport.upload(record.clone()) {
                return Err(SyncCryptoError::Transport(format!("{error:?}")));
            }
            self.pending_uploads.remove(&record.key);
            uploaded += 1;
        }
        Ok(uploaded)
    }

    #[must_use]
    pub fn pending_upload_count(&self) -> usize {
        self.pending_uploads.len()
    }

    /// Returns and clears metadata for deterministic local/remote merge
    /// decisions. No decrypted record contents are included.
    pub fn take_conflicts(&mut self) -> Vec<SyncConflict> {
        std::mem::take(&mut self.conflicts)
    }

    #[must_use]
    pub fn pending_conflicts(&self) -> Vec<SyncConflict> {
        self.pending_conflict_metadata.values().cloned().collect()
    }

    /// Resolves a conflict by republishing the chosen plaintext as a new
    /// device revision. The chosen value therefore wins on every transport,
    /// including transports that reject lower revisions.
    pub fn resolve_conflict(
        &mut self,
        key: &str,
        choice: SyncConflictChoice,
    ) -> Result<bool, SyncCryptoError> {
        let Some((local, remote)) = self.pending_conflicts.remove(key) else {
            return Ok(false);
        };
        self.pending_conflict_metadata.remove(key);
        let source = match choice {
            SyncConflictChoice::Local => local,
            SyncConflictChoice::Remote => remote,
        };
        let plaintext = self.codec.decrypt(&source.envelope)?;
        self.publish(key.to_owned(), &plaintext)?;
        Ok(true)
    }

    pub fn pull(&mut self) -> Result<Vec<(String, Vec<u8>)>, SyncCryptoError> {
        let incoming = self
            .transport
            .download()
            .map_err(|error| SyncCryptoError::Transport(format!("{error:?}")))?;
        for record in incoming {
            self.next_revision = self.next_revision.max(record.revision.saturating_add(1));
            if let Some(current) = self.records.get(&record.key) {
                if current.envelope != record.envelope {
                    let selected_device_id = if record_order(&record) > record_order(current) {
                        record.device_id.clone()
                    } else {
                        current.device_id.clone()
                    };
                    if self.conflicts.len() >= CONFLICT_HISTORY_LIMIT {
                        self.conflicts.remove(0);
                    }
                    self.conflicts.push(SyncConflict {
                        key: record.key.clone(),
                        local_revision: current.revision,
                        local_device_id: current.device_id.clone(),
                        remote_revision: record.revision,
                        remote_device_id: record.device_id.clone(),
                        selected_device_id,
                    });
                    self.pending_conflicts
                        .insert(record.key.clone(), (current.clone(), record.clone()));
                    if let Some(conflict) = self.conflicts.last().cloned() {
                        self.pending_conflict_metadata
                            .insert(record.key.clone(), conflict);
                    }
                }
            }
            let replace = self
                .records
                .get(&record.key)
                .is_none_or(|current| record_order(&record) > record_order(current));
            if replace {
                self.records.insert(record.key.clone(), record);
            }
        }
        self.records
            .values()
            .map(|record| {
                self.codec
                    .decrypt(&record.envelope)
                    .map(|plaintext| (record.key.clone(), plaintext))
            })
            .collect()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

fn record_order(record: &SyncRecord) -> (u64, &str) {
    (record.revision, record.device_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptedSyncCodec, EncryptedSyncStore, FileSyncTransport, MemorySyncTransport,
        SyncConflictChoice, SyncCryptoError, SyncKeyMaterial, SyncRecord, SyncTransport,
        SyncTransportError,
    };

    #[derive(Clone, Default)]
    struct OfflineTransport {
        available: bool,
        records: Vec<SyncRecord>,
    }

    impl SyncTransport for OfflineTransport {
        fn upload(&mut self, record: SyncRecord) -> Result<(), SyncTransportError> {
            if !self.available {
                return Err(SyncTransportError::Unavailable("offline".into()));
            }
            self.records.push(record);
            Ok(())
        }

        fn download(&self) -> Result<Vec<SyncRecord>, SyncTransportError> {
            Ok(self.records.clone())
        }
    }

    #[test]
    fn encrypted_sync_round_trips_and_uses_unique_nonces() {
        let codec = EncryptedSyncCodec::new([7; 32]);
        let first = codec.encrypt(b"session").unwrap();
        let second = codec.encrypt(b"session").unwrap();
        assert_ne!(&first[1..13], &second[1..13]);
        assert_eq!(codec.decrypt(&first).unwrap(), b"session");
    }

    #[test]
    fn encrypted_sync_rejects_tampering_and_wrong_key() {
        let codec = EncryptedSyncCodec::new([7; 32]);
        let mut envelope = codec.encrypt(b"session").unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        assert_eq!(
            codec.decrypt(&envelope),
            Err(SyncCryptoError::AuthenticationFailed)
        );
        let other = EncryptedSyncCodec::new([8; 32]);
        let envelope = codec.encrypt(b"session").unwrap();
        assert_eq!(
            other.decrypt(&envelope),
            Err(SyncCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn sync_store_encrypts_and_merges_records_through_transport() {
        let mut transport = MemorySyncTransport::default();
        let mut first = EncryptedSyncStore::new([3; 32], "device-a", transport);
        let record = first.publish("session", b"one").unwrap();
        transport = first.transport().clone();
        let mut second = EncryptedSyncStore::new([3; 32], "device-b", transport);
        second.publish("other", b"two").unwrap();
        assert_eq!(record.envelope.first().copied(), Some(1));
        let records = second.pull().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|(key, value)| key == "session" && value == b"one"));
    }

    #[test]
    fn file_sync_transport_round_trips_encrypted_records() {
        let path = std::env::temp_dir().join(format!(
            "nomad-sync-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let mut transport = FileSyncTransport::new(&path);
        let codec = EncryptedSyncCodec::new([9; 32]);
        let record = super::SyncRecord {
            key: "session".into(),
            revision: 1,
            device_id: "device-a".into(),
            envelope: codec.encrypt(b"local-only").unwrap(),
        };
        transport.upload(record).unwrap();
        let records = transport.download().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(codec.decrypt(&records[0].envelope).unwrap(), b"local-only");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sync_store_retains_failed_uploads_for_retry() {
        let mut store = EncryptedSyncStore::new(
            [4; 32],
            "device-a",
            OfflineTransport {
                available: false,
                records: Vec::new(),
            },
        );
        assert!(matches!(
            store.publish("session", b"offline"),
            Err(SyncCryptoError::Transport(_))
        ));
        assert_eq!(store.pending_upload_count(), 1);
    }

    #[test]
    fn sync_store_exposes_and_resolves_conflicts() {
        let mut local =
            EncryptedSyncStore::new([5; 32], "device-a", MemorySyncTransport::default());
        local.publish("state", b"local").unwrap();
        let transport = local.transport().clone();
        let mut second = EncryptedSyncStore::new([5; 32], "device-b", transport);
        second.publish("state", b"remote").unwrap();
        let mut first = EncryptedSyncStore::new([5; 32], "device-a", second.transport().clone());
        first.publish("state", b"local").unwrap();

        first.pull().unwrap();
        assert_eq!(first.pending_conflicts().len(), 1);
        assert_eq!(first.pending_conflicts()[0].key, "state");
        assert_eq!(first.take_conflicts().len(), 1);
        assert_eq!(first.pending_conflicts().len(), 1);

        first
            .resolve_conflict("state", SyncConflictChoice::Local)
            .unwrap();
        assert!(first.pending_conflicts().is_empty());
        let records = first.pull().unwrap();
        assert!(records
            .iter()
            .any(|(key, value)| key == "state" && value == b"local"));
    }

    #[test]
    fn sync_key_setup_and_recovery_are_deterministic_without_exposing_the_key() {
        let (material, phrase) = SyncKeyMaterial::generate().unwrap();
        let recovered = SyncKeyMaterial::recover(&phrase).unwrap();
        assert_eq!(material.key(), recovered.key());
        assert_eq!(material.fingerprint(), recovered.fingerprint());
        assert_eq!(material.fingerprint().len(), 16);
        assert!(matches!(
            SyncKeyMaterial::recover("not-a-valid-key"),
            Err(SyncCryptoError::InvalidRecoveryPhrase)
        ));
    }
}
