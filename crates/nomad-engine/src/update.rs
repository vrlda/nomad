use std::cmp::Ordering;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ED25519_SIGNATURE_BYTES: usize = 64;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const MAX_VERSION_LENGTH: usize = 64;
const MAX_KEY_ID_LENGTH: usize = 128;
const MAX_PLATFORM_LENGTH: usize = 128;
const MAX_PUBLISHED_AT_LENGTH: usize = 64;
const MAX_UPDATE_BINARY_BYTES: usize = 512 * 1024 * 1024;
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Release channel carried by a signed update manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Stable,
    Beta,
    Nightly,
}

impl UpdateChannel {
    /// Returns whether a release channel is eligible for this policy.
    #[must_use]
    pub fn allows(self, candidate: Self) -> bool {
        candidate <= self
    }
}

/// User-controlled release selection policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdatePolicy {
    pub channel: UpdateChannel,
    pub automatic_checks: bool,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            channel: UpdateChannel::Stable,
            automatic_checks: true,
        }
    }
}

/// A signed release catalog returned by an update endpoint or selected by the
/// user as a local feed file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateFeed {
    pub updates: Vec<SignedUpdate>,
}

impl UpdateFeed {
    /// Parses the bounded JSON feed format used by Nomad update providers.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateFeedError::InvalidJson`] for malformed feed data.
    pub fn from_json(raw: &str) -> Result<Self, UpdateFeedError> {
        serde_json::from_str(raw).map_err(|error| UpdateFeedError::InvalidJson(error.to_string()))
    }

    /// Selects the newest release allowed by the policy and target platform.
    /// Signature and artifact verification still happen before staging.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidVersion`] when the installed version is
    /// not a bounded numeric version.
    pub fn select(
        &self,
        policy: UpdatePolicy,
        installed_version: &str,
        expected_platform: &str,
    ) -> Result<Option<&SignedUpdate>, UpdateError> {
        let installed = parse_version(installed_version)?;
        Ok(self
            .updates
            .iter()
            .filter(|update| {
                update.manifest.platform == expected_platform
                    && policy.channel.allows(update.manifest.channel)
            })
            .filter_map(|update| {
                let version = parse_version(&update.manifest.version).ok()?;
                (version > installed).then_some((version, update))
            })
            .max_by(|left, right| left.0.cmp(&right.0))
            .map(|(_, update)| update))
    }

    /// Produces the state a settings surface can show after an update check.
    ///
    /// The returned `Available` state contains only signed-feed metadata. A
    /// caller must still download the artifact and pass it through
    /// [`verify_update`] (or [`UpdateStager::stage_manual_install`]) before it
    /// can be installed.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidVersion`] when the installed version is
    /// not a bounded numeric version.
    pub fn availability(
        &self,
        policy: UpdatePolicy,
        installed_version: &str,
        expected_platform: &str,
    ) -> Result<UpdateAvailability, UpdateError> {
        if !policy.automatic_checks {
            return Ok(UpdateAvailability::Disabled);
        }

        let Some(update) = self.select(policy, installed_version, expected_platform)? else {
            return Ok(UpdateAvailability::UpToDate {
                installed_version: installed_version.to_owned(),
            });
        };

        Ok(UpdateAvailability::Available {
            version: update.manifest.version.clone(),
            channel: update.manifest.channel,
            platform: update.manifest.platform.clone(),
            artifact_sha256: update.manifest.artifact_sha256.clone(),
            artifact_size: update.manifest.artifact_size,
            published_at: update.manifest.published_at.clone(),
            key_id: update.key_id.clone(),
        })
    }
}

/// The user-visible result of checking a signed update feed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateAvailability {
    Disabled,
    UpToDate {
        installed_version: String,
    },
    Available {
        version: String,
        channel: UpdateChannel,
        platform: String,
        artifact_sha256: String,
        artifact_size: u64,
        published_at: String,
        key_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateFeedError {
    InvalidJson(String),
}

/// The metadata covered by an update signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateManifest {
    pub version: String,
    pub channel: UpdateChannel,
    pub platform: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub published_at: String,
}

impl UpdateManifest {
    /// Creates a manifest for a verified artifact hash.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        channel: UpdateChannel,
        platform: impl Into<String>,
        artifact: &[u8],
        published_at: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            channel,
            platform: platform.into(),
            artifact_sha256: sha256_hex(artifact),
            artifact_size: artifact.len() as u64,
            published_at: published_at.into(),
        }
    }
}

/// An update manifest and its detached Ed25519 signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedUpdate {
    pub key_id: String,
    pub manifest: UpdateManifest,
    /// Base64-encoded Ed25519 signature over the canonical update payload JSON.
    pub signature: String,
}

impl SignedUpdate {
    /// Returns the deterministic bytes that release tooling must sign.
    ///
    /// The signing payload is a fixed-order serde struct, so its JSON encoding
    /// is stable as long as the manifest schema is unchanged. The key ID is
    /// included to prevent a valid signature from being relabeled.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        serde_json::to_vec(&SigningPayload {
            key_id: &self.key_id,
            manifest: &self.manifest,
        })
        .map_err(|error| UpdateError::ManifestSerialization(error.to_string()))
    }
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    key_id: &'a str,
    manifest: &'a UpdateManifest,
}

/// A public key trusted to sign Nomad releases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedUpdateKey {
    key_id: String,
    public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl TrustedUpdateKey {
    /// Creates a trusted key entry. The key ID is metadata and is matched
    /// exactly against the signed envelope.
    #[must_use]
    pub fn new(key_id: impl Into<String>, public_key: [u8; ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self {
            key_id: key_id.into(),
            public_key,
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// The successful result of verifying an update envelope and artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdate {
    pub manifest: UpdateManifest,
    pub key_id: String,
}

/// A verified package staged for an external, next-launch installer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedUpdate {
    path: PathBuf,
    manifest: UpdateManifest,
    key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StagedUpdateMetadata {
    package: String,
    key_id: String,
    manifest: UpdateManifest,
}

impl StagedUpdate {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn manifest(&self) -> &UpdateManifest {
        &self.manifest
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Errors produced while staging an already verified update package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateStagingError {
    InvalidManifest,
    InvalidArtifactHash,
    ArtifactSizeMismatch { expected: u64, actual: u64 },
    ArtifactHashMismatch,
    UnsafeDirectory,
    Io(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateInstallError {
    InvalidFeed(UpdateFeedError),
    Verification(UpdateError),
    Staging(UpdateStagingError),
    NoEligibleUpdate,
}

/// A filesystem-backed staging boundary for verified update packages.
///
/// Staging never replaces an installed executable. It writes a fresh package
/// with exclusive creation, flushes it, and atomically renames it into the
/// staging directory. A platform-specific helper can consume the returned
/// package on the next launch.
pub struct UpdateStager {
    root: PathBuf,
}

impl UpdateStager {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Stages the exact bytes covered by a previously verified manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact no longer matches the verified
    /// manifest, the staging directory is unsafe, or the filesystem rejects
    /// the atomic write.
    pub fn stage(
        &self,
        verified: &VerifiedUpdate,
        artifact: &[u8],
    ) -> Result<StagedUpdate, UpdateStagingError> {
        validate_manifest(&verified.manifest).map_err(|_| UpdateStagingError::InvalidManifest)?;
        validate_artifact(&verified.manifest, artifact)?;
        ensure_real_directory(&self.root)?;

        let counter = STAGING_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        let hash_fragment = verified
            .manifest
            .artifact_sha256
            .strip_prefix("sha256:")
            .and_then(|hash| hash.get(..16))
            .ok_or(UpdateStagingError::InvalidArtifactHash)?;
        let filename = format!(
            "nomad-update-{}-{hash_fragment}-{}-{counter}.package",
            verified.manifest.version,
            std::process::id()
        );
        if filename
            .bytes()
            .any(|byte| byte == b'/' || byte == b'\\' || byte.is_ascii_control())
        {
            return Err(UpdateStagingError::UnsafeDirectory);
        }
        let destination = self.root.join(filename);
        let temporary = self.root.join(format!(
            ".{}.{}.tmp",
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("update"),
            std::process::id()
        ));
        reject_symlink_if_present(&temporary)?;

        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }

        let write_result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            file.write_all(artifact)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            drop(file);
            fs::rename(&temporary, &destination)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result?;

        let metadata_path = destination.with_extension("metadata.json");
        let metadata = serde_json::to_vec(&StagedUpdateMetadata {
            package: destination
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(UpdateStagingError::UnsafeDirectory)?
                .to_owned(),
            key_id: verified.key_id.clone(),
            manifest: verified.manifest.clone(),
        })
        .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
        let metadata_temporary = self.root.join(format!(
            ".{}.{}.tmp",
            metadata_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("update-metadata"),
            std::process::id()
        ));
        reject_symlink_if_present(&metadata_temporary)?;
        let metadata_result = (|| {
            let mut file = options_for_staging_file(&metadata_temporary)?;
            file.write_all(&metadata)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            drop(file);
            fs::rename(&metadata_temporary, &metadata_path)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))
        })();
        if metadata_result.is_err() {
            let _ = fs::remove_file(&metadata_temporary);
        }
        metadata_result?;

        Ok(StagedUpdate {
            path: destination,
            manifest: verified.manifest.clone(),
            key_id: verified.key_id.clone(),
        })
    }

    /// Recovers verified packages that were durably staged before a process
    /// restart. Invalid or incomplete metadata is ignored; a later update
    /// check can safely replace it without treating local disk state as a
    /// trusted release.
    ///
    /// # Errors
    ///
    /// Returns an error when the staging directory cannot be inspected or a
    /// recovered artifact cannot be read.
    pub fn recover(&self) -> Result<Vec<StagedUpdate>, UpdateStagingError> {
        ensure_real_directory(&self.root)?;
        let mut recovered = Vec::new();
        for entry in
            fs::read_dir(&self.root).map_err(|error| UpdateStagingError::Io(error.to_string()))?
        {
            let entry = entry.map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            let metadata_path = entry.path();
            let Some(name) = metadata_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.ends_with(".metadata.json") {
                continue;
            }
            let metadata = fs::symlink_metadata(&metadata_path)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            let raw = fs::read(&metadata_path)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            let Ok(metadata) = serde_json::from_slice::<StagedUpdateMetadata>(&raw) else {
                continue;
            };
            if metadata.package.is_empty()
                || metadata.package.contains('/')
                || metadata.package.contains('\\')
                || metadata.package.starts_with('.')
            {
                continue;
            }
            let package_path = self.root.join(&metadata.package);
            let Ok(package_metadata) = fs::symlink_metadata(&package_path) else {
                continue;
            };
            if package_metadata.file_type().is_symlink() || !package_metadata.is_file() {
                continue;
            }
            let artifact = fs::read(&package_path)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
            if validate_manifest(&metadata.manifest).is_err()
                || validate_artifact(&metadata.manifest, &artifact).is_err()
            {
                continue;
            }
            recovered.push(StagedUpdate {
                path: package_path,
                manifest: metadata.manifest,
                key_id: metadata.key_id,
            });
        }
        recovered.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(recovered)
    }

    /// Verifies and stages a user-selected signed update feed and artifact.
    ///
    /// The feed itself is never trusted: the selected envelope is verified
    /// against the configured release keys before any package is staged.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the feed is malformed, no release is
    /// eligible, signature or artifact verification fails, or staging fails.
    pub fn stage_manual_install(
        &self,
        feed_json: &str,
        artifact: &[u8],
        policy: UpdatePolicy,
        trusted_keys: &[TrustedUpdateKey],
        installed_version: &str,
        expected_platform: &str,
    ) -> Result<StagedUpdate, UpdateInstallError> {
        let feed = UpdateFeed::from_json(feed_json).map_err(UpdateInstallError::InvalidFeed)?;
        let update = feed
            .select(policy, installed_version, expected_platform)
            .map_err(UpdateInstallError::Verification)?
            .ok_or(UpdateInstallError::NoEligibleUpdate)?;
        let verified = verify_update(
            update,
            trusted_keys,
            installed_version,
            expected_platform,
            artifact,
        )
        .map_err(UpdateInstallError::Verification)?;
        self.stage(&verified, artifact)
            .map_err(UpdateInstallError::Staging)
    }

    /// Removes one staged package and its metadata after explicit user choice
    /// or after an installer has consumed it. Only files inside this stager's
    /// real root can be removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the package is outside the staging root, is a
    /// symlink, or cannot be removed.
    pub fn discard(&self, staged: &StagedUpdate) -> Result<(), UpdateStagingError> {
        ensure_real_directory(&self.root)?;
        let package = fs::symlink_metadata(&staged.path)
            .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
        if package.file_type().is_symlink() || !package.is_file() {
            return Err(UpdateStagingError::UnsafeDirectory);
        }
        if staged.path.parent() != Some(self.root.as_path()) {
            return Err(UpdateStagingError::UnsafeDirectory);
        }
        let metadata_path = staged.path.with_extension("metadata.json");
        if let Ok(metadata) = fs::symlink_metadata(&metadata_path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(UpdateStagingError::UnsafeDirectory);
            }
            fs::remove_file(&metadata_path)
                .map_err(|error| UpdateStagingError::Io(error.to_string()))?;
        }
        fs::remove_file(&staged.path).map_err(|error| UpdateStagingError::Io(error.to_string()))
    }
}

/// Errors produced while applying or recovering an installed update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateInstallerError {
    InvalidPath,
    InvalidStagedArtifact,
    Io(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct InstallMarker {
    executable: String,
    backup: String,
    staged: String,
}

/// Applies staged packages with a restart-safe two-file transaction.
///
/// The running process remains untouched until the caller is ready to restart.
/// `apply` writes a marker before moving the current executable aside, so a
/// process or machine interruption can be repaired by calling
/// [`Self::recover_interrupted`] on the next launch. The previous executable
/// remains available until an explicit [`Self::rollback`] or a later update.
pub struct UpdateInstaller {
    executable: PathBuf,
    backup: PathBuf,
    marker: PathBuf,
}

impl UpdateInstaller {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        let executable = executable.into();
        Self {
            backup: executable.with_extension("previous"),
            marker: executable.with_extension("update-state.json"),
            executable,
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Applies a verified staged package and leaves the old executable ready
    /// for rollback.
    ///
    /// # Errors
    ///
    /// Returns an error if any participating path is unsafe, the staged bytes
    /// no longer match their manifest, or the filesystem rejects the update.
    pub fn apply(&self, staged: &StagedUpdate) -> Result<(), UpdateInstallerError> {
        self.recover_interrupted()?;
        self.validate_paths(staged)?;

        let artifact = fs::read(&staged.path).map_err(|error| io_error(&error))?;
        validate_manifest(&staged.manifest)
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        validate_artifact(&staged.manifest, &artifact)
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        let binary = materialize_update_binary(&artifact)?;

        ensure_regular_or_missing(&self.backup)?;
        if fs::symlink_metadata(&self.backup).is_ok() {
            fs::remove_file(&self.backup).map_err(|error| io_error(&error))?;
        }

        let permissions = fs::symlink_metadata(&self.executable)
            .map_err(|error| io_error(&error))?
            .permissions();
        let source = write_install_source(&self.executable, &binary, &permissions)?;

        let marker = InstallMarker {
            executable: path_string(&self.executable),
            backup: path_string(&self.backup),
            staged: path_string(&source),
        };
        if let Err(error) = write_install_marker(&self.marker, &marker) {
            let _ = fs::remove_file(&source);
            return Err(error);
        }

        if let Err(error) = fs::rename(&self.executable, &self.backup) {
            let _ = remove_install_marker(&self.marker);
            let _ = fs::remove_file(&source);
            return Err(io_error(&error));
        }

        if let Err(error) = fs::rename(&source, &self.executable) {
            if fs::symlink_metadata(&self.executable).is_err() {
                let _ = fs::rename(&self.backup, &self.executable);
            }
            return Err(io_error(&error));
        }

        remove_install_marker(&self.marker)
    }

    /// Repairs an install interrupted after the old executable was moved.
    ///
    /// Returns `true` when a backup was restored. If the new executable is
    /// already present, the transaction completed and only its marker is
    /// cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if the marker or its participating paths are unsafe,
    /// malformed, or cannot be repaired.
    pub fn recover_interrupted(&self) -> Result<bool, UpdateInstallerError> {
        ensure_installer_parent(&self.executable)?;
        let Some(marker) = read_install_marker(&self.marker)? else {
            return Ok(false);
        };
        if marker.executable != path_string(&self.executable)
            || marker.backup != path_string(&self.backup)
        {
            return Err(UpdateInstallerError::InvalidPath);
        }

        ensure_regular_or_missing(&self.executable)?;
        ensure_regular_or_missing(&self.backup)?;
        ensure_regular_or_missing(Path::new(&marker.staged))?;

        if fs::symlink_metadata(&self.executable).is_err() {
            fs::rename(&self.backup, &self.executable).map_err(|error| io_error(&error))?;
            remove_install_marker(&self.marker)?;
            return Ok(true);
        }

        remove_install_marker(&self.marker)?;
        Ok(false)
    }

    /// Restores the executable saved by the most recent successful update.
    ///
    /// Returns `false` when no rollback image exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the rollback image is unsafe or cannot replace
    /// the current executable.
    pub fn rollback(&self) -> Result<bool, UpdateInstallerError> {
        ensure_installer_parent(&self.executable)?;
        ensure_regular_or_missing(&self.executable)?;
        ensure_regular_or_missing(&self.backup)?;
        if fs::symlink_metadata(&self.backup).is_err() {
            return Ok(false);
        }
        if fs::symlink_metadata(&self.executable).is_ok() {
            fs::remove_file(&self.executable).map_err(|error| io_error(&error))?;
        }
        fs::rename(&self.backup, &self.executable).map_err(|error| io_error(&error))?;
        remove_install_marker(&self.marker)?;
        Ok(true)
    }

    fn validate_paths(&self, staged: &StagedUpdate) -> Result<(), UpdateInstallerError> {
        ensure_installer_parent(&self.executable)?;
        ensure_regular_file(&self.executable)?;
        ensure_regular_file(&staged.path)?;
        let Some(parent) = staged.path.parent() else {
            return Err(UpdateInstallerError::InvalidPath);
        };
        ensure_real_directory_for_installer(parent)
    }
}

fn materialize_update_binary(artifact: &[u8]) -> Result<Vec<u8>, UpdateInstallerError> {
    if artifact.starts_with(b"PK\x03\x04") {
        return extract_zip_binary(artifact);
    }
    if artifact.starts_with(&[0x1f, 0x8b]) {
        return extract_tar_gz_binary(artifact);
    }
    if artifact.len() > MAX_UPDATE_BINARY_BYTES {
        return Err(UpdateInstallerError::InvalidStagedArtifact);
    }
    Ok(artifact.to_vec())
}

fn extract_zip_binary(artifact: &[u8]) -> Result<Vec<u8>, UpdateInstallerError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(artifact))
        .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
    let mut binary = None;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        let path = file
            .enclosed_name()
            .ok_or(UpdateInstallerError::InvalidStagedArtifact)?;
        if file.is_symlink() {
            return Err(UpdateInstallerError::InvalidStagedArtifact);
        }
        if file.is_dir() || !is_update_binary_path(&path) {
            continue;
        }
        let size = file.size();
        if binary.is_some() || size > MAX_UPDATE_BINARY_BYTES as u64 {
            return Err(UpdateInstallerError::InvalidStagedArtifact);
        }
        let size =
            usize::try_from(size).map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        let mut contents = Vec::with_capacity(size);
        file.read_to_end(&mut contents)
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        binary = Some(contents);
    }
    binary.ok_or(UpdateInstallerError::InvalidStagedArtifact)
}

fn extract_tar_gz_binary(artifact: &[u8]) -> Result<Vec<u8>, UpdateInstallerError> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(artifact));
    let mut archive = tar::Archive::new(decoder);
    let mut binary = None;
    for entry in archive
        .entries()
        .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?
    {
        let mut entry = entry.map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        let path = entry
            .path()
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?
            .into_owned();
        if !is_safe_archive_path(&path) {
            return Err(UpdateInstallerError::InvalidStagedArtifact);
        }
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(UpdateInstallerError::InvalidStagedArtifact);
        }
        if !is_update_binary_path(&path) {
            continue;
        }
        let size = entry.size();
        if binary.is_some() || size > MAX_UPDATE_BINARY_BYTES as u64 {
            return Err(UpdateInstallerError::InvalidStagedArtifact);
        }
        let size =
            usize::try_from(size).map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        let mut contents = Vec::with_capacity(size);
        entry
            .read_to_end(&mut contents)
            .map_err(|_| UpdateInstallerError::InvalidStagedArtifact)?;
        binary = Some(contents);
    }
    binary.ok_or(UpdateInstallerError::InvalidStagedArtifact)
}

fn is_update_binary_path(path: &Path) -> bool {
    if !is_safe_archive_path(path) {
        return false;
    }
    let in_bin = path
        .components()
        .any(|component| component == Component::Normal("bin".as_ref()));
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    in_bin && name.starts_with("nomad-browser")
}

fn is_safe_archive_path(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn write_install_source(
    executable: &Path,
    binary: &[u8],
    permissions: &std::fs::Permissions,
) -> Result<PathBuf, UpdateInstallerError> {
    let Some(parent) = executable.parent() else {
        return Err(UpdateInstallerError::InvalidPath);
    };
    ensure_real_directory_for_installer(parent)?;
    let counter = STAGING_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let source = parent.join(format!(
        ".nomad-update-source-{}-{counter}.tmp",
        std::process::id()
    ));
    if fs::symlink_metadata(&source).is_ok() {
        return Err(UpdateInstallerError::Io(
            "update source temporary path already exists".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&source).map_err(|error| io_error(&error))?;
        file.write_all(binary).map_err(|error| io_error(&error))?;
        file.sync_all().map_err(|error| io_error(&error))?;
        drop(file);
        fs::set_permissions(&source, permissions.clone()).map_err(|error| io_error(&error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&source);
    }
    result.map(|()| source)
}

fn io_error(error: &std::io::Error) -> UpdateInstallerError {
    UpdateInstallerError::Io(error.to_string())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn ensure_installer_parent(path: &Path) -> Result<(), UpdateInstallerError> {
    let Some(parent) = path.parent() else {
        return Err(UpdateInstallerError::InvalidPath);
    };
    ensure_real_directory_for_installer(parent)
}

fn ensure_real_directory_for_installer(path: &Path) -> Result<(), UpdateInstallerError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(&error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(UpdateInstallerError::InvalidPath);
    }
    Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<(), UpdateInstallerError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(&error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(UpdateInstallerError::InvalidPath);
    }
    Ok(())
}

fn ensure_regular_or_missing(path: &Path) -> Result<(), UpdateInstallerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(UpdateInstallerError::InvalidPath);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(&error)),
    }
}

fn write_install_marker(path: &Path, marker: &InstallMarker) -> Result<(), UpdateInstallerError> {
    ensure_installer_parent(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(UpdateInstallerError::Io(
            "update transaction marker already exists".into(),
        ));
    }
    let bytes =
        serde_json::to_vec(marker).map_err(|error| UpdateInstallerError::Io(error.to_string()))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| io_error(&error))?;
    file.write_all(&bytes).map_err(|error| io_error(&error))?;
    file.sync_all().map_err(|error| io_error(&error))
}

fn read_install_marker(path: &Path) -> Result<Option<InstallMarker>, UpdateInstallerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(&error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(UpdateInstallerError::InvalidPath);
    }
    let raw = fs::read(path).map_err(|error| io_error(&error))?;
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| UpdateInstallerError::InvalidPath)
}

fn remove_install_marker(path: &Path) -> Result<(), UpdateInstallerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(UpdateInstallerError::InvalidPath)
        }
        Ok(_) => fs::remove_file(path).map_err(|error| io_error(&error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(&error)),
    }
}

fn options_for_staging_file(path: &Path) -> Result<std::fs::File, UpdateStagingError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
        .open(path)
        .map_err(|error| UpdateStagingError::Io(error.to_string()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateError {
    UnknownKey(String),
    InvalidKeyId,
    InvalidManifestField(&'static str),
    InvalidSignatureEncoding,
    InvalidSignature,
    ManifestSerialization(String),
    InvalidVersion(String),
    Downgrade {
        installed: String,
        candidate: String,
    },
    PlatformMismatch {
        expected: String,
        actual: String,
    },
    InvalidArtifactHash,
    ArtifactSizeMismatch {
        expected: u64,
        actual: u64,
    },
    ArtifactHashMismatch,
}

/// Verifies signed releases without performing network or filesystem I/O.
///
/// Callers are responsible for obtaining the envelope and artifact through a
/// user-approved transport. This verifier only accepts a known public key,
/// an exact platform, a strictly newer version, and a byte-for-byte artifact
/// hash match.
///
/// # Errors
///
/// Returns [`UpdateError`] when the envelope, signature, version, platform,
/// size, or artifact hash fails validation.
pub fn verify_update(
    update: &SignedUpdate,
    trusted_keys: &[TrustedUpdateKey],
    installed_version: &str,
    expected_platform: &str,
    artifact: &[u8],
) -> Result<VerifiedUpdate, UpdateError> {
    if update.key_id.trim().is_empty()
        || update.key_id.len() > MAX_KEY_ID_LENGTH
        || update.key_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(UpdateError::InvalidKeyId);
    }
    validate_manifest(&update.manifest)?;
    if update.manifest.platform != expected_platform {
        return Err(UpdateError::PlatformMismatch {
            expected: expected_platform.to_owned(),
            actual: update.manifest.platform.clone(),
        });
    }

    let key = trusted_keys
        .iter()
        .find(|key| key.key_id == update.key_id)
        .ok_or_else(|| UpdateError::UnknownKey(update.key_id.clone()))?;
    let signature_bytes = BASE64
        .decode(&update.signature)
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
    if signature_bytes.len() != ED25519_SIGNATURE_BYTES {
        return Err(UpdateError::InvalidSignatureEncoding);
    }

    let signing_bytes = update.signing_bytes()?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key.public_key)
        .verify(&signing_bytes, &signature_bytes)
        .map_err(|_| UpdateError::InvalidSignature)?;

    let installed = parse_version(installed_version)?;
    let candidate = parse_version(&update.manifest.version)?;
    if candidate.cmp(&installed) != Ordering::Greater {
        return Err(UpdateError::Downgrade {
            installed: installed_version.to_owned(),
            candidate: update.manifest.version.clone(),
        });
    }

    validate_artifact(&update.manifest, artifact).map_err(|error| match error {
        UpdateStagingError::InvalidArtifactHash
        | UpdateStagingError::InvalidManifest
        | UpdateStagingError::UnsafeDirectory
        | UpdateStagingError::Io(_) => UpdateError::InvalidArtifactHash,
        UpdateStagingError::ArtifactSizeMismatch { expected, actual } => {
            UpdateError::ArtifactSizeMismatch { expected, actual }
        }
        UpdateStagingError::ArtifactHashMismatch => UpdateError::ArtifactHashMismatch,
    })?;

    Ok(VerifiedUpdate {
        manifest: update.manifest.clone(),
        key_id: update.key_id.clone(),
    })
}

fn validate_manifest(manifest: &UpdateManifest) -> Result<(), UpdateError> {
    if manifest.version.trim().is_empty() || manifest.version.len() > MAX_VERSION_LENGTH {
        return Err(UpdateError::InvalidVersion(manifest.version.clone()));
    }
    if manifest.platform.trim().is_empty()
        || manifest.platform.len() > MAX_PLATFORM_LENGTH
        || manifest
            .platform
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(UpdateError::InvalidManifestField("platform"));
    }
    if manifest.published_at.trim().is_empty()
        || manifest.published_at.len() > MAX_PUBLISHED_AT_LENGTH
        || manifest
            .published_at
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(UpdateError::InvalidManifestField("published_at"));
    }
    if manifest.artifact_sha256.len() > 80 {
        return Err(UpdateError::InvalidManifestField("artifact_sha256"));
    }
    parse_version(&manifest.version)?;
    Ok(())
}

fn validate_artifact(manifest: &UpdateManifest, artifact: &[u8]) -> Result<(), UpdateStagingError> {
    let expected_hash = parse_sha256(&manifest.artifact_sha256)
        .map_err(|_| UpdateStagingError::InvalidArtifactHash)?;
    if manifest.artifact_size != artifact.len() as u64 {
        return Err(UpdateStagingError::ArtifactSizeMismatch {
            expected: manifest.artifact_size,
            actual: artifact.len() as u64,
        });
    }
    let actual_hash = Sha256::digest(artifact);
    if actual_hash.as_slice() != expected_hash.as_slice() {
        return Err(UpdateStagingError::ArtifactHashMismatch);
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), UpdateStagingError> {
    fs::create_dir_all(path).map_err(|error| UpdateStagingError::Io(error.to_string()))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| UpdateStagingError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(UpdateStagingError::UnsafeDirectory);
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), UpdateStagingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(UpdateStagingError::UnsafeDirectory)
        }
        Ok(_) => Err(UpdateStagingError::Io(
            "update staging temporary path already exists".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UpdateStagingError::Io(error.to_string())),
    }
}

fn parse_version(raw: &str) -> Result<Vec<u64>, UpdateError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_VERSION_LENGTH {
        return Err(UpdateError::InvalidVersion(raw.to_owned()));
    }
    let mut version = raw
        .split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(UpdateError::InvalidVersion(raw.to_owned()));
            }
            part.parse::<u64>()
                .map_err(|_| UpdateError::InvalidVersion(raw.to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    while version.last() == Some(&0) {
        version.pop();
    }
    if version.is_empty() {
        version.push(0);
    }
    Ok(version)
}

fn parse_sha256(raw: &str) -> Result<[u8; 32], UpdateError> {
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(UpdateError::InvalidArtifactHash);
    };
    if hex.len() != 64 {
        return Err(UpdateError::InvalidArtifactHash);
    }
    let mut result = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or(UpdateError::InvalidArtifactHash)?;
        let low = hex_digit(pair[1]).ok_or(UpdateError::InvalidArtifactHash)?;
        result[index] = (high << 4) | low;
    }
    Ok(result)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        path_string, verify_update, write_install_marker, InstallMarker, SignedUpdate,
        TrustedUpdateKey, UpdateChannel, UpdateError, UpdateFeed, UpdateInstallError,
        UpdateInstaller, UpdateManifest, UpdatePolicy, UpdateStager, UpdateStagingError,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::io::Write;

    fn signed_update() -> (SignedUpdate, TrustedUpdateKey, Vec<u8>) {
        let artifact = b"nomad-release-artifact".to_vec();
        let manifest = UpdateManifest::new(
            "1.2.0",
            UpdateChannel::Stable,
            "x86_64-apple-darwin",
            &artifact,
            "2026-08-15T00:00:00Z",
        );
        let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(key_pair.public_key().as_ref());
        let mut update = SignedUpdate {
            key_id: "release-2026".to_owned(),
            manifest,
            signature: String::new(),
        };
        let signature = key_pair.sign(&update.signing_bytes().unwrap());
        update.signature = BASE64.encode(signature.as_ref());
        (
            update,
            TrustedUpdateKey::new("release-2026", public_key),
            artifact,
        )
    }

    #[test]
    fn verifies_newer_signed_update_and_artifact() {
        let (update, key, artifact) = signed_update();
        let verified =
            verify_update(&update, &[key], "1.1.9", "x86_64-apple-darwin", &artifact).unwrap();
        assert_eq!(verified.key_id, "release-2026");
        assert_eq!(verified.manifest.version, "1.2.0");
    }

    #[test]
    fn stages_verified_artifact_without_overwriting_existing_packages() {
        let (update, key, artifact) = signed_update();
        let verified =
            verify_update(&update, &[key], "1.1.9", "x86_64-apple-darwin", &artifact).unwrap();
        let root =
            std::env::temp_dir().join(format!("nomad-update-staging-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let update_stager = UpdateStager::new(&root);
        let staged_update = update_stager.stage(&verified, &artifact).unwrap();
        assert_eq!(std::fs::read(staged_update.path()).unwrap(), artifact);
        assert_eq!(staged_update.manifest(), &update.manifest);
        assert_eq!(staged_update.key_id(), "release-2026");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        assert_eq!(
            update_stager.stage(&verified, b"tampered"),
            Err(UpdateStagingError::ArtifactSizeMismatch {
                expected: 22,
                actual: 8,
            })
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovers_valid_staged_update_metadata_after_restart() {
        let (update, key, artifact) = signed_update();
        let verified =
            verify_update(&update, &[key], "1.1.9", "x86_64-apple-darwin", &artifact).unwrap();
        let root = std::env::temp_dir().join(format!(
            "nomad-update-recovery-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let update_stager = UpdateStager::new(&root);
        let staged_update = update_stager.stage(&verified, &artifact).unwrap();

        let recovered = update_stager.recover().unwrap();
        assert_eq!(recovered, vec![staged_update]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unknown_key_and_tampered_artifact() {
        let (update, key, mut artifact) = signed_update();
        artifact.push(0);
        assert_eq!(
            verify_update(&update, &[], "1.0.0", "x86_64-apple-darwin", &artifact,),
            Err(UpdateError::UnknownKey("release-2026".to_owned()))
        );
        assert_eq!(
            verify_update(&update, &[key], "1.0.0", "x86_64-apple-darwin", &artifact,),
            Err(UpdateError::ArtifactSizeMismatch {
                expected: 22,
                actual: 23,
            })
        );
    }

    #[test]
    fn rejects_downgrades_platform_mismatch_and_bad_signature() {
        let (mut update, key, artifact) = signed_update();
        assert!(matches!(
            verify_update(
                &update,
                std::slice::from_ref(&key),
                "1.2.0",
                "x86_64-apple-darwin",
                &artifact,
            ),
            Err(UpdateError::Downgrade { .. })
        ));
        update.manifest.platform = "x86_64-pc-windows-msvc".to_owned();
        assert!(matches!(
            verify_update(
                &update,
                std::slice::from_ref(&key),
                "1.0.0",
                "x86_64-apple-darwin",
                &artifact,
            ),
            Err(UpdateError::PlatformMismatch { .. })
        ));
        update.manifest.platform = "x86_64-apple-darwin".to_owned();
        update.signature = BASE64.encode([0_u8; 64]);
        assert_eq!(
            verify_update(
                &update,
                std::slice::from_ref(&key),
                "1.0.0",
                "x86_64-apple-darwin",
                &artifact,
            ),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_unbounded_signed_metadata_before_crypto_work() {
        let (mut update, key, artifact) = signed_update();
        update.manifest.published_at = "x".repeat(65);
        assert_eq!(
            verify_update(
                &update,
                std::slice::from_ref(&key),
                "1.0.0",
                "x86_64-apple-darwin",
                &artifact,
            ),
            Err(UpdateError::InvalidManifestField("published_at"))
        );
    }

    #[test]
    fn feed_selection_respects_channel_platform_and_newest_version() {
        let (stable, _, _) = signed_update();
        let mut beta = stable.clone();
        beta.manifest.version = "1.3.0".into();
        beta.manifest.channel = UpdateChannel::Beta;
        let feed = UpdateFeed {
            updates: vec![stable, beta],
        };

        let stable_selection = feed
            .select(UpdatePolicy::default(), "1.0.0", "x86_64-apple-darwin")
            .unwrap()
            .unwrap();
        assert_eq!(stable_selection.manifest.version, "1.2.0");

        let beta_selection = feed
            .select(
                UpdatePolicy {
                    channel: UpdateChannel::Beta,
                    automatic_checks: true,
                },
                "1.0.0",
                "x86_64-apple-darwin",
            )
            .unwrap()
            .unwrap();
        assert_eq!(beta_selection.manifest.version, "1.3.0");
        assert!(feed
            .select(UpdatePolicy::default(), "1.0.0", "x86_64-pc-windows-msvc")
            .unwrap()
            .is_none());
    }

    #[test]
    fn feed_availability_exposes_disabled_current_and_available_states() {
        let (stable, _, _) = signed_update();
        let feed = UpdateFeed {
            updates: vec![stable],
        };
        assert_eq!(
            feed.availability(
                UpdatePolicy {
                    automatic_checks: false,
                    ..UpdatePolicy::default()
                },
                "1.0.0",
                "x86_64-apple-darwin",
            )
            .unwrap(),
            super::UpdateAvailability::Disabled
        );
        assert_eq!(
            feed.availability(UpdatePolicy::default(), "1.2.0", "x86_64-apple-darwin")
                .unwrap(),
            super::UpdateAvailability::UpToDate {
                installed_version: "1.2.0".into()
            }
        );
        assert!(matches!(
            feed.availability(UpdatePolicy::default(), "1.0.0", "x86_64-apple-darwin")
                .unwrap(),
            super::UpdateAvailability::Available {
                version,
                artifact_size: 22,
                ..
            } if version == "1.2.0"
        ));
    }

    #[test]
    fn manual_install_verifies_selected_release_before_staging() {
        let (update, key, artifact) = signed_update();
        let feed_json = serde_json::to_string(&UpdateFeed {
            updates: vec![update.clone()],
        })
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "nomad-update-manual-install-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let update_stager = UpdateStager::new(&root);
        let staged_update = update_stager
            .stage_manual_install(
                &feed_json,
                &artifact,
                UpdatePolicy::default(),
                &[key],
                "1.1.9",
                "x86_64-apple-darwin",
            )
            .unwrap();
        assert_eq!(staged_update.manifest(), &update.manifest);
        update_stager.discard(&staged_update).unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn manual_install_rejects_feed_without_eligible_release() {
        let (update, key, artifact) = signed_update();
        let feed_json = serde_json::to_string(&UpdateFeed {
            updates: vec![update],
        })
        .unwrap();
        let root =
            std::env::temp_dir().join(format!("nomad-update-no-candidate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let result = UpdateStager::new(&root).stage_manual_install(
            &feed_json,
            &artifact,
            UpdatePolicy::default(),
            &[key],
            "9.0.0",
            "x86_64-apple-darwin",
        );
        assert_eq!(result, Err(UpdateInstallError::NoEligibleUpdate));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn installer_applies_verified_package_and_rolls_back() {
        let (update, key, artifact) = signed_update();
        let verified =
            verify_update(&update, &[key], "1.1.9", "x86_64-apple-darwin", &artifact).unwrap();
        let root =
            std::env::temp_dir().join(format!("nomad-update-installer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("nomad-browser");
        std::fs::write(&executable, b"previous-release").unwrap();
        let staged = UpdateStager::new(root.join("staged"))
            .stage(&verified, &artifact)
            .unwrap();
        let installer = UpdateInstaller::new(&executable);

        installer.apply(&staged).unwrap();
        assert_eq!(std::fs::read(&executable).unwrap(), artifact);
        assert!(installer.rollback().unwrap());
        assert_eq!(std::fs::read(&executable).unwrap(), b"previous-release");
        assert!(!installer.recover_interrupted().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn installer_recovers_when_interrupted_after_moving_previous_release() {
        let (update, key, artifact) = signed_update();
        let verified =
            verify_update(&update, &[key], "1.1.9", "x86_64-apple-darwin", &artifact).unwrap();
        let root =
            std::env::temp_dir().join(format!("nomad-update-interrupted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("nomad-browser");
        std::fs::write(&executable, b"previous-release").unwrap();
        let staged = UpdateStager::new(root.join("staged"))
            .stage(&verified, &artifact)
            .unwrap();
        let installer = UpdateInstaller::new(&executable);
        write_install_marker(
            &installer.marker,
            &InstallMarker {
                executable: path_string(&installer.executable),
                backup: path_string(&installer.backup),
                staged: path_string(staged.path()),
            },
        )
        .unwrap();
        std::fs::rename(&installer.executable, &installer.backup).unwrap();

        assert!(installer.recover_interrupted().unwrap());
        assert_eq!(std::fs::read(&executable).unwrap(), b"previous-release");
        assert!(!installer.marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn installer_extracts_only_the_release_binary_from_archives() {
        let mut zip_bytes = std::io::Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut zip_bytes);
            let options = zip::write::SimpleFileOptions::default();
            archive
                .start_file("nomad-browser-macos-1.2.0/bin/nomad-browser", options)
                .unwrap();
            archive.write_all(b"new-release").unwrap();
            archive.finish().unwrap();
        }
        assert_eq!(
            super::materialize_update_binary(zip_bytes.get_ref()).unwrap(),
            b"new-release"
        );

        let mut tar_bytes = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(11);
            header.set_mode(0o755);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    "nomad-browser-linux-1.2.0/bin/nomad-browser",
                    &b"new-release"[..],
                )
                .unwrap();
            let encoder = archive.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        assert_eq!(
            super::materialize_update_binary(&tar_bytes).unwrap(),
            b"new-release"
        );
    }
}
