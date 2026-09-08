use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use url::Url;

use crate::TabId;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DownloadId(u64);

impl DownloadId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DownloadState {
    Queued,
    InProgress,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug)]
pub enum DownloadTransportEvent {
    Response { total_bytes: Option<u64> },
    BodyChunk(Vec<u8>),
    Finished(Result<(), String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadRequest {
    pub tab_id: Option<TabId>,
    pub url: Url,
    pub suggested_filename: String,
    pub total_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadSnapshot {
    pub id: DownloadId,
    pub tab_id: Option<TabId>,
    pub url: Url,
    pub suggested_filename: String,
    pub destination: PathBuf,
    pub bytes_received: u64,
    pub total_bytes: Option<u64>,
    pub state: DownloadState,
    pub error: Option<String>,
    pub checksum: Option<String>,
    pub security_warning: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DownloadError {
    UnsupportedScheme(String),
    InvalidFilename(String),
    MissingDownload(DownloadId),
    InvalidState {
        id: DownloadId,
        state: DownloadState,
    },
    Io(String),
}

pub struct DownloadManager {
    next_id: u64,
    directory: PathBuf,
    downloads: Vec<DownloadSnapshot>,
    files: HashMap<DownloadId, File>,
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new(PathBuf::from("downloads"))
    }
}

impl DownloadManager {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            next_id: 1,
            directory: directory.into(),
            downloads: Vec::new(),
            files: HashMap::new(),
        }
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn set_directory(&mut self, directory: impl Into<PathBuf>) {
        self.directory = directory.into();
    }

    #[must_use]
    pub fn downloads(&self) -> &[DownloadSnapshot] {
        &self.downloads
    }

    #[must_use]
    pub fn get(&self, id: DownloadId) -> Option<&DownloadSnapshot> {
        self.downloads.iter().find(|download| download.id == id)
    }

    /// Queues a validated browser download without touching the filesystem.
    ///
    /// The transport layer owns the eventual file creation and feeds progress
    /// back through this manager. The destination is always derived from the
    /// configured download directory and a single safe filename.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL scheme is not supported or the suggested
    /// filename could escape the configured directory.
    pub fn queue(&mut self, request: DownloadRequest) -> Result<DownloadId, DownloadError> {
        if !matches!(request.url.scheme(), "http" | "https" | "umc") {
            return Err(DownloadError::UnsupportedScheme(
                request.url.scheme().to_owned(),
            ));
        }
        let filename = safe_filename(&request.suggested_filename)?;
        let security_warning = security_warning(&request.url);
        let id = DownloadId::new(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let destination = self.available_destination(&filename);
        self.downloads.push(DownloadSnapshot {
            id,
            tab_id: request.tab_id,
            url: request.url,
            suggested_filename: filename,
            destination,
            bytes_received: 0,
            total_bytes: request.total_bytes,
            state: DownloadState::Queued,
            error: None,
            checksum: None,
            security_warning,
        });
        Ok(id)
    }

    /// Reconstructs the transport request for a retry.
    ///
    /// The existing download id is retained so the browser UI keeps one
    /// stable history entry while the transfer is retried.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing or is not terminal.
    pub fn retry_request(&mut self, id: DownloadId) -> Result<DownloadRequest, DownloadError> {
        let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
        if !matches!(
            download.state,
            DownloadState::Failed | DownloadState::Cancelled
        ) {
            return Err(DownloadError::InvalidState {
                id,
                state: download.state,
            });
        }

        let request = DownloadRequest {
            tab_id: download.tab_id,
            url: download.url.clone(),
            suggested_filename: download.suggested_filename.clone(),
            total_bytes: None,
        };
        let download = self.get_mut(id)?;
        download.bytes_received = 0;
        download.total_bytes = None;
        download.state = DownloadState::Queued;
        download.error = None;
        download.checksum = None;
        Ok(request)
    }

    fn available_destination(&self, filename: &str) -> PathBuf {
        let base = self.directory.join(filename);
        let occupied = |path: &Path| {
            path.exists()
                || self
                    .downloads
                    .iter()
                    .any(|download| download.destination == path)
        };
        if !occupied(&base) {
            return base;
        }

        let path = Path::new(filename);
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(filename);
        let extension = path.extension().and_then(|extension| extension.to_str());
        for index in 1.. {
            let candidate_name = match extension {
                Some(extension) => format!("{stem} ({index}).{extension}"),
                None => format!("{stem} ({index})"),
            };
            let candidate = self.directory.join(candidate_name);
            if !occupied(&candidate) {
                return candidate;
            }
        }
        unreachable!("download destination suffix exhausted")
    }

    /// Marks a queued download as ready for transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the download does not exist or is not queued.
    pub fn begin(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        let download = self.get_mut(id)?;
        ensure_state(download, DownloadState::Queued)?;
        download.state = DownloadState::InProgress;
        Ok(())
    }

    /// Records the response's advertised size.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing or already terminal.
    pub fn set_total_bytes(
        &mut self,
        id: DownloadId,
        total_bytes: Option<u64>,
    ) -> Result<(), DownloadError> {
        let download = self.get_mut(id)?;
        if !matches!(
            download.state,
            DownloadState::Queued | DownloadState::InProgress
        ) {
            return Err(DownloadError::InvalidState {
                id,
                state: download.state,
            });
        }
        download.total_bytes = total_bytes;
        Ok(())
    }

    /// Records bytes received from the transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the download does not exist or is not in progress.
    pub fn receive_bytes(&mut self, id: DownloadId, bytes: u64) -> Result<(), DownloadError> {
        let download = self.get_mut(id)?;
        ensure_state(download, DownloadState::InProgress)?;
        download.bytes_received = download.bytes_received.saturating_add(bytes);
        Ok(())
    }

    /// Writes a response chunk and records its size.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing, inactive, or the
    /// destination cannot be written.
    pub fn receive_chunk(&mut self, id: DownloadId, chunk: &[u8]) -> Result<(), DownloadError> {
        let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
        ensure_state(download, DownloadState::InProgress)?;
        self.ensure_file(id)?
            .write_all(chunk)
            .map_err(|error| io_error(&error))?;
        let download = self.get_mut(id)?;
        download.bytes_received = download.bytes_received.saturating_add(chunk.len() as u64);
        Ok(())
    }

    /// Marks an in-progress download as complete.
    ///
    /// # Errors
    ///
    /// Returns an error when the download does not exist or is not in progress.
    pub fn complete(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        {
            let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
            ensure_state(download, DownloadState::InProgress)?;
        }
        self.ensure_file(id)?
            .flush()
            .map_err(|error| io_error(&error))?;
        self.files.remove(&id);
        let destination = self
            .get(id)
            .ok_or(DownloadError::MissingDownload(id))?
            .destination
            .clone();
        let checksum = sha256_file(&destination)?;
        let download = self.get_mut(id)?;
        download.checksum = Some(checksum);
        download.state = DownloadState::Completed;
        Ok(())
    }

    /// Records a transport failure for a queued or active download.
    ///
    /// # Errors
    ///
    /// Returns an error when the download does not exist or is terminal.
    pub fn fail(&mut self, id: DownloadId, error: impl Into<String>) -> Result<(), DownloadError> {
        {
            let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
            if !matches!(
                download.state,
                DownloadState::Queued | DownloadState::InProgress
            ) {
                return Err(DownloadError::InvalidState {
                    id,
                    state: download.state,
                });
            }
        }
        self.remove_partial_file(id);
        let download = self.get_mut(id)?;
        download.state = DownloadState::Failed;
        download.error = Some(error.into());
        Ok(())
    }

    /// Pauses an active download, keeping its transport state for a later
    /// `resume`.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing or not in progress.
    pub fn pause(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        let download = self.get_mut(id)?;
        ensure_state(download, DownloadState::InProgress)?;
        download.state = DownloadState::Paused;
        Ok(())
    }

    /// Resumes a paused download.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing or not paused.
    pub fn resume(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        let download = self.get_mut(id)?;
        ensure_state(download, DownloadState::Paused)?;
        download.state = DownloadState::InProgress;
        Ok(())
    }

    /// Removes a terminal download from the manager history without touching
    /// its file.
    ///
    /// # Errors
    ///
    /// Returns an error when the download is missing or still active.
    pub fn erase(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        {
            let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
            if !matches!(
                download.state,
                DownloadState::Completed | DownloadState::Failed | DownloadState::Cancelled
            ) {
                return Err(DownloadError::InvalidState {
                    id,
                    state: download.state,
                });
            }
        }
        self.downloads.retain(|download| download.id != id);
        Ok(())
    }

    /// Cancels a queued or active download.
    ///
    /// # Errors
    ///
    /// Returns an error when the download does not exist or is terminal.
    pub fn cancel(&mut self, id: DownloadId) -> Result<(), DownloadError> {
        {
            let download = self.get(id).ok_or(DownloadError::MissingDownload(id))?;
            if !matches!(
                download.state,
                DownloadState::Queued | DownloadState::InProgress
            ) {
                return Err(DownloadError::InvalidState {
                    id,
                    state: download.state,
                });
            }
        }
        self.remove_partial_file(id);
        self.get_mut(id)?.state = DownloadState::Cancelled;
        Ok(())
    }

    fn remove_partial_file(&mut self, id: DownloadId) {
        let had_file = self.files.remove(&id).is_some();
        if !had_file {
            return;
        }
        let Some(destination) = self.get(id).map(|download| download.destination.clone()) else {
            return;
        };
        let _ = fs::remove_file(destination);
    }

    fn ensure_file(&mut self, id: DownloadId) -> Result<&mut File, DownloadError> {
        if !self.files.contains_key(&id) {
            let destination = self
                .get(id)
                .ok_or(DownloadError::MissingDownload(id))?
                .destination
                .clone();
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
            }
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(destination)
                .map_err(|error| io_error(&error))?;
            self.files.insert(id, file);
        }
        Ok(self
            .files
            .get_mut(&id)
            .expect("download file inserted above"))
    }

    fn get_mut(&mut self, id: DownloadId) -> Result<&mut DownloadSnapshot, DownloadError> {
        self.downloads
            .iter_mut()
            .find(|download| download.id == id)
            .ok_or(DownloadError::MissingDownload(id))
    }
}

fn io_error(error: &io::Error) -> DownloadError {
    DownloadError::Io(error.to_string())
}

fn sha256_file(path: &Path) -> Result<String, DownloadError> {
    let mut file = File::open(path).map_err(|error| io_error(&error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(|error| io_error(&error))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn security_warning(url: &Url) -> Option<String> {
    (url.scheme() == "http").then(|| "Unencrypted HTTP download".to_owned())
}

fn safe_filename(filename: &str) -> Result<String, DownloadError> {
    let filename = filename.trim();
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.chars().any(char::is_control)
    {
        return Err(DownloadError::InvalidFilename(filename.to_owned()));
    }
    Ok(filename.to_owned())
}

fn ensure_state(download: &DownloadSnapshot, expected: DownloadState) -> Result<(), DownloadError> {
    if download.state == expected {
        Ok(())
    } else {
        Err(DownloadError::InvalidState {
            id: download.id,
            state: download.state,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use url::Url;

    use super::{DownloadError, DownloadManager, DownloadRequest, DownloadState};

    fn request(filename: &str) -> DownloadRequest {
        DownloadRequest {
            tab_id: None,
            url: Url::parse("https://example.com/file.bin").unwrap(),
            suggested_filename: filename.to_owned(),
            total_bytes: Some(10),
        }
    }

    #[test]
    fn test_download_lifecycle_tracks_progress() {
        let directory =
            std::env::temp_dir().join(format!("nomad-download-lifecycle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut manager = DownloadManager::new(&directory);
        let id = manager.queue(request("file.bin")).unwrap();

        manager.begin(id).unwrap();
        manager.receive_bytes(id, 4).unwrap();
        manager.receive_bytes(id, 6).unwrap();
        manager.complete(id).unwrap();

        let download = manager.get(id).unwrap();
        assert_eq!(download.state, DownloadState::Completed);
        assert_eq!(download.bytes_received, 10);
        assert_eq!(
            download.checksum.as_deref(),
            Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(download.destination, directory.join("file.bin"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_download_writes_body_and_tracks_response_size() {
        let directory =
            std::env::temp_dir().join(format!("nomad-download-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut manager = DownloadManager::new(&directory);
        let id = manager.queue(request("body.bin")).unwrap();

        manager.begin(id).unwrap();
        manager.set_total_bytes(id, Some(3)).unwrap();
        manager.receive_chunk(id, b"abc").unwrap();
        manager.complete(id).unwrap();

        let download = manager.get(id).unwrap();
        assert_eq!(download.total_bytes, Some(3));
        assert_eq!(download.bytes_received, 3);
        assert_eq!(fs::read(&download.destination).unwrap(), b"abc");
        assert_eq!(
            download.checksum.as_deref(),
            Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_http_download_exposes_security_warning() {
        let mut manager = DownloadManager::default();
        let mut request = request("file.bin");
        request.url = Url::parse("http://example.com/file.bin").unwrap();
        let id = manager.queue(request).unwrap();

        assert_eq!(
            manager.get(id).unwrap().security_warning.as_deref(),
            Some("Unencrypted HTTP download")
        );
    }

    #[test]
    fn test_download_rejects_unsafe_filename_and_scheme() {
        let mut manager = DownloadManager::default();

        assert_eq!(
            manager.queue(request("../escape.bin")),
            Err(DownloadError::InvalidFilename("../escape.bin".into()))
        );

        let mut request = request("file.bin");
        request.url = Url::parse("javascript:alert(1)").unwrap();
        assert_eq!(
            manager.queue(request),
            Err(DownloadError::UnsupportedScheme("javascript".into()))
        );
    }

    #[test]
    fn test_download_terminal_states_cannot_be_reused() {
        let mut manager = DownloadManager::default();
        let id = manager.queue(request("file.bin")).unwrap();
        manager.cancel(id).unwrap();

        assert_eq!(
            manager.begin(id),
            Err(DownloadError::InvalidState {
                id,
                state: DownloadState::Cancelled,
            })
        );
    }

    #[test]
    fn test_pause_resume_erase_lifecycle() {
        let directory =
            std::env::temp_dir().join(format!("nomad-download-pause-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut manager = DownloadManager::new(&directory);
        let id = manager.queue(request("file.bin")).unwrap();

        assert_eq!(
            manager.pause(id),
            Err(DownloadError::InvalidState {
                id,
                state: DownloadState::Queued,
            }),
            "pausing a queued download must be rejected"
        );
        manager.begin(id).unwrap();
        manager.pause(id).unwrap();
        assert_eq!(manager.get(id).unwrap().state, DownloadState::Paused);
        assert_eq!(
            manager.begin(id),
            Err(DownloadError::InvalidState {
                id,
                state: DownloadState::Paused,
            }),
            "begin must reject a paused download"
        );
        manager.resume(id).unwrap();
        assert_eq!(manager.get(id).unwrap().state, DownloadState::InProgress);
        assert_eq!(
            manager.erase(id),
            Err(DownloadError::InvalidState {
                id,
                state: DownloadState::InProgress,
            }),
            "erasing an active download must be rejected"
        );
        manager.cancel(id).unwrap();
        assert_eq!(manager.get(id).unwrap().state, DownloadState::Cancelled);
        manager.erase(id).unwrap();
        assert!(manager.get(id).is_none(), "erase must remove the download");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn test_failed_download_can_retry_and_removes_partial_file() {
        let directory =
            std::env::temp_dir().join(format!("nomad-download-retry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut manager = DownloadManager::new(&directory);
        let id = manager.queue(request("retry.bin")).unwrap();

        manager.begin(id).unwrap();
        manager.receive_chunk(id, b"partial").unwrap();
        let destination = manager.get(id).unwrap().destination.clone();
        manager.fail(id, "connection reset").unwrap();
        assert!(!destination.exists());

        let retry = manager.retry_request(id).unwrap();
        assert_eq!(retry.suggested_filename, "retry.bin");
        assert_eq!(retry.total_bytes, None);
        assert_eq!(manager.get(id).unwrap().state, DownloadState::Queued);

        fs::remove_dir_all(directory).unwrap();
    }
}
