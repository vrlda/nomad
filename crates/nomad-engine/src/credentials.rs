#![allow(clippy::missing_errors_doc)]

//! Browser-owned credential classification and OS-backed secret storage.
//!
//! Page scripts only receive non-secret field classifications. Credential
//! values stay behind this module and are released only after a browser-owned
//! confirmation decision.

use std::fmt;

use keyring::Entry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CredentialStoreBackend {
    MacKeychain,
    WindowsCredentialManager,
    LinuxSecretService,
    Unsupported,
}

impl CredentialStoreBackend {
    #[must_use]
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            return Self::MacKeychain;
        }
        #[cfg(target_os = "windows")]
        {
            return Self::WindowsCredentialManager;
        }
        #[cfg(target_os = "linux")]
        {
            return Self::LinuxSecretService;
        }
        #[allow(unreachable_code)]
        Self::Unsupported
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MacKeychain => "macOS Keychain",
            Self::WindowsCredentialManager => "Windows Credential Manager",
            Self::LinuxSecretService => "Linux Secret Service",
            Self::Unsupported => "unsupported secure credential store",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialStoreError {
    InvalidOrigin,
    Backend(String),
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrigin => {
                formatter.write_str("credential origin is not a valid site origin")
            }
            Self::Backend(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for CredentialStoreError {}

/// A browser-owned credential store. The keyring crate selects the native
/// Keychain/Credential Manager/Secret Service backend for the current target.
pub struct OsCredentialStore {
    service: String,
}

impl Default for OsCredentialStore {
    fn default() -> Self {
        Self::new("org.nomad.browser")
    }
}

impl OsCredentialStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    #[must_use]
    pub const fn backend(&self) -> CredentialStoreBackend {
        CredentialStoreBackend::current()
    }

    pub fn save(
        &self,
        origin: &str,
        username: &str,
        password: &str,
    ) -> Result<(), CredentialStoreError> {
        let account = credential_account(origin, username)?;
        Entry::new(&self.service, &account)
            .map_err(|error| CredentialStoreError::Backend(error.to_string()))?
            .set_password(password)
            .map_err(|error| CredentialStoreError::Backend(error.to_string()))
    }

    pub fn load(
        &self,
        origin: &str,
        username: &str,
    ) -> Result<Option<String>, CredentialStoreError> {
        let account = credential_account(origin, username)?;
        let entry = Entry::new(&self.service, &account)
            .map_err(|error| CredentialStoreError::Backend(error.to_string()))?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(CredentialStoreError::Backend(error.to_string())),
        }
    }

    pub fn delete(&self, origin: &str, username: &str) -> Result<(), CredentialStoreError> {
        let account = credential_account(origin, username)?;
        Entry::new(&self.service, &account)
            .map_err(|error| CredentialStoreError::Backend(error.to_string()))?
            .delete_credential()
            .map_err(|error| CredentialStoreError::Backend(error.to_string()))
    }
}

fn credential_account(origin: &str, username: &str) -> Result<String, CredentialStoreError> {
    let parsed = url::Url::parse(origin).map_err(|_| CredentialStoreError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(CredentialStoreError::InvalidOrigin);
    }
    let username = username.trim();
    if username.is_empty() || username.len() > 512 || username.contains('\0') {
        return Err(CredentialStoreError::InvalidOrigin);
    }
    Ok(format!(
        "{}\n{}",
        parsed.origin().ascii_serialization(),
        username
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AutofillFieldKind {
    Username,
    Email,
    CurrentPassword,
    NewPassword,
    OneTimeCode,
    CardNumber,
    CardName,
    CardExpiry,
    CardSecurityCode,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutofillFieldDescriptor {
    pub name: String,
    pub id: String,
    pub label: String,
    pub input_type: String,
    pub autocomplete: String,
}

#[must_use]
pub fn classify_autofill_field(field: &AutofillFieldDescriptor) -> AutofillFieldKind {
    let autocomplete = field.autocomplete.trim().to_ascii_lowercase();
    let hints = format!(
        "{} {} {} {}",
        field.name.to_ascii_lowercase(),
        field.id.to_ascii_lowercase(),
        field.label.to_ascii_lowercase(),
        autocomplete
    );
    if autocomplete
        .split_whitespace()
        .any(|hint| hint == "one-time-code")
        || hints.contains("otp")
        || hints.contains("one time")
    {
        return AutofillFieldKind::OneTimeCode;
    }
    if autocomplete
        .split_whitespace()
        .any(|hint| hint == "cc-number")
        || hints.contains("card number")
        || hints.contains("cc-number")
        || hints.contains("cardnumber")
    {
        return AutofillFieldKind::CardNumber;
    }
    if autocomplete
        .split_whitespace()
        .any(|hint| hint == "cc-name")
        || hints.contains("cardholder")
    {
        return AutofillFieldKind::CardName;
    }
    if autocomplete.split_whitespace().any(|hint| hint == "cc-exp")
        || hints.contains("expiry")
        || hints.contains("expiration")
    {
        return AutofillFieldKind::CardExpiry;
    }
    if autocomplete.split_whitespace().any(|hint| hint == "cc-csc")
        || hints.contains("cvv")
        || hints.contains("security code")
    {
        return AutofillFieldKind::CardSecurityCode;
    }
    if field.input_type.eq_ignore_ascii_case("password") {
        if autocomplete
            .split_whitespace()
            .any(|hint| hint == "new-password")
            || hints.contains("new password")
            || hints.contains("confirm password")
        {
            return AutofillFieldKind::NewPassword;
        }
        return AutofillFieldKind::CurrentPassword;
    }
    if autocomplete.split_whitespace().any(|hint| hint == "email") || hints.contains("email") {
        return AutofillFieldKind::Email;
    }
    if autocomplete
        .split_whitespace()
        .any(|hint| hint == "username")
        || hints.contains("user")
        || hints.contains("login")
    {
        return AutofillFieldKind::Username;
    }
    AutofillFieldKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::{
        classify_autofill_field, AutofillFieldDescriptor, AutofillFieldKind,
        CredentialStoreBackend, OsCredentialStore,
    };

    fn field(name: &str, input_type: &str, autocomplete: &str) -> AutofillFieldDescriptor {
        AutofillFieldDescriptor {
            name: name.into(),
            id: name.into(),
            label: name.into(),
            input_type: input_type.into(),
            autocomplete: autocomplete.into(),
        }
    }

    #[test]
    fn classifier_prefers_explicit_autocomplete_tokens() {
        assert_eq!(
            classify_autofill_field(&field("account", "text", "username")),
            AutofillFieldKind::Username
        );
        assert_eq!(
            classify_autofill_field(&field("pass", "password", "new-password")),
            AutofillFieldKind::NewPassword
        );
        assert_eq!(
            classify_autofill_field(&field("code", "text", "one-time-code")),
            AutofillFieldKind::OneTimeCode
        );
    }

    #[test]
    fn classifier_covers_payment_fields_without_values() {
        assert_eq!(
            classify_autofill_field(&field("cc-number", "text", "")),
            AutofillFieldKind::CardNumber
        );
        assert_eq!(
            classify_autofill_field(&field("cvv", "text", "")),
            AutofillFieldKind::CardSecurityCode
        );
    }

    #[test]
    fn credential_store_reports_native_backend_and_rejects_bad_origins() {
        let store = OsCredentialStore::default();
        assert_ne!(store.backend(), CredentialStoreBackend::Unsupported);
        assert!(store.load("javascript:alert(1)", "user").is_err());
        assert!(store.load("https://example.test", "").is_err());
    }
}
