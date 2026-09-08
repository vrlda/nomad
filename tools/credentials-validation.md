# Credentials and autofill validation

`nomad-engine::OsCredentialStore` uses the `keyring` provider abstraction,
which selects the native macOS Keychain, Windows Credential Manager, or Linux
Secret Service backend. Service accounts are scoped to a validated HTTP(S)
origin and username; invalid origins and empty accounts are rejected.

`classify_autofill_field` returns only non-secret field classes (username,
email, password, OTP, and payment metadata). The native renderer scans only
that metadata in an isolated browser-owned world; credential values are kept
in the Chrome confirmation panel or OS credential manager until an explicit
save/fill action. The classifier and backend-selection/error boundary are
covered by engine unit tests. A native clean-machine credential round trip
remains a release-validation gate.
