# Nomad Browser

Rust browser project built around a maintained Servo fork, first-party UMC
networking, and a Rust Xray-compatible tunnel.

## Current status

The initial workspace contains the switchable routing contract and a small CLI
shell. Servo, UMC, and Xray backends are intentionally not wired yet.

Network modes are individually selectable:

```text
UMC off, Xray off  → direct
UMC on,  Xray off  → UMC
UMC off, Xray on   → Xray
```

UMC and Xray are mutually exclusive. Enabling one runtime switch disables the
other; passing both enable flags to the CLI is rejected.

An enabled backend that is unavailable fails closed. The browser never silently
falls back to direct traffic when UMC or Xray is enabled.

## Run

```sh
cargo run -p nomad-browser
cargo run -p nomad-browser -- --help
```

The `--umc` and `--xray` switches currently report an unavailable backend until
their integrations land.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
