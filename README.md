# Nomad Browser

Rust browser project built around a locally owned Servo fork, first-party UMC
networking, and a Rust Xray-compatible tunnel.

## Current status: Alpha

The foundation contains the switchable routing contract, a stateful browser
shell, and an embedded Servo engine. The full Servo and Stylo source trees are
stored locally under `vendor/` and are compiled only for the native browser
feature. Nomad renders pages offscreen and composites them with a native GPU
URL bar and vertical tab sidebar.

Alpha builds for macOS are available from
[GitHub Releases](https://github.com/vrlda/nomad/releases). They are currently
ad-hoc signed and not notarized; macOS may require confirming the first launch
from System Settings → Privacy & Security.

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
# Launch the graphical browser with a clean session.
cargo run -p nomad-browser --features native-servo -- --new-session

# Show the native browser options.
cargo run -p nomad-browser --features native-servo -- --help
```

`--umc` starts Nomad's local SOCKS5 adapter over the UMC Control API. It uses
UMC's protected local socket and application stream protocol:

On Unix, `NOMAD_UMC_SOCKET` is a Unix-domain socket path. On Windows, it is a
local named-pipe path such as `\\.\pipe\umc-control`. The engine also exposes a
generic UMC application-session API for stream and datagram protocols; the
browser's web route uses the stream path.

```sh
NOMAD_UMC_SOCKET="/path/to/.local/run/umc.sock" \
NOMAD_UMC_DESTINATION=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  cargo run -p nomad-browser --features native-servo -- --umc https://example.com
```

`NOMAD_UMC_DESTINATION` is the 32-byte UMC endpoint id of the authorized
gateway/application peer for ordinary web URLs. It is optional when browsing
explicit identity-addressed UMC resources: a `umc://` host containing a
64-character endpoint id becomes the UMC destination directly.
`NOMAD_UMC_PROTOCOL` can select a deployed application protocol; it defaults to
`org.nomad.browser.tcp/1`. The browser passes each target as stream metadata,
so the UMC application protocol decides how that stream reaches the resource.

For example, an explicit identity resource can run without a gateway hint:

```sh
NOMAD_UMC_SOCKET="/path/to/.local/run/umc.sock" \
  cargo run -p nomad-browser --features native-servo -- --umc \
  umc://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/
```

If a conventional web URL or an aliased `umc://service-name/` resource is
opened without `NOMAD_UMC_DESTINATION`, its connection fails closed instead of
falling back to direct traffic.

An opt-in interoperability test can exercise a running daemon directly:

```sh
NOMAD_UMC_SOCKET=/path/to/umc.sock \
NOMAD_UMC_DESTINATION=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  cargo test -p nomad-engine live_control_api_interoperates_with_configured_umc_daemon -- --ignored
```

`--xray` starts the embedded Rust forwarding core. It keeps Xray's protocol and
transport layers separate. Live handlers currently cover SOCKS5, HTTP CONNECT,
legacy Shadowsocks AEAD including XChaCha20-Poly1305, Shadowsocks 2022
BLAKE3-AEAD, VMess AEAD, Trojan, VLESS over RAW/TLS, HTTPUpgrade/WebSocket/gRPC,
XHTTP `packet-up`, `stream-one`, and split `stream-up` over HTTP/1.1, and
Hysteria v2 over QUIC/HTTP/3:

```sh
NOMAD_XRAY_PROXY=socks5h://127.0.0.1:1080 \
  cargo run -p nomad-browser --features native-servo -- --xray https://example.com
```

`NOMAD_XRAY_CONFIG` may point to the JSON profile instead. Direct `freedom`
outbounds are supported only when explicitly selected in that profile; they
are never used as a fallback after another outbound fails. Their
`domainStrategy` can constrain direct resolution to IPv4 or IPv6, and when the
profile also declares a `dns` outbound the `UseIP`-family strategies route DNS
packets through that server instead of the system resolver. DNS packet
forwarding is available through the explicit `XrayDnsResolver` API, and
Loopback requires an explicit in-process connector.
The embedded handlers also include REALITY over RAW/XHTTP, mKCP (with Xray's
default `SimpleAuthenticator` datagram authentication and seed-derived
AES-128-GCM), WireGuard userspace transport, DNS packet forwarding, Loopback,
and Blackhole. gRPC is available over cleartext or verified TLS; Hysteria is
v2 over verified QUIC; XHTTP currently implements `auto` (packet-up for
cleartext/TLS and stream-one for REALITY), `packet-up`, `stream-one`, and split
`stream-up`; the remaining HTTP/1.1 metadata placements include path, query,
header, and cookie, while packet payloads support body, header, and cookie
placement. VLESS supports the `xtls-rprx-vision` and `xtls-rprx-vision-udp443`
flows over raw TCP with TLS or REALITY, including XTLS Vision's length-randomized
padding framing; the Go-TLS-only `xtls-rprx-direct`/`xtls-rprx-splice` splice
variants and mKCP disguise headers other than `none` are validated but
explicitly rejected. VMess supports `auto`, `aes-128-gcm`,
`chacha20-poly1305`, and `none` (authenticated header, plaintext body)
security modes. HTTP/2/HTTP/3, padding, download profiles, and connection
multiplexing remain unsupported. Unsupported
protocol/security combinations are rejected before the local listener starts;
they are never aliased to ordinary TLS, generic KCP, or direct traffic.
Credentials in endpoint URLs are rejected.

Servo's HTTP memory and disk cache keys include the registered top-level site,
so the same third-party URL cannot be reused across different site partitions.
The switches can never be enabled together.

The shell includes workspace/container context, split browsing, reader mode,
translation, structured DevTools inspection, and encrypted user-owned
synchronization. The WebExtensions core supports validated Manifest V2/V3
content-script packages from inline resources, real directories, and bounded
ZIP/XPI archives. It includes install/uninstall lifecycle, persistent extension
state in encrypted sessions, explicit permission and host grants, `activeTab`
grants that expire with the tab, v2 `browser_action` and v3 `action` metadata,
background pages and service-worker-style event contexts, startup/install/action
events, permission-checked `storage.local`, redacted `tabs.query`, bounded
runtime messaging in both directions, target-scoped extension-to-extension
messages, `history.search`, `bookmarks.search`, `downloads.search`/`list`/`download`,
`alarms`, `commands.getAll`/`onCommand`, native-rendered action popups, native
notifications, `i18n.getMessage` locale resolution, Servo-backed `cookies`,
`scripting.executeScript`, allowlisted native messaging, and `webRequest`
delivery. `webRequestBlocking` also supports pre-request
declarative host cancellation through the `nomad_blocked_hosts` manifest field.
Directory and archive packages reject symlink/traversal resources. Execution
still follows manifest-declared background, content-script, and popup paths;
other package resources are retained only for extension-origin loading and
declared web-accessible resources.

This is Nomad's maintained compatibility surface, not Chromium-level parity.
The current Servo embedder uses a sandboxed extension realm and a
capability-checked browser bridge. Wallet-critical paths are included:
extension-origin provider resources, declared main-world injection,
`runtime.sendMessage`, `runtime.connect` ports, storage, and tab lifecycle
APIs. This is Nomad's maintained compatibility contract, not a claim of
Chromium's exact isolated-world ABI or complete parity with every browser-
vendor API. Unsupported APIs fail explicitly rather than being silently
mapped to direct page access. The blocking surface is intentionally
declarative so cancellation happens before the network thread proceeds;
callback-based `webRequest` remains observational.

To run the native browser with the embedded Servo engine:

```sh
# Normal startup restores the last cleanly saved session; with no saved
# session it opens a blank tab.
cargo run -p nomad-browser --features native-servo --

# Start without restoring saved tabs.
cargo run -p nomad-browser --features native-servo -- --new-session

# Restore saved tabs explicitly, or open one URL in a new session.
cargo run -p nomad-browser --features native-servo -- --restore-session
cargo run -p nomad-browser --features native-servo -- https://example.com
```

After building the native binary, the repeatable local browser smoke exercises
real page navigation, a DOM click, history back/forward, reload, and script
evaluation:

```sh
python3 tools/run-nomad-browser-smoke.py
```

For example:

```sh
NOMAD_XRAY_PROXY=socks5h://127.0.0.1:1080 \
  cargo run -p nomad-browser --features native-servo -- --xray https://example.com
```

The default workspace keeps the native Servo feature disabled so core and shell
development does not compile the full browser engine.

## Development checks

```sh
cargo fmt --manifest-path crates/nomad-core/Cargo.toml -- --check
cargo fmt --manifest-path crates/nomad-browser/Cargo.toml -- --check
cargo fmt --manifest-path crates/nomad-engine/Cargo.toml -- --check
cargo fmt --manifest-path crates/nomad-shell/Cargo.toml -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Phase 10 hardening checks
cargo test --workspace --all-targets
cargo bench -p nomad-shell --bench large_session
cargo +nightly fuzz build --fuzz-dir fuzz
cargo +nightly fuzz run xray_config --fuzz-dir fuzz -- -runs=1000
```
