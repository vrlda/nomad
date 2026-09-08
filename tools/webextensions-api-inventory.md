# Nomad WebExtensions API Inventory

This inventory maps the Chromium `chrome.*` / `browser.*` WebExtensions API
surface to Nomad's implementation status, by manifest version, context,
permission, event, and callback/promise behavior. It is the authoritative
answer to the completion-matrix item "Inventory the Chromium WebExtensions API
surface" and is maintained alongside `crates/nomad-engine/src/extensions.rs`
(registry), `crates/nomad-engine/src/servo.rs` (background/content shim), and
`crates/nomad-shell/src/lib.rs` (API dispatcher).

Status legend: **IMPLEMENTED** = wired end-to-end. **PARTIAL** = some methods
only (specific gaps listed). **MISSING** = not present in the shim, validator,
or dispatcher. **REJECTED** = recognized but returns an explicit permission
error or a null stub (never a silent no-op with success).

## Manifests, contexts, worlds

| Surface | Status | Notes |
| --- | --- | --- |
| MV2 | IMPLEMENTED | `manifest_version: 2`; `background.scripts` (multiple, joined, persistent page); `browser_action` maps to `action` |
| MV3 | IMPLEMENTED | `manifest_version: 3`; `background.service_worker` (+ `"type": "module"`); `action` |
| Content-script worlds | IMPLEMENTED | `ISOLATED` (default, per-extension world) and `MAIN` (page world); `scripting.executeScript` runs in the isolated world |
| Background lifecycle | PARTIAL | Runs on demand; `persistent` flag parsed but always "running on demand" |
| Package sources | IMPLEMENTED | Inline resources, real directories, bounded ZIP/XPI archives; symlink/traversal rejection |

## API families

### runtime — PARTIAL
- IMPLEMENTED: `sendMessage`, `onMessage`, `onMessageExternal`, `onInstalled`, `onStartup`, `onSuspend`, `onUpdateAvailable`, `connect`/`onConnect` (tab-side), `onConnectExternal` plus external port connect/message/disconnect routing with `externally_connectable` checks, `id`, `getURL`, `getManifest`, `getPlatformInfo`, `getBrowserInfo`, `getContexts` (background context), `sendNativeMessage` (allowlisted hosts), `setUninstallURL`, and `openOptionsPage` request plumbing
- IMPLEMENTED: callback-scoped `runtime.lastError` exposes rejected API messages while the callback runs and is cleared on the next microtask
- PARTIAL: background `runtime.sendMessage` delivery is routed toward matching content-script tabs, but the real MetaMask dApp handshake is not yet passing end-to-end; the native smoke currently hangs on the first `eth_chainId` request
- PARTIAL: tab/frame context enumeration beyond the background context

### tabs — PARTIAL
- IMPLEMENTED: `query` (permission-filtered URLs), `get`, `create`, `update`, `remove`, `reload`, `duplicate`, `discard` (maps to the browser's suspended-tab lifecycle), `goBack`, `goForward`, `getCurrent`, `sendMessage`, `connect` (background→content port), `group`, `ungroup`, and `onCreated`/`onUpdated`/`onRemoved`/`onActivated` lifecycle events
- PARTIAL: `captureVisibleTab` now uses an asynchronous renderer PNG path with host/activeTab checks; `tabGroups.get/query/update` is implemented for Nomad's single-window model with title/color/collapsed state. Additional Chromium-only tab capture/session/grouping APIs remain missing, and a clean native extension smoke is still required.

### windows — PARTIAL
- IMPLEMENTED: `get`, `getCurrent`, `getAll`, `create`, `update`, and `remove` through Nomad's single-window/tab-backed model; `populate` remains gated on `tabs`
- IMPLEMENTED: `onCreated`, `onRemoved`, and `onFocusChanged` for that model
- MISSING: multi-window behavior and Chromium window types/bounds beyond the single native window

### scripting — PARTIAL
- IMPLEMENTED: `executeScript` (code/files, `tabId` target, host-permission or activeTab check, isolated world), dynamic content-script registration/update/removal/query, and `insertCSS`/`removeCSS`
- PARTIAL: renderer injection is scoped to Nomad's supported tab lifecycle and does not yet expose every Chromium frame/world option

### declarativeNetRequest — PARTIAL
- IMPLEMENTED: `updateDynamicRules`/`getDynamicRules` (persisted), `updateSessionRules`/`getSessionRules` (session), rule validation, **real pre-request blocking** (block rules + manifest `nomad_blocked_hosts`)
- IMPLEMENTED: manifest-declared static rulesets load from package resources, validate rule IDs, participate in pre-request blocking, expose enabled IDs, and persist enable/disable state across registry restore.
- PARTIAL: `isSessionEnabled` and `isRegexSupported` have permission-checked basic responses and validation; `setExtensionActionOptions` now persists `displayActionCountAsBadgeText` and matching block rules update the action badge count, while full redirect/header rule execution remains missing. `onRuleMatched` dispatches for Nomad's matching static/dynamic/session block rules.

### cookies — PARTIAL
- IMPLEMENTED: `get`, `getAll`, `set`, `remove` against Servo's cookie jar (host-grant checked)
- IMPLEMENTED: `onChanged` dispatches explicit `set`/`remove` mutations to all enabled cookie extensions

### storage — PARTIAL
- IMPLEMENTED: `local` get/set/remove/clear + `onChanged`; quotas enforced
- IMPLEMENTED: `sync` is a separate persisted namespace and `session` is a separate in-memory namespace cleared on restore; area-specific change events and bounded quotas are enforced
- IMPLEMENTED: `managed` is an empty read-only policy area when no enterprise policy provider is configured; reads return caller defaults and zero bytes in use
- PARTIAL: enterprise policy injection and managed-area change events are not configured

### history — PARTIAL
- IMPLEMENTED: `search`, `getVisits`, `addUrl`, `deleteUrl`, `deleteRange`, `deleteAll`, `onVisited`, `onTitleChanged`, and `onVisitRemoved`
- PARTIAL: title updates are sourced from Servo's native page-title callback; persisted history records still retain URL/visit metadata only

### bookmarks — PARTIAL
- IMPLEMENTED: `search`, `create`, `get`, `getTree`, `getChildren`, `getSubTree`, `update`, `remove`, `removeTree`, `move`, and `onCreated`/`onRemoved`/`onChanged`/`onMoved`
- PARTIAL: the native bookmark model is intentionally flat apart from Nomad's local folders; Chromium sync metadata and reorder semantics are not complete

### downloads — PARTIAL
- IMPLEMENTED: `download` (host-permission checked), `search`/`list`, `pause`, `resume`, `cancel`, `remove`, `erase`, `open`, `show`, and `onChanged`/`onCreated`/`onErased`
- PARTIAL: native open/show actions are shell-mediated and require a desktop-capable embedder

### notifications — PARTIAL
- IMPLEMENTED: `create`, `clear`, `getAll`, and `onClosed`/`onClicked`/`onButtonClicked` event dispatch
- PARTIAL: native rendering and interaction are shell-dependent

### alarms — PARTIAL
- IMPLEMENTED: `create` (when/delayInMinutes/periodInMinutes), `get`, `getAll`, `clear`, `clearAll`, and `onAlarm` (polled)

### commands — PARTIAL
- IMPLEMENTED: manifest command parsing, `getAll`, and `onCommand` dispatch for Nomad-triggered keyboard commands
- MISSING: browser-level shortcut registration/conflict UI and the full Chromium command shortcut surface

### contextMenus — PARTIAL
- IMPLEMENTED: `create`, `update`, `remove`, `removeAll` (bounded, permission-checked), and `onClicked`/`onShown`/`onHidden` dispatch plumbing
- PARTIAL: native menu presentation and selection depend on the desktop shell

### webNavigation — PARTIAL
- IMPLEMENTED: `onCommitted`, `onCompleted`, `onErrorOccurred`, `onHistoryStateUpdated`, `onBeforeNavigate`, `onDOMContentLoaded` (host-grant filtered), and `getAllFrames`/`getFrame` (synthetic top frame)
- MISSING: real frame-tree enumeration and frame-specific lifecycle details

### webRequest — PARTIAL (observational + blocking decisions)
- IMPLEMENTED: `onBeforeRequest` observational delivery (method/url/status/duration), `webRequestBlocking` gates declarative pre-request blocking
- IMPLEMENTED: `resolveBlocking` is bound end-to-end for extension JS (background shim → dispatcher → navigation): `cancel` produces `BlockedByWebRequest` and `redirectUrl` retargets the navigation; both require the `webRequestBlocking` permission and are exercised by shell regression tests
- PARTIAL: `handlerBehaviorChanged` is a permission-checked no-op because Nomad's request listeners are installed without a mutable filter cache. `requestBody`/`responseHeaders`/`requestHeaders` delivery and subresource (non-navigation) interception remain missing

### management — PARTIAL
- IMPLEMENTED: `getAll`, `get`, `setEnabled` (reinstalls renderer resources/background), `getSelf`, `uninstallSelf`, and `onInstalled`/`onUninstalled`/`onEnabled`/`onDisabled`
- PARTIAL: `getPermissionWarningsById` returns an intentionally conservative empty list

### identity — PARTIAL
- IMPLEMENTED: provider-backed `getAuthToken` and `launchWebAuthFlow` with
  manifest OAuth2 configuration, PKCE authorization-code exchange, bounded
  persistent token grants, refresh handling, and `onSignInChanged` dispatch on
  account transitions. `externally_connectable` remains a separate
  message-authentication mechanism.
- PARTIAL: interactive account UX is browser-owned and the provider endpoint
  transport is intentionally replaceable for deterministic tests.

### permissions — PARTIAL
- IMPLEMENTED: `contains`, `request`, `remove`, and `onAdded`/`onRemoved` dispatch with renderer script refresh.
- MISSING: user-facing prompt UI and browser-specific permission warning text.

### action / browserAction — PARTIAL
- IMPLEMENTED: `onClicked`, `setBadgeText`, `setBadgeBackgroundColor`, `setBadgeTextColor`, `setIcon`, `setTitle`, `setPopup`, `enable`, `disable`, `getBadgeText`, `getBadgeBackgroundColor`, `getBadgeTextColor`, `getTitle`, `getPopup`, and manifest `default_popup` handling.
- PARTIAL: `setIcon` validates and persists the requested path/image-data state, but native toolbar icon rasterization and display are not implemented.

### i18n — PARTIAL
- IMPLEMENTED: `getUILanguage` (currently `en-US`), `getAcceptLanguages`, `detectLanguage` (bounded Unicode-script detection), and `getMessage` (locale catalog lookup with positional substitution)
- MISSING: user locale negotiation beyond the English fallback and Chromium's full language-detection corpus

### browser — PARTIAL
- `browser.*` mirrors `chrome.*`; `browser.runtime.onMessage` variants follow runtime status

### Other namespaces — MISSING or explicitly unsupported
Truly missing (no shim, validator, or dispatcher surface): `topSites`,
`omnibox`, `power`, `dns`, `sidePanel`, `devtools`, `debugger`, `dom`.

Explicitly unsupported per the implementation boundaries tracked in
[`docs/remaining-work.md`](../docs/remaining-work.md) and the general
specification: recognized permission strings with no scheduled API work are
`proxy`, `privacy`, `idle`, and `clipboard.*`. Nomad's user-controlled
networking model (proxies, Xray, UMC) is intentionally configured in the
browser rather than exposed to extension content.

Also explicitly unsupported for now: multi-window `windows` behavior beyond
the single native window, Chromium window types/bounds, browser-level command
shortcut registration, and enterprise managed-storage policy injection.

## Recognized permissions

`readpage, activetab, modifypage, scripting, storage, unlimitedstorage, clipboard, clipboardread, clipboardwrite, downloads, tabs, history, bookmarks, network, webrequest, webrequestblocking, cookies, alarms, notifications, nativemessaging, webnavigation, contextmenus, offscreen, management, identity, windows, tabgroups, sessions, permissions, proxy, privacy, idle, declarativenetrequest, declarativenetrequestwithhostaccess, declarativenetrequestfeedback, userscripts`. Unrecognized names are preserved in `unsupported_permissions` and never granted. Host patterns in `permissions` are promoted to `host_permissions`.

## Events

`ExtensionEventKind` supports: Startup, Installed{reason}, RuntimeMessage, RuntimePortConnected, RuntimePortMessage, RuntimePortDisconnected, WebNavigation, StorageChanged, Alarm, WebRequest, ActionClicked, IdentitySignInChanged, RuntimeResponse. Events are queued per extension and dispatched to the background shim's `dispatch()`.

The full implemented surface additionally includes:
`RuntimeExternalPortConnected/Message/Disconnected`, `NotificationClosed`,
`NotificationClicked`, `NotificationButtonClicked`, `ContextMenuClicked`,
`ContextMenuShown`, `ContextMenuHidden`, `PermissionAdded`,
`PermissionRemoved`, `CookieChanged`, `RuntimeSuspend`,
`RuntimeUpdateAvailable`, `ManagementInstalled`, `ManagementUninstalled`,
`ManagementEnabled`, `ManagementDisabled`, `HistoryVisited`,
`HistoryTitleChanged`, `HistoryVisitRemoved`, and declarativeNetRequest
rule-matched dispatch — all wired through the background shim's listener
arrays and `dispatch()`.

## Wallet-critical surface (MetaMask)

MetaMask is an MV3 package that depends primarily on: `storage.local`, `runtime` (sendMessage/onMessage/connect), `tabs` (query/create/onUpdated), `windows` (create for the popup), `notifications`, `i18n.getMessage` (localization), `action`, and `alarms`. Nomad now exposes those bridge paths, including the JS `i18n.getMessage` method and lifecycle event dispatch. The remaining wallet gate is behavioral: run the real package through popup creation, provider injection, permissions, signing, chain changes, event delivery, and failure paths against representative dApps. Install/resource/permission/uninstall validation alone is not sufficient.

For an embedder-controlled native run, `nomad-browser --new-session
--extension-archive <PATH> --webdriver <PORT> <URL>` installs the real archive,
grants required manifest permissions and requested hosts for that explicit
preload, and refreshes the page scripts through the browser navigation path.
`tools/run-nomad-metamask-smoke.py` exercises this path; it remains a live
acceptance gate rather than an inventory-only claim. The current fresh-binary
result is provider injection plus three event listeners passing, followed by an
`eth_chainId` WebDriver timeout.
