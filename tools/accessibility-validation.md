# Nomad Accessibility Validation

This document records Nomad's accessibility surface, the evidence for each
claim, and the known gaps. It complements the completion matrix (Section 3,
accessibility row).

## Renderer plumbing (implemented and unit-tested)

Nomad embeds Servo's AccessKit integration and exposes a platform-independent
renderer API in `crates/nomad-engine/src/servo.rs`:

- `take_accessibility_updates()` drains `servo::accesskit::TreeUpdate`s per
  tab; the native shell owns one platform root and grafts each WebView's host
  tree into it while preserving the document subtree ID.
- `dispatch_accessibility_action(tab_id, ActionRequest)` forwards focus,
  scroll, click, and text-edit actions from the platform adapter into the
  page.
- The Servo embedder enables `accessibility_enabled` in the browser baseline
  preferences (asserted by the servo-feature unit test
  `nomad_preferences_enable_browser_core_capabilities`).
- `accessibility_updates` storage and the action dispatch are exercised under
  `cargo test -p nomad-engine --features servo`.

## WebDriver accessible-name evidence

Nomad now wires the W3C WebDriver `GetComputedLabel` command through the
vendored Servo server and computes names in the script process using DOM
authoring mechanisms (`aria-labelledby`, `aria-label`, hidden-reference
handling, host-language `alt`/`placeholder`/`title`, and text content). The
declared native macOS probe passes all 131 subtests:

```
accname/name/comp_label.html  -> 131/131 subtests pass
```

This is a standards-harness signal, not a substitute for native assistive
technology validation. `accessibility/aria-owns.html` is not in the enabled WPT
surface, and the full AccessKit tree/action smoke still requires platform
adapters on macOS, Linux, and Windows.

## Native assistive-technology smoke tests

Native AT smoke tests (VoiceOver on macOS, AT-SPI on Linux, UIA on Windows)
require the platform adapters and a clean desktop; they are part of the
release-validation gate (completion matrix Section 7). The renderer plumbing
above is adapter-independent so the same integration feeds every target.

## Focus / keyboard semantics

Focus actions and keyboard navigation flow through the AccessKit action
request path and the native chrome's key handling in
`crates/nomad-browser/src/chrome.rs`. Keyboard/focus WPT fixtures that do not
depend on the WebDriver label command run through the corpus harness.

## Live regions

AccessKit live-region properties are part of the TreeUpdate stream; consumers
are the platform adapters during AT smoke validation.
