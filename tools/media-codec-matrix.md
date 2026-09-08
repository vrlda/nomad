# Nomad Media Codec / Platform Matrix

This matrix records Nomad's declared media surface per platform, the evidence
basis for each claim, and the explicit refusal paths for features Nomad does
not implement. It is a living document updated alongside the media WPT
baseline and the media-session plumbing in `crates/nomad-engine/src/servo.rs`.

## Media backend

Nomad's embedded Servo uses GStreamer for media decode on every supported
desktop (macOS, Linux, Windows). The `media-gstreamer` crate feature enables
the glvideo path (`media_glvideo_enabled`); without it media is not decoded.

## Codec support

Codec availability follows the GStreamer plugins present on the machine
(bad/ugly sets for proprietary codecs). The matrix below is the supported
surface when the standard plugin set is installed; a machine without a plugin
reports the codec as unsupported instead of crashing.

| Codec / container | H.264 | VP8 | VP9 | AV1 | Opus | Vorbis | AAC | MP3 | FLAC | WebM | MP4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macOS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Linux | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Windows | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

The exact set is verified per clean machine during release validation; this
matrix is the declared target, not a per-machine snapshot.

## Feature surface

| Feature | Status | Evidence |
| --- | --- | --- |
| Controls (play/pause/seek/volume) | Implemented | Servo `<video>/<audio>` controls; media-session plumbing in `servo.rs` |
| Seeking | Implemented | GStreamer seek; covered by media WPT seeking fixtures where decodable |
| Suspension / tab lifecycle | Implemented | Resource manager suspends media tabs; see `resources.rs` and shell lifecycle |
| Audio focus / media session | Implemented | `MediaSessionEvent` (metadata, playback state, position) emitted and coalesced; `dispatch_media_session_action` forwards native actions; unit-tested in `servo.rs` under the `servo` feature |
| Captions / subtitles | Implemented | WebVTT rendered by GStreamer text overlay |
| Media Source Extensions (MSE) | **Not available** | Probe: `media-source/SourceBuffer-abort.html` fails with `MediaSource is not defined` in the current native build |
| Encrypted Media Extensions (EME) | **Refused by design** | No CDM is embedded; `requestMediaKeySystemAccess` is not provided, so pages requesting protected playback fail closed with an explicit rejection rather than a silent fallback |

## EME refusal path

Nomad ships no Content Decryption Module. Pages that require EME receive an
explicit failure (`requestMediaKeySystemAccess` rejects); Nomad never aliases
protected playback to an unprotected path. This is a declared limitation
recorded as a known-unsupported feature rather than a bug.

## MSE limitation

The vendored Servo build does not yet expose `MediaSource`. This is recorded
as a known limitation; the media WPT slice therefore excludes MSE fixtures and
the corpus records `MediaSource is not defined` as the expected failure for any
MSE fixture that is added later.

## Controls / suspension / audio-focus evidence

- `servo::tests::media_session_events_have_stable_coalescing_kinds` — metadata,
  playback-state, and position events are classified.
- `servo::tests::media_session_position_updates_are_coalesced_per_tab` — rapid
  position updates coalesce per tab.
- `dispatch_media_session_action` routes native play/pause/seek actions into
  the page media session.
- Media tabs participate in the tab lifecycle: suspension releases the media
  surface and playback state is retained for resume.

## Verification

- Media WPT fixtures that are decodable on the machine run through
  `tools/run-nomad-wpt.py`; MSE/EME fixtures are expected-fail with the refusal
  path above.
- Clean-machine decode checks for each codec row are part of the release
  validation gate (Section 7 of the completion matrix).
