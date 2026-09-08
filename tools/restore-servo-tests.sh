#!/usr/bin/env bash
# Restore the large upstream test corpus omitted from Nomad's source checkout.
# The immutable commit keeps CI and local validation reproducible.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${SERVO_TESTS_DEST:-$ROOT/vendor/servo/tests}"
SENTINEL="$DEST/wpt/tests/tools/wptrunner/wptrunner/wptrunner.py"
META_SENTINEL="$DEST/wpt/meta/MANIFEST.json"
SERVO_REV="1d44e5dd6a8b64c02f9dbf7fcbdf4ebdd0740019"

if [[ -f "$SENTINEL" && -f "$META_SENTINEL" ]]; then
  echo "Servo test corpus already present"
  exit 0
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nomad-servo-tests.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

git init --quiet "$TEMP_DIR/servo"
git -C "$TEMP_DIR/servo" remote add origin https://github.com/servo/servo.git
git -C "$TEMP_DIR/servo" sparse-checkout init --cone
git -C "$TEMP_DIR/servo" sparse-checkout set \
  tests/capi \
  tests/unit \
  tests/wpt/meta \
  tests/wpt/tests/tools \
  tests/wpt/tests/resources \
  tests/wpt/tests/FileAPI \
  tests/wpt/tests/IndexedDB \
  tests/wpt/tests/WebCryptoAPI \
  tests/wpt/tests/console \
  tests/wpt/tests/css/css-box/parsing \
  tests/wpt/tests/css/cssom \
  tests/wpt/tests/dom \
  tests/wpt/tests/domparsing \
  tests/wpt/tests/encoding \
  tests/wpt/tests/fetch \
  tests/wpt/tests/html/dom/documents/dom-tree-accessors \
  tests/wpt/tests/html/anonymous-iframe \
  tests/wpt/tests/html/syntax/parsing-html-fragments \
  tests/wpt/tests/performance-timeline \
  tests/wpt/tests/url \
  tests/wpt/tests/web-animations/interfaces/Animation \
  tests/wpt/tests/websockets \
  tests/wpt/tests/webstorage \
  tests/wpt/tests/workers/constructors/Worker \
  tests/wpt/tests/xhr \
  tests/wpt/tests/accname/name \
  tests/wpt/tests/service-workers \
  tests/wpt/tests/compression
git -C "$TEMP_DIR/servo" fetch --quiet --depth 1 origin "$SERVO_REV"
git -C "$TEMP_DIR/servo" checkout --quiet --detach FETCH_HEAD

mkdir -p "$DEST"
cp -R "$TEMP_DIR/servo/tests/." "$DEST/"
test -f "$SENTINEL"
test -f "$META_SENTINEL"
echo "Restored Servo test corpus at $SERVO_REV"
