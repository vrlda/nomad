#!/usr/bin/env bash
# Restore the large upstream test corpus omitted from Nomad's source checkout.
# The immutable commit keeps CI and local validation reproducible.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/vendor/servo/tests"
SENTINEL="$DEST/wpt/tests/tools/wptrunner/wptrunner.py"
SERVO_REV="1d44e5dd6a8b64c02f9dbf7fcbdf4ebdd0740019"

if [[ -f "$SENTINEL" ]]; then
  echo "Servo test corpus already present"
  exit 0
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nomad-servo-tests.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

git init --quiet "$TEMP_DIR/servo"
git -C "$TEMP_DIR/servo" remote add origin https://github.com/servo/servo.git
git -C "$TEMP_DIR/servo" sparse-checkout init --cone
git -C "$TEMP_DIR/servo" sparse-checkout set tests
git -C "$TEMP_DIR/servo" fetch --quiet --depth 1 origin "$SERVO_REV"
git -C "$TEMP_DIR/servo" checkout --quiet --detach FETCH_HEAD

mkdir -p "$DEST"
cp -R "$TEMP_DIR/servo/tests/." "$DEST/"
test -f "$SENTINEL"
echo "Restored Servo test corpus at $SERVO_REV"
