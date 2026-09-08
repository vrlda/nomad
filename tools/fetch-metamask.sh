#!/usr/bin/env bash
# Fetch the pinned MetaMask Chrome extension package used by Nomad's wallet
# compatibility validation and verify it against MetaMask's published SHA256.
#
# The package is not committed to the repository; this script downloads it
# into tools/metamask/ (git-ignored) so the ignored MetaMask validation tests
# can run with a real package.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/tools/metamask"
VERSION="v13.44.0"
ASSET="metamask-chrome-13.44.0.zip"
mkdir -p "$DIR"

echo "Downloading MetaMask $VERSION ($ASSET)"
curl -fL --retry 3 -o "$DIR/$ASSET" \
  "https://github.com/MetaMask/metamask-extension/releases/download/$VERSION/$ASSET"

echo "Downloading SHA256SUMS"
curl -fL --retry 3 -o "$DIR/SHA256SUMS" \
  "https://github.com/MetaMask/metamask-extension/releases/download/$VERSION/SHA256SUMS"

(
  cd "$DIR"
  # Verify only our asset; shasum -c exits non-zero because SHA256SUMS also
  # lists the other release assets we do not download.
  shasum -a 256 -c SHA256SUMS 2>/dev/null || true
  if ! grep -F "$ASSET: OK" <(shasum -a 256 -c SHA256SUMS 2>/dev/null || true); then
    expected=$(grep -F "$ASSET" SHA256SUMS | awk '{print $1}')
    actual=$(shasum -a 256 "$ASSET" | awk '{print $1}')
    echo "SHA256 mismatch for $ASSET" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
)

echo "MetaMask package ready at $DIR/$ASSET"
echo "Run the ignored wallet tests with:"
echo "  cargo test -p nomad-shell --test metamask_validation -- --ignored"
echo "Run the native provider smoke with:"
echo "  python3 tools/run-nomad-metamask-smoke.py"
