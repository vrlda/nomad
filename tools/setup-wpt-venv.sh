#!/usr/bin/env bash
# Create the Python virtual environment used by Nomad's WPT tooling and
# install Servo's pinned requirements into it.
#
# The corpus runner (tools/run-nomad-wpt.py) drives Servo's vendored mach
# runner with this interpreter. Only the Python dependencies needed to run
# testharness WPT tests over the loopback HTTP/HTTPS servers are installed;
# the full `mach bootstrap` system-package step is not required for the
# testharness corpus.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${WPT_VENV_DIR:-$ROOT/tools/.wpt-venv}"
PYTHON_BIN="${PYTHON3:-python3}"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "Creating WPT virtualenv at $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
"$VENV_DIR/bin/python" -m pip install --quiet -r "$ROOT/vendor/servo/python/requirements.txt"
"$VENV_DIR/bin/python" -m pip install --quiet \
  -r "$ROOT/vendor/servo/tests/wpt/tests/tools/wptrunner/requirements.txt" \
  -r "$ROOT/vendor/servo/tests/wpt/tests/tools/wptrunner/requirements_firefox.txt"
# wptserve/wptrunner are part of the vendored WPT tools tree and are injected
# onto sys.path by the mach bootstrap at runtime; pin psutil for the geckordp
# devtools requirement installed above.
"$VENV_DIR/bin/python" -m pip install --quiet "psutil==6.1.0"

echo "WPT venv ready at $VENV_DIR"
"$VENV_DIR/bin/python" -c "import toml, mozlog, mozinfo; print('deps ok')"