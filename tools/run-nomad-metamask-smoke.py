#!/usr/bin/env python3
"""Exercise a real MetaMask package against a live local dApp.

This is intentionally an opt-in native smoke test.  It installs the pinned
MetaMask release through Nomad's native startup path, navigates to a local
page, and checks the provider injection, chain query, event listener, and
expected unauthenticated transaction failure paths through WebDriver.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import threading
import time
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"
DEFAULT_ARCHIVE = (
    REPOSITORY_ROOT / "tools" / "metamask" / "metamask-chrome-13.44.0.zip"
)


DAPP_HTML = """<!doctype html>
<meta charset="utf-8">
<title>Nomad MetaMask dApp smoke</title>
<h1>Nomad MetaMask dApp smoke</h1>
<script>
window.__nomadWallet = { injected: false, isMetaMask: false, events: [], listeners: 0 };
(function () {
  const state = window.__nomadWallet;
  const provider = window.ethereum;
  if (!provider) return;
  state.injected = true;
  state.isMetaMask = provider.isMetaMask === true;
  for (const eventName of ["chainChanged", "accountsChanged", "message"]) {
    provider.on(eventName, (value) => state.events.push({ event: eventName, value }));
    state.listeners += 1;
  }
})();
</script>
"""


class DappHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/" and self.path != "/index.html":
            self.send_error(404)
            return
        body = DAPP_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def webdriver_request(
    base_url: str, method: str, path: str, payload: Any = None
) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        base_url + path,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError) as error:
        detail = (
            error.read().decode("utf-8", errors="replace")
            if isinstance(error, HTTPError)
            else str(error)
        )
        raise RuntimeError(f"WebDriver {method} {path} failed: {detail}") from error


def wait_for_webdriver(base_url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            webdriver_request(base_url, "GET", "/status")
            return
        except (OSError, RuntimeError) as error:
            last_error = error
            time.sleep(0.1)
    raise RuntimeError(f"Nomad WebDriver did not start: {last_error}")


def execute_script(base_url: str, session_id: str, script: str) -> Any:
    response = webdriver_request(
        base_url,
        "POST",
        f"/session/{session_id}/execute/sync",
        {"script": script, "args": []},
    )
    return response.get("value")


def wait_for_provider(
    base_url: str, session_id: str, timeout: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_state: dict[str, Any] = {}
    while time.monotonic() < deadline:
        state = execute_script(
            base_url,
            session_id,
            "return Object.assign({}, window.__nomadWallet || {});",
        )
        if isinstance(state, dict):
            last_state = state
            if state.get("injected"):
                return state
        time.sleep(0.2)
    raise RuntimeError(f"MetaMask provider was not injected: {last_state}")


def run(binary: Path, archive: Path, timeout: float) -> None:
    if not binary.is_file():
        raise RuntimeError(f"native Nomad binary not found: {binary}")
    if not archive.is_file():
        raise RuntimeError(f"MetaMask archive not found: {archive}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), DappHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    webdriver_port = free_loopback_port()
    webdriver_base = f"http://127.0.0.1:{webdriver_port}"
    dapp_url = f"http://127.0.0.1:{server.server_address[1]}/"
    log_file = tempfile.NamedTemporaryFile(prefix="nomad-metamask-", suffix=".log")
    process = subprocess.Popen(
        [
            str(binary),
            "--new-session",
            "--extension-archive",
            str(archive),
            "--webdriver",
            str(webdriver_port),
            dapp_url,
        ],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    session_id: str | None = None
    succeeded = False
    try:
        wait_for_webdriver(webdriver_base, timeout)
        session = webdriver_request(
            webdriver_base,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {"pageLoadStrategy": "none"},
                    "firstMatch": [],
                }
            },
        )
        session_id = session["value"]["sessionId"]
        state = wait_for_provider(webdriver_base, session_id, timeout)
        if not state.get("isMetaMask"):
            raise RuntimeError(f"provider was injected but isMetaMask was false: {state}")
        if state.get("listeners") != 3:
            raise RuntimeError(f"provider event listeners were not installed: {state}")
        chain_state = execute_script(
            webdriver_base,
            session_id,
            """
            const wallet = window.__nomadWallet || {};
            return Promise.race([
              window.ethereum.request({method: "eth_chainId"})
                .then((value) => ({chainId: value}))
                .catch((error) => ({chainIdError: String(error && (error.message || error))})),
              new Promise((resolve) => setTimeout(() => resolve({chainIdTimeout: true}), 3000))
            ]).then((result) => Object.assign({}, wallet, result));
            """,
        )
        if not isinstance(chain_state, dict) or not str(chain_state.get("chainId", "")).startswith("0x"):
            raise RuntimeError(f"eth_chainId did not produce a provider result: {chain_state}")

        failure = execute_script(
            webdriver_base,
            session_id,
            """
            const provider = window.ethereum;
            return Promise.race([
              provider.request({method: "eth_sendTransaction", params: [{}]})
                .then(() => ({ settled: true, error: false }))
                .catch((error) => ({ settled: true, error: String(error && (error.message || error)) })),
              new Promise((resolve) => setTimeout(() => resolve({ settled: false }), 2000))
            ]);
            """,
        )
        if not isinstance(failure, dict) or not failure.get("settled") or not failure.get("error"):
            raise RuntimeError(f"unauthenticated transaction did not fail cleanly: {failure}")

        print(
            "MetaMask dApp smoke passed: provider injection, event listeners, "
            f"chainId={state['chainId']}, and transaction failure ({failure['error']})"
        )
        succeeded = True
    finally:
        if session_id is not None:
            try:
                webdriver_request(webdriver_base, "DELETE", f"/session/{session_id}")
            except RuntimeError:
                pass
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if not succeeded:
            log_file.seek(0)
            print(log_file.read().decode("utf-8", errors="replace")[-6000:])
        log_file.close()
        server.shutdown()
        server_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--timeout", type=float, default=30.0)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.archive.resolve(), arguments.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
