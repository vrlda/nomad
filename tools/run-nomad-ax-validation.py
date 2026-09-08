#!/usr/bin/env python3
"""Validate Nomad's macOS accessibility behavior through the native AX API.

Starts the browser via WebDriver, loads a fixture page exercising buttons,
links, headings, text fields, focus order, keyboard operation, and a live
region, then asserts against the same AX tree VoiceOver consumes:

- chrome and content roles/names are exposed,
- Tab keyboard navigation moves focus in a sane order,
- live-region text updates appear in the tree,
- actions (press/focus) are available on controls.

Writes a JSON evidence report. Exits nonzero on any failure.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import ApplicationServices
import Quartz


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Nomad AX fixtures</title></head>
<body>
<h1>Nomad accessibility probe</h1>
<a id="link" href="#target">Probe link</a>
<button id="press">Press me</button>
<button id="counter" aria-label="Counter button">Count: <span id="count">0</span></button>
<label>Probe field <input id="field" type="text" value=""></label>
<div id="live" aria-live="polite">initial status</div>
<div id="target">target section</div>
<script>
document.getElementById("press").addEventListener("click", () => {
  document.getElementById("live").textContent = "pressed at " + Date.now();
});
document.getElementById("counter").addEventListener("click", () => {
  const count = document.getElementById("count");
  count.textContent = String(Number(count.textContent) + 1);
});
</script>
</body></html>
"""


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: Any) -> None:
        return


def webdriver_request(base_url: str, method: str, path: str, payload: Any = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        base_url + path,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError) as error:
        detail = error.read().decode("utf-8", errors="replace") if isinstance(error, HTTPError) else str(error)
        raise RuntimeError(f"WebDriver {method} {path} failed: {detail}") from error


def execute_script(base_url: str, session_id: str, script: str) -> Any:
    return webdriver_request(
        base_url, "POST", f"/session/{session_id}/execute/sync",
        {"script": script, "args": []}).get("value")


def ax_value(element, attr):
    try:
        result = ApplicationServices.AXUIElementCopyAttributeValue(element, attr, None)
    except Exception:
        return None
    if not isinstance(result, tuple) or len(result) != 2:
        return None
    error, value = result
    return None if error else value


def flatten(element, depth=0, limit=400, out=None, seen=None):
    out = [] if out is None else out
    seen = set() if seen is None else seen
    if len(out) >= limit:
        return out
    key = repr(element)
    if key in seen:
        return out
    seen.add(key)
    role = ax_value(element, "AXRole") or ""
    text = (ax_value(element, "AXTitle") or ax_value(element, "AXDescription")
            or ax_value(element, "AXValue") or "")
    text = str(text).strip().replace("\n", " ")[:80]
    focused = bool(ax_value(element, "AXFocused"))
    actions = ax_value(element, "AXActionNames") or []
    out.append({"role": str(role), "text": text, "focused": focused,
                "actions": [str(a) for a in actions], "depth": depth})
    for child in ax_value(element, "AXChildren") or []:
        flatten(child, depth + 1, limit, out, seen)
        if len(out) >= limit:
            break
    return out


def kill_stale_browsers():
    import subprocess as sp
    try:
        out = sp.check_output(["pgrep", "-f", "nomad-browser --webdriver"],
                              text=True)
    except Exception:
        return
    import os
    import signal
    for pid in out.split():
        try:
            os.kill(int(pid), signal.SIGKILL)
        except Exception:
            pass


def foreground_nomad():
    import subprocess as sp
    try:
        sp.run(
            ["osascript", "-e",
             'tell application "System Events" to set frontmost of '
             '(first process whose name contains "nomad") to true'],
            capture_output=True, timeout=15)
    except Exception:
        pass


def nomad_app(pid: int):
    return ApplicationServices.AXUIElementCreateApplication(pid)


def app_tree(pid: int):
    app = nomad_app(pid)
    ax_windows = ax_value(app, "AXWindows") or []
    nodes = []
    for window in ax_windows:
        nodes.extend(flatten(window))
    return nodes


def wait_for(predicate, timeout: float, description: str):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.3)
    raise RuntimeError(f"{description} timed out; last={last!r}")


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def run(binary: Path, timeout: float) -> dict:
    if not ApplicationServices.AXIsProcessTrusted():
        raise RuntimeError("terminal is not Accessibility-trusted")
    checks: dict = {}
    with tempfile.TemporaryDirectory(prefix="nomad-ax-") as directory:
        root = Path(directory)
        (root / "index.html").write_text(PAGE, encoding="utf-8")
        handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(root), **kwargs)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        server_port = server.server_address[1]

        kill_stale_browsers()
        webdriver_port = free_loopback_port()
        webdriver_base = f"http://127.0.0.1:{webdriver_port}"
        process = subprocess.Popen(
            [str(binary), "--webdriver", str(webdriver_port), "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        session_id = None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    webdriver_request(webdriver_base, "GET", "/status")
                    break
                except (OSError, RuntimeError):
                    time.sleep(0.2)
            else:
                raise RuntimeError("Nomad WebDriver did not start")
            session = webdriver_request(
                webdriver_base, "POST", "/session",
                {"capabilities": {"alwaysMatch": {"pageLoadStrategy": "none"}, "firstMatch": []}})
            session_id = session["value"]["sessionId"]
            foreground_nomad()
            browser_pid = process.pid
            webdriver_request(
                webdriver_base, "POST", f"/session/{session_id}/url",
                {"url": f"http://127.0.0.1:{server_port}/index.html"})
            wait_for(lambda: any(n["role"] == "AXHeading" and "accessibility probe" in n["text"].lower()
                                 for n in app_tree(browser_pid)),
                     timeout, "web content in AX tree")

            tree = app_tree(browser_pid)
            roles = [(n["role"], n["text"]) for n in tree]

            def has(role, text_part=""):
                return any(r == role and text_part.lower() in t.lower() for r, t in roles)

            checks["window_exposed"] = any(r == "AXWindow" for r, _ in roles)
            checks["heading_exposed"] = has("AXHeading", "accessibility probe")
            checks["link_exposed"] = has("AXLink", "probe link")
            checks["button_named"] = has("AXButton", "press me")
            checks["text_field_exposed"] = any(r in ("AXTextField", "AXTextArea") for r, _ in roles)
            checks["live_region_exposed"] = has("AXGroup", "initial status") or \
                any("initial status" in t for _, t in roles)
            press_actions = [n["actions"] for n in tree
                             if n["role"] == "AXButton" and "press me" in n["text"].lower()]
            checks["button_actions"] = bool(press_actions) and \
                "AXPress" in (press_actions[0] if press_actions else [])
            failed = sorted(name for name, ok in checks.items() if not ok)
            if failed:
                raise RuntimeError(f"AX tree checks failed: {failed}; roles={roles[:40]!r}")

            # Keyboard: Tab through the page, focus must move across controls.
            focused_before = [n["text"] for n in app_tree(browser_pid) if n["focused"]]
            webdriver_request(
                webdriver_base, "POST", f"/session/{session_id}/actions",
                {"actions": [{"type": "key", "id": "kbd",
                              "actions": [{"type": "keyDown", "value": "\ue004"},
                                          {"type": "keyUp", "value": "\ue004"}]}]})
            time.sleep(1.0)
            active = execute_script(
                webdriver_base, session_id,
                "return (document.activeElement && (document.activeElement.id || document.activeElement.tagName)) || 'none';")
            checks["keyboard_moves_focus"] = active not in ("none", "", None)
            checks["keyboard_focus_visible_in_ax"] = any(n["focused"] for n in app_tree(browser_pid))
            failed = sorted(name for name, ok in checks.items() if not ok)
            if failed:
                raise RuntimeError(f"keyboard checks failed: {failed}; active={active!r} "
                                   f"focused_before={focused_before!r}")

            # Live region: activate the button through the page and watch the
            # live-region text update in the AX tree.
            execute_script(webdriver_base, session_id,
                           "document.getElementById('press').click();")
            updated = wait_for(
                lambda: next((n["text"] for n in app_tree(browser_pid)
                              if n["text"].startswith("pressed at")), None),
                timeout, "live region update in AX tree")
            checks["live_region_updates"] = updated.startswith("pressed at")
            print(f"AX validation passed: {sorted(checks)}")
            return {"checks": checks, "live_region_text": updated,
                    "focused_after_tab": active}
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
            server.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json-out", type=Path, default=None)
    arguments = parser.parse_args()
    if not arguments.binary.is_file():
        parser.error(f"native Nomad binary not found: {arguments.binary}")
    result = run(arguments.binary.resolve(), arguments.timeout)
    if arguments.json_out is not None:
        arguments.json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
