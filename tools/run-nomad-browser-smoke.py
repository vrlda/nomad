#!/usr/bin/env python3
"""Exercise the native browser's everyday navigation path through WebDriver."""

from __future__ import annotations

import argparse
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: Any) -> None:
        return


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def webdriver_request(base_url: str, method: str, path: str, payload: Any = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        base_url + path,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError) as error:
        detail = (
            error.read().decode("utf-8", errors="replace")
            if isinstance(error, HTTPError)
            else str(error)
        )
        raise RuntimeError(f"WebDriver {method} {path} failed: {detail}") from error
    if isinstance(result, dict) and result.get("error"):
        raise RuntimeError(f"WebDriver {method} {path} failed: {result}")
    return result


def wait_for_webdriver(base_url: str, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            webdriver_request(base_url, "GET", "/status")
            return
        except (OSError, RuntimeError) as error:
            last_error = error
            if process.poll() is not None:
                raise RuntimeError(
                    f"Nomad exited before WebDriver became available: {process.returncode}"
                ) from error
            time.sleep(0.1)
    raise RuntimeError(f"Nomad WebDriver did not start: {last_error}")


def wait_for_source_marker(
    base_url: str,
    session_id: str,
    marker: str,
    timeout: float,
    description: str,
) -> str:
    deadline = time.monotonic() + timeout
    last_source = ""
    while time.monotonic() < deadline:
        try:
            response = webdriver_request(
                base_url, "GET", f"/session/{session_id}/source"
            )
            last_source = response.get("value", "")
            if marker in last_source:
                return last_source
        except RuntimeError:
            # pageLoadStrategy=none intentionally allows this request to race
            # the renderer while a navigation is still being committed.
            pass
        time.sleep(0.1)
    raise RuntimeError(
        f"{description} did not complete; source tail: {last_source[-300:]}"
    )


def assert_title(base_url: str, session_id: str, expected: str) -> None:
    actual = webdriver_request(base_url, "GET", f"/session/{session_id}/title")
    if actual.get("value") != expected:
        raise RuntimeError(f"expected title {expected!r}, got {actual!r}")


def execute_script(base_url: str, session_id: str, script: str) -> Any:
    response = webdriver_request(
        base_url,
        "POST",
        f"/session/{session_id}/execute/sync",
        {"script": script, "args": []},
    )
    return response.get("value")


def find_element(base_url: str, session_id: str, selector: str) -> str:
    element = webdriver_request(
        base_url,
        "POST",
        f"/session/{session_id}/element",
        {"using": "css selector", "value": selector},
    )
    element_id = element["value"].get(
        "element-6066-11e4-a52e-4f735466cecf",
        element["value"].get("ELEMENT"),
    )
    if not element_id:
        raise RuntimeError(f"element response did not contain an ID: {element}")
    return str(element_id)


def wait_for_script(
    base_url: str,
    session_id: str,
    script: str,
    predicate: Any,
    timeout: float,
    description: str,
) -> Any:
    deadline = time.monotonic() + timeout
    last_value: Any = None
    while time.monotonic() < deadline:
        try:
            last_value = execute_script(base_url, session_id, script)
            if predicate(last_value):
                return last_value
        except RuntimeError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{description} did not complete; last value: {last_value!r}")


def navigate_and_check(
    base_url: str,
    session_id: str,
    url: str,
    marker: str,
    title: str,
    description: str,
    timeout: float,
) -> None:
    webdriver_request(base_url, "POST", f"/session/{session_id}/url", {"url": url})
    wait_for_source_marker(base_url, session_id, marker, timeout, description)
    assert_title(base_url, session_id, title)


def run(binary: Path, timeout: float) -> None:
    if not binary.is_file():
        raise RuntimeError(f"native Nomad binary not found: {binary}")

    with tempfile.TemporaryDirectory(prefix="nomad-browser-smoke-") as directory:
        root = Path(directory)
        (root / "first.html").write_text(
            "<!doctype html><title>Nomad first</title>"
            "<main><h1>First page</h1><button id='next' "
            "onclick=\"location.href='/second.html'\">Next</button></main>",
            encoding="utf-8",
        )
        (root / "second.html").write_text(
            "<!doctype html><title>Nomad second</title>"
            "<main><h1>Second page</h1><p>Navigation works.</p></main>",
            encoding="utf-8",
        )
        (root / "compatibility.html").write_text(
            """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nomad compatibility</title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; min-width: 0; }
body { font: 16px system-ui, sans-serif; }
#layout-state::after { content: "wide"; }
.flex-shell { display: flex; width: 100%; min-width: 0; }
.fixture-sidebar { flex: 0 0 180px; }
.fixture-content { flex: 1 1 auto; min-width: 0; max-width: 100%; }
.responsive-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.responsive-grid > div { min-width: 0; overflow-wrap: anywhere; }
.spacer { height: 2400px; }
@media (max-width: 700px) {
  #layout-state::after { content: "compact"; }
  .fixture-sidebar { flex-basis: 96px; }
  .responsive-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<main class="flex-shell" data-marker="compat-ready">
  <aside class="fixture-sidebar">Sidebar</aside>
  <section class="fixture-content">
    <strong id="layout-state"></strong>
    <label for="name">Name</label><input id="name" autocomplete="off">
    <div class="responsive-grid"><div>alpha</div><div>beta</div><div>gamma</div></div>
    <canvas id="canvas" width="8" height="8"></canvas>
    <svg id="vector" width="120" height="40" viewBox="0 0 120 40">
      <rect x="5" y="5" width="110" height="30" rx="6"></rect>
    </svg>
    <div class="spacer"></div>
    <button id="bottom" onclick="document.body.dataset.bottomClicked='yes'">Bottom action</button>
  </section>
</main>
<script>
const context = document.querySelector('#canvas').getContext('2d');
context.fillStyle = 'rgb(20, 40, 60)';
context.fillRect(0, 0, 8, 8);
document.documentElement.dataset.ready = 'yes';
</script>
</body>
</html>""",
            encoding="utf-8",
        )
        handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(root), **kwargs)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        server_port = server.server_address[1]

        webdriver_port = free_loopback_port()
        webdriver_base = f"http://127.0.0.1:{webdriver_port}"
        log_path = root / "nomad.log"
        with log_path.open("wb") as log_file:
            process = subprocess.Popen(
                [
                    str(binary),
                    "--new-session",
                    "--webdriver",
                    str(webdriver_port),
                    "about:blank",
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            session_id: str | None = None
            succeeded = False
            try:
                wait_for_webdriver(webdriver_base, process, timeout)
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
                first_url = f"http://127.0.0.1:{server_port}/first.html"
                second_url = f"http://127.0.0.1:{server_port}/second.html"

                navigate_and_check(
                    webdriver_base,
                    session_id,
                    first_url,
                    "First page",
                    "Nomad first",
                    "first page navigation",
                    timeout,
                )
                print("Initial navigation passed")

                element_id = find_element(webdriver_base, session_id, "#next")
                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/element/{element_id}/click",
                    {},
                )
                wait_for_source_marker(
                    webdriver_base,
                    session_id,
                    "Second page",
                    timeout,
                    "button navigation",
                )
                assert_title(webdriver_base, session_id, "Nomad second")
                print("Real page interaction passed")

                webdriver_request(webdriver_base, "POST", f"/session/{session_id}/back", {})
                wait_for_source_marker(
                    webdriver_base, session_id, "First page", timeout, "back navigation"
                )
                assert_title(webdriver_base, session_id, "Nomad first")
                webdriver_request(
                    webdriver_base, "POST", f"/session/{session_id}/forward", {}
                )
                wait_for_source_marker(
                    webdriver_base, session_id, "Second page", timeout, "forward navigation"
                )
                assert_title(webdriver_base, session_id, "Nomad second")
                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/refresh",
                    {},
                )
                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/refresh",
                    {},
                )
                wait_for_source_marker(
                    webdriver_base,
                    session_id,
                    "Second page",
                    timeout,
                    "rapid reload navigation",
                )
                assert_title(webdriver_base, session_id, "Nomad second")
                print("Back, forward, and rapid double reload passed")

                value = execute_script(
                    webdriver_base,
                    session_id,
                    "return {title: document.title, text: document.querySelector('main').innerText};",
                )
                if value.get("title") != "Nomad second" or "Navigation works." not in value.get(
                    "text", ""
                ):
                    raise RuntimeError(f"DOM script evaluation returned an unexpected value: {value}")
                print("DOM script evaluation passed")

                compatibility_url = (
                    f"http://127.0.0.1:{server_port}/compatibility.html"
                )
                navigate_and_check(
                    webdriver_base,
                    session_id,
                    compatibility_url,
                    "compat-ready",
                    "Nomad compatibility",
                    "compatibility fixture navigation",
                    timeout,
                )
                wait_for_script(
                    webdriver_base,
                    session_id,
                    "return document.documentElement.dataset.ready;",
                    lambda result: result == "yes",
                    timeout,
                    "compatibility fixture initialization",
                )
                compatibility = execute_script(
                    webdriver_base,
                    session_id,
                    """return {
                      innerWidth,
                      clientWidth: document.documentElement.clientWidth,
                      scrollWidth: document.documentElement.scrollWidth,
                      contentRight: document.querySelector('.fixture-content').getBoundingClientRect().right,
                      layout: getComputedStyle(document.querySelector('#layout-state'), '::after').content,
                      columns: getComputedStyle(document.querySelector('.responsive-grid')).gridTemplateColumns,
                      pixel: Array.from(document.querySelector('#canvas').getContext('2d').getImageData(0, 0, 1, 1).data),
                      svgViewportWidth: document.querySelector('#vector').getBoundingClientRect().width,
                      svgGeometryWidth: document.querySelector('#vector rect').getBoundingClientRect().width,
                      svgBBoxSupported: typeof document.querySelector('#vector rect').getBBox === 'function'
                    };""",
                )
                if compatibility["pixel"] != [20, 40, 60, 255]:
                    raise RuntimeError(f"canvas pixels were incorrect: {compatibility}")
                if compatibility["svgViewportWidth"] != 120:
                    raise RuntimeError(f"SVG viewport sizing was incorrect: {compatibility}")
                if compatibility["svgGeometryWidth"] == 0:
                    print("SVG child client geometry remains unsupported")
                if not compatibility["svgBBoxSupported"]:
                    print("SVG viewport passed; SVGGraphicsElement.getBBox remains unsupported")
                if compatibility["scrollWidth"] > compatibility["clientWidth"] + 1:
                    raise RuntimeError(f"wide layout overflowed horizontally: {compatibility}")
                if compatibility["contentRight"] > compatibility["innerWidth"] + 1:
                    raise RuntimeError(f"flex content exceeded the viewport: {compatibility}")
                print("Flex, canvas, and SVG viewport compatibility passed")

                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/window/rect",
                    {"width": 860, "height": 560},
                )
                compact = wait_for_script(
                    webdriver_base,
                    session_id,
                    """return {
                      innerWidth,
                      clientWidth: document.documentElement.clientWidth,
                      scrollWidth: document.documentElement.scrollWidth,
                      contentRight: document.querySelector('.fixture-content').getBoundingClientRect().right,
                      layout: getComputedStyle(document.querySelector('#layout-state'), '::after').content,
                      columns: getComputedStyle(document.querySelector('.responsive-grid')).gridTemplateColumns
                    };""",
                    lambda result: result
                    and result.get("innerWidth", 10000) <= 700
                    and result.get("layout") == '"compact"',
                    timeout,
                    "compact responsive resize",
                )
                if compact["scrollWidth"] > compact["clientWidth"] + 1:
                    raise RuntimeError(f"compact layout overflowed horizontally: {compact}")
                if compact["contentRight"] > compact["innerWidth"] + 1:
                    raise RuntimeError(f"compact flex content exceeded the viewport: {compact}")

                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/window/rect",
                    {"width": 1400, "height": 900},
                )
                expanded = wait_for_script(
                    webdriver_base,
                    session_id,
                    "return {innerWidth, layout: getComputedStyle(document.querySelector('#layout-state'), '::after').content};",
                    lambda result: result
                    and result.get("innerWidth", 0) > 700
                    and result.get("layout") == '"wide"',
                    timeout,
                    "expanded responsive resize",
                )
                if expanded["layout"] != '"wide"':
                    raise RuntimeError(f"expanded layout did not restore: {expanded}")
                print("Responsive native resize passed")

                name_id = find_element(webdriver_base, session_id, "#name")
                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/element/{name_id}/value",
                    {"text": "Nomad input", "value": list("Nomad input")},
                )
                input_value = wait_for_script(
                    webdriver_base,
                    session_id,
                    "return document.querySelector('#name').value;",
                    lambda result: result == "Nomad input",
                    timeout,
                    "text input delivery",
                )
                if input_value != "Nomad input":
                    raise RuntimeError(f"text input failed: {input_value!r}")

                bottom_id = find_element(webdriver_base, session_id, "#bottom")
                webdriver_request(
                    webdriver_base,
                    "POST",
                    f"/session/{session_id}/element/{bottom_id}/click",
                    {},
                )
                interaction = execute_script(
                    webdriver_base,
                    session_id,
                    "return {clicked: document.body.dataset.bottomClicked, scrollY};",
                )
                if interaction.get("clicked") != "yes" or interaction.get("scrollY", 0) < 500:
                    raise RuntimeError(f"offscreen click or scrolling failed: {interaction}")
                print("Text input, scrolling, and offscreen interaction passed")

                execute_script(
                    webdriver_base,
                    session_id,
                    "localStorage.setItem('nomad-smoke', 'persistent'); sessionStorage.setItem('nomad-session', 'reload'); return true;",
                )
                webdriver_request(
                    webdriver_base, "POST", f"/session/{session_id}/refresh", {}
                )
                wait_for_source_marker(
                    webdriver_base,
                    session_id,
                    "compat-ready",
                    timeout,
                    "compatibility fixture reload",
                )
                storage = wait_for_script(
                    webdriver_base,
                    session_id,
                    "return {local: localStorage.getItem('nomad-smoke'), session: sessionStorage.getItem('nomad-session')};",
                    lambda result: result and result.get("local") == "persistent",
                    timeout,
                    "storage persistence",
                )
                if storage.get("session") != "reload":
                    raise RuntimeError(f"session storage did not survive reload: {storage}")
                print("Local and session storage reload persistence passed")
                succeeded = True
            finally:
                if session_id is not None:
                    try:
                        webdriver_request(
                            webdriver_base,
                            "DELETE",
                            f"/session/{session_id}/servo/shutdown",
                        )
                    except RuntimeError:
                        try:
                            webdriver_request(
                                webdriver_base, "DELETE", f"/session/{session_id}"
                            )
                        except RuntimeError:
                            pass
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if not succeeded:
                    print(log_path.read_text(encoding="utf-8", errors="replace")[-4000:])

        server.shutdown()
        server_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--timeout", type=float, default=20.0)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
