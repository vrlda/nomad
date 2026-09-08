#!/usr/bin/env python3
"""Validate Nomad's native media playback on macOS through WebDriver.

Serves WPT media fixtures over loopback HTTP, loads them in <video>/<audio>
elements with a WebVTT track, and asserts decode-level facts through script
execution: readyState, decoded video dimensions, playback progress, seeking,
caption cues, and audio duration.

This is separate from the WPT harness because Servo's manifest covers only a
curated test subset; these fixtures exercise the GStreamer decode path
directly in the shipped macOS binary.
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


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"
FIXTURES = (
    REPOSITORY_ROOT / "vendor" / "servo" / "tests" / "wpt" / "tests" / "media"
)
PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Nomad media fixtures</title></head>
<body>
<video id="mp4" src="movie_5.mp4" preload="auto"></video>
<video id="webm" src="movie_5.webm" preload="auto"></video>
<audio id="mp3" src="sine440.mp3" preload="auto"></audio>
<video id="captioned" src="movie_5.mp4" preload="auto">
<track id="track" kind="subtitles" srclang="en" src="foo.vtt" default>
</video>
<script>
window.__nomadMediaState = () => {
  const pick = (id) => {
    const el = document.getElementById(id);
    return {
      readyState: el.readyState,
      width: el.videoWidth || 0,
      height: el.videoHeight || 0,
      time: el.currentTime,
      duration: el.duration,
      error: el.error ? el.error.code : 0,
    };
  };
  const track = document.getElementById("track").track;
  return {
    mp4: pick("mp4"),
    webm: pick("webm"),
    mp3: pick("mp3"),
    captioned: pick("captioned"),
    cues: track ? track.cues.length : -1,
  };
};
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
    response = webdriver_request(
        base_url,
        "POST",
        f"/session/{session_id}/execute/sync",
        {"script": script, "args": []},
    )
    return response.get("value")


def wait_for(condition, timeout: float, description: str) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = condition()
        if last:
            return last
        time.sleep(0.2)
    raise RuntimeError(f"{description} timed out; last state: {last!r}")


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def run(binary: Path, timeout: float) -> dict:
    for name in ("movie_5.mp4", "movie_5.webm", "sine440.mp3", "foo.vtt"):
        if not (FIXTURES / name).is_file():
            raise RuntimeError(f"missing media fixture: {name}")
    with tempfile.TemporaryDirectory(prefix="nomad-media-smoke-") as directory:
        root = Path(directory)
        (root / "index.html").write_text(PAGE, encoding="utf-8")
        for name in ("movie_5.mp4", "movie_5.webm", "sine440.mp3", "foo.vtt"):
            (root / name).write_bytes((FIXTURES / name).read_bytes())

        handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(root), **kwargs)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        server_port = server.server_address[1]

        webdriver_port = free_loopback_port()
        webdriver_base = f"http://127.0.0.1:{webdriver_port}"
        process = subprocess.Popen(
            [str(binary), "--webdriver", str(webdriver_port), "about:blank"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        session_id = None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    webdriver_request(webdriver_base, "GET", "/status")
                    break
                except (OSError, RuntimeError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("Nomad WebDriver did not start")

            session = webdriver_request(
                webdriver_base, "POST", "/session",
                {"capabilities": {"alwaysMatch": {"pageLoadStrategy": "none"}, "firstMatch": []}},
            )
            session_id = session["value"]["sessionId"]
            webdriver_request(
                webdriver_base, "POST", f"/session/{session_id}/url",
                {"url": f"http://127.0.0.1:{server_port}/index.html"},
            )

            def loaded() -> dict | None:
                try:
                    state = execute_script(webdriver_base, session_id, "return window.__nomadMediaState();")
                except RuntimeError:
                    return None
                if not state or state["mp4"]["readyState"] < 2:
                    return None
                return state

            state = wait_for(loaded, timeout, "mp4 metadata/decode")
            checks: dict = {}

            # Codec decode: mp4 (H.264), webm (VP8/VP9), mp3 audio.
            checks["mp4_decodes"] = state["mp4"]["width"] > 0 and state["mp4"]["error"] == 0
            webm = execute_script(webdriver_base, session_id, "return window.__nomadMediaState().webm;")
            checks["webm_decodes"] = webm["width"] > 0 and webm["error"] == 0
            mp3 = execute_script(webdriver_base, session_id, "return window.__nomadMediaState().mp3;")
            checks["mp3_decodes"] = (mp3["duration"] or 0) > 0 and mp3["error"] == 0

            # Playback progress on the mp4 element.
            execute_script(webdriver_base, session_id, "document.getElementById('mp4').play();")
            time.sleep(1.5)
            progressed = execute_script(webdriver_base, session_id, "return window.__nomadMediaState().mp4;")
            checks["playback_progresses"] = progressed["time"] > 0

            # Seeking.
            execute_script(
                webdriver_base, session_id,
                "const v = document.getElementById('mp4'); v.pause(); v.currentTime = Math.min(2, (v.duration || 3) / 2);",
            )
            time.sleep(1.0)
            seeked = execute_script(webdriver_base, session_id, "return window.__nomadMediaState().mp4;")
            checks["seeking_works"] = seeked["time"] > 0.05 and seeked["error"] == 0

            # Captions: WebVTT cue parsing on the captioned element.
            def cues_ready() -> dict | None:
                current = execute_script(webdriver_base, session_id, "return window.__nomadMediaState();")
                if current and current["cues"] > 0:
                    return current
                return None

            captioned = wait_for(cues_ready, timeout, "caption cues")
            checks["captions_parse"] = captioned["cues"] > 0

            failed = sorted(name for name, ok in checks.items() if not ok)
            if failed:
                raise RuntimeError(f"media checks failed: {failed}; state={state!r}")
            print(f"Media smoke passed: {sorted(checks)}")
            return {"checks": checks, "state": state}
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
