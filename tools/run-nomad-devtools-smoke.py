#!/usr/bin/env python3
"""Verify the opt-in loopback Servo remote-inspector endpoint."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
from threading import Thread
import time


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "debug" / "nomad-browser"
DEBUGGER_FIXTURE_HTML = b"""<!doctype html>
<html><head><link rel="stylesheet" href="/style.css"></head>
<body>debugger fixture<script>globalThis.nomadDebuggerProbe = 1;</script></body>
</html>"""
DEBUGGER_FIXTURE_CSS = b"body { color: red; }"


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/style.css":
            body = DEBUGGER_FIXTURE_CSS
            content_type = "text/css; charset=utf-8"
        else:
            body = DEBUGGER_FIXTURE_HTML
            content_type = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def read_packet(connection: socket.socket) -> dict:
    length = bytearray()
    while True:
        byte = connection.recv(1)
        if not byte:
            raise RuntimeError("DevTools endpoint closed before its root packet")
        if byte == b":":
            break
        length.extend(byte)
        if len(length) > 20 or not byte.isdigit():
            raise RuntimeError("invalid DevTools packet length prefix")
    size = int(length)
    payload = bytearray()
    while len(payload) < size:
        chunk = connection.recv(size - len(payload))
        if not chunk:
            raise RuntimeError("DevTools endpoint truncated its root packet")
        payload.extend(chunk)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"DevTools root packet was not an object: {value!r}")
    return value


def request(connection: socket.socket, packet: dict) -> dict:
    payload = json.dumps(packet)
    connection.sendall(f"{len(payload)}:{payload}".encode("utf-8"))
    response = read_packet(connection)
    if response.get("error"):
        raise RuntimeError(f"DevTools request failed: {packet} -> {response}")
    return response


def request_final(connection: socket.socket, packet: dict) -> dict:
    payload = json.dumps(packet)
    connection.sendall(f"{len(payload)}:{payload}".encode("utf-8"))
    while True:
        response = read_packet(connection)
        if response.get("type"):
            continue
        if response.get("error"):
            raise RuntimeError(f"DevTools request failed: {packet} -> {response}")
        return response


def run(binary: Path, timeout: float) -> None:
    if not binary.is_file():
        raise RuntimeError(f"native Nomad binary not found: {binary}")
    port = free_port()
    fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    fixture_thread = Thread(target=fixture_server.serve_forever, daemon=True)
    fixture_thread.start()
    fixture_url = f"http://127.0.0.1:{fixture_server.server_port}/fixture.html"
    process = subprocess.Popen(
        [str(binary), "--new-session", "--devtools", str(port), fixture_url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    connection: socket.socket | None = None
    try:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                connection.settimeout(timeout)
                break
            except OSError as error:
                last_error = error
                if process.poll() is not None:
                    raise RuntimeError(
                        f"Nomad exited before DevTools became available: {process.returncode}"
                    ) from error
                time.sleep(0.1)
        if connection is None:
            raise RuntimeError(f"DevTools endpoint did not start: {last_error}")
        root = read_packet(connection)
        if root.get("from") != "root":
            raise RuntimeError(f"unexpected DevTools root actor: {root}")
        time.sleep(1)
        root_info = request(connection, {"to": "root", "type": "getRoot", "id": 1})
        if not all(root_info.get(name) for name in ("deviceActor", "perfActor", "preferenceActor")):
            raise RuntimeError(f"DevTools root did not expose global actors: {root_info}")
        tabs = request(connection, {"to": "root", "type": "listTabs", "id": 2})
        tab_list = tabs.get("tabs")
        if not isinstance(tab_list, list) or not tab_list:
            raise RuntimeError(f"DevTools root did not expose the native tab: {tabs}")
        for _ in range(25):
            if tab_list[0].get("url") == fixture_url:
                break
            time.sleep(0.2)
            tabs = request_final(connection, {"to": "root", "type": "listTabs", "id": 22})
            tab_list = tabs.get("tabs")
            if not isinstance(tab_list, list) or not tab_list:
                raise RuntimeError(f"DevTools root lost the native tab: {tabs}")
        tab_actor = tab_list[0].get("actor")
        if not isinstance(tab_actor, str) or not tab_actor:
            raise RuntimeError(f"DevTools tab descriptor is malformed: {tabs}")
        target = request_final(connection, {"to": tab_actor, "type": "getTarget", "id": 3})
        for _ in range(25):
            frame = target.get("frame")
            if isinstance(frame, dict) and frame.get("url") == fixture_url:
                break
            time.sleep(0.2)
            target = request_final(connection, {"to": tab_actor, "type": "getTarget", "id": 23})
        frame = target.get("frame")
        required_actors = (
            "accessibilityActor",
            "consoleActor",
            "cssPropertiesActor",
            "inspectorActor",
            "styleSheetsActor",
            "threadActor",
        )
        if not isinstance(frame, dict) or not all(frame.get(name) for name in required_actors):
            raise RuntimeError(f"DevTools target did not expose inspector actors: {target}")
        storage_actor = frame.get("storageActor")
        watcher_actor = frame.get("watcherActor")
        if not isinstance(storage_actor, str) or not isinstance(watcher_actor, str):
            raise RuntimeError(f"DevTools target did not expose storage/watcher actors: {target}")
        storage = request(
            connection,
            {"to": storage_actor, "type": "getStoreObjects", "storageType": "localStorage", "id": 5},
        )
        cookies = request(
            connection,
            {"to": storage_actor, "type": "getCookies", "id": 6},
        )
        if not isinstance(storage.get("entries"), list) or not isinstance(cookies.get("cookies"), list):
            raise RuntimeError(f"DevTools storage actor returned malformed data: {storage}, {cookies}")
        inspector = request(
            connection,
            {"to": frame["inspectorActor"], "type": "getWalker", "id": 8},
        )
        walker = inspector.get("walker")
        if not isinstance(walker, dict) or not isinstance(walker.get("actor"), str):
            raise RuntimeError(f"DevTools inspector did not expose a walker actor: {inspector}")
        document_element = request(
            connection,
            {"to": walker["actor"], "type": "documentElement", "id": 9},
        )
        if not isinstance(document_element.get("node"), dict):
            raise RuntimeError(f"DevTools walker returned malformed document element: {document_element}")
        page_style = request(
            connection,
            {"to": frame["inspectorActor"], "type": "getPageStyle", "id": 10},
        )
        if not isinstance(page_style.get("pageStyle"), dict) or not isinstance(
            page_style["pageStyle"].get("actor"), str
        ):
            raise RuntimeError(f"DevTools inspector did not expose page style: {page_style}")
        stylesheets = {}
        stylesheet_forms = []
        stylesheet_edit = "verified"
        for _ in range(25):
            stylesheets = request_final(
                connection,
                {"to": frame["styleSheetsActor"], "type": "getStyleSheets", "id": 16},
            )
            stylesheet_forms = stylesheets.get("styleSheets", [])
            if stylesheet_forms:
                break
            time.sleep(0.2)
        if isinstance(stylesheet_forms, list) and stylesheet_forms:
            resource_id = stylesheet_forms[0].get("resourceId")
            if not isinstance(resource_id, str) or not resource_id:
                raise RuntimeError(f"DevTools stylesheet resource is malformed: {stylesheet_forms[0]}")
            before = request_final(
                connection,
                {
                    "to": frame["styleSheetsActor"],
                    "type": "getText",
                    "resourceId": resource_id,
                    "id": 17,
                },
            )
            before_text = before.get("text", {}).get("initial", "")
            if "red" not in before_text:
                raise RuntimeError(f"DevTools stylesheet actor returned unexpected text: {before}")
            updated = request_final(
                connection,
                {
                    "to": frame["styleSheetsActor"],
                    "type": "setStyleSheetText",
                    "resourceId": resource_id,
                    "text": "body { color: blue; }",
                    "id": 18,
                },
            )
            if updated.get("updated") is not True:
                raise RuntimeError(f"DevTools stylesheet actor did not update text: {updated}")
            after = request_final(
                connection,
                {
                    "to": frame["styleSheetsActor"],
                    "type": "getText",
                    "resourceId": resource_id,
                    "id": 19,
                },
            )
            if "blue" not in after.get("text", {}).get("initial", ""):
                raise RuntimeError(f"DevTools stylesheet text was not persisted: {after}")
        else:
            stylesheet_edit = "safe-noop-empty-document"
            unsupported = request_final(
                connection,
                {
                    "to": frame["styleSheetsActor"],
                    "type": "setStyleSheetText",
                    "resourceId": "1-0",
                    "text": "body { color: blue; }",
                    "id": 18,
                },
            )
            if unsupported.get("updated") is not False:
                raise RuntimeError(
                    f"DevTools stylesheet actor returned an invalid empty-document result: {unsupported}"
                )
        thread_actor = frame["threadActor"]
        request_final(
            connection,
            {"to": thread_actor, "type": "attach", "id": 11},
        )
        sources = request_final(
            connection,
            {"to": thread_actor, "type": "sources", "id": 12},
        )
        source_forms = sources.get("sources")
        if not isinstance(source_forms, list):
            raise RuntimeError(f"DevTools thread actor returned malformed sources: {sources}")
        if source_forms:
            source_actor = source_forms[0].get("actor")
            if not isinstance(source_actor, str) or not source_actor:
                raise RuntimeError(f"DevTools source form is malformed: {source_forms[0]}")
            source = request_final(
                connection,
                {"to": source_actor, "type": "source", "id": 13},
            )
            if not isinstance(source.get("source"), str):
                raise RuntimeError(f"DevTools source actor returned malformed content: {source}")
        request_final(
            connection,
            {
                "to": thread_actor,
                "type": "resume",
                "resumeLimit": {"type": "next"},
                "id": 14,
            },
        )
        request_final(
            connection,
            {
                "to": thread_actor,
                "type": "resume",
                "resumeLimit": {"type": "step"},
                "id": 15,
            },
        )
        request_final(
            connection,
            {
                "to": watcher_actor,
                "type": "watchResources",
                "resourceTypes": ["local-storage", "session-storage", "cookies"],
                "id": 7,
            },
        )
        description = request(
            connection,
            {"to": "root", "type": "protocolDescription", "id": 4},
        )
        if description.get("from") != "root" or not isinstance(
            description.get("types"), dict
        ):
            raise RuntimeError(f"unexpected DevTools protocol description: {description}")
        print(
            json.dumps(
                {
                    "port": port,
                    "root": "root",
                    "protocol": "firefox-rdp-json",
                    "types": sorted(description["types"]),
                    "tabActors": sorted(required_actors),
                    "stylesheetEdit": stylesheet_edit,
                }
            )
        )
    finally:
        if connection is not None:
            connection.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        fixture_server.shutdown()
        fixture_server.server_close()
        fixture_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--timeout", type=float, default=15)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
