#!/usr/bin/env python3
"""Exercise Nomad's native PDF interception through WebDriver.

This is deliberately separate from the WPT test harness: PDF navigation
replaces the top-level document with Nomad's local viewer, so a normal
testharness page cannot remain alive long enough to inspect the result.
"""

from __future__ import annotations

import argparse
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import socket
import tempfile
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"


def build_pdf() -> bytes:
    """Build a small, valid PDF with selectable text and one rendered page."""

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length 49 >>\nstream\nBT /F1 18 Tf 72 700 Td "
        b"(Nomad PDF smoke) Tj ET\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    document = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(document))
        document += f"{number} 0 obj\n".encode("ascii")
        document += obj + b"\nendobj\n"
    xref_offset = len(document)
    document += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    document += b"0000000000 65535 f \n"
    document += b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:])
    document += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return document


def build_large_pdf(pages: int) -> bytes:
    """Build a multi-page PDF with selectable text on every page.

    This exercises bounded loading and navigation of a genuinely large
    document (many pages, repeated text content) through the native viewer.
    """

    page_objects: list[bytes] = []
    for page in range(pages):
        text = " ".join(f"Nomad page {page + 1} content" for _ in range(120))
        content = (
            f"<< /Length {62 + len(text)} >>\nstream\nBT /F1 12 Tf 72 720 Td "
            f"({text}) Tj ET\nendstream"
        ).encode("ascii")
        page_objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents "
            + f"{3 + page} 0 R".encode("ascii")
            + b" >>"
        )

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{' '.join(f'{3 + i} 0 R' for i in range(pages))}] /Count {pages} >>".encode(
            "ascii"
        ),
    ]
    objects.extend(page_objects)
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    document = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(document))
        document += f"{number} 0 obj\n".encode("ascii")
        document += obj + b"\nendobj\n"
    xref_offset = len(document)
    document += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    document += b"0000000000 65535 f \n"
    document += b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:])
    document += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return document


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


def wait_for_viewer(base_url: str, session_id: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last_source = ""
    while time.monotonic() < deadline:
        response = webdriver_request(base_url, "GET", f"/session/{session_id}/source")
        last_source = response.get("value", "")
        if "Find in PDF" in last_source and "application/pdf" in last_source:
            return last_source
        time.sleep(0.1)
    current_url = webdriver_request(base_url, "GET", f"/session/{session_id}/url")
    title = webdriver_request(base_url, "GET", f"/session/{session_id}/title")
    raise RuntimeError(
        "Nomad PDF viewer did not become ready; "
        f"url={current_url.get('value')!r} title={title.get('value')!r} "
        "source tail: "
        + last_source[-200:]
    )


def wait_for_source_marker(
    base_url: str, session_id: str, marker: str, timeout: float, description: str
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
            # The navigation command is asynchronous when pageLoadStrategy is
            # "none"; an early source request is expected to race the load.
            pass
        time.sleep(0.1)
    raise RuntimeError(
        f"{description} did not complete; source tail: {last_source[-200:]}"
    )


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def run(binary: Path, timeout: float) -> None:
    with tempfile.TemporaryDirectory(prefix="nomad-pdf-smoke-") as directory:
        root = Path(directory)
        (root / "control.html").write_text(
            "<!doctype html><title>Nomad control</title><p>control navigation</p>",
            encoding="utf-8",
        )
        (root / "valid.pdf").write_bytes(build_pdf())
        (root / "large.pdf").write_bytes(build_large_pdf(30))
        (root / "invalid.pdf").write_bytes(b"this is not a PDF")

        handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(root), **kwargs)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        server_port = server.server_address[1]

        webdriver_port = free_loopback_port()
        webdriver_base = f"http://127.0.0.1:{webdriver_port}"
        log_path = root / "nomad.log"
        log_file = log_path.open("wb")
        process = subprocess.Popen(
            [
                str(binary),
                "--webdriver",
                str(webdriver_port),
                "about:blank",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        session_id = None
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
            print(f"WebDriver session: {session_id}")
            control_url = f"http://127.0.0.1:{server_port}/control.html"
            webdriver_request(
                webdriver_base,
                "POST",
                f"/session/{session_id}/url",
                {"url": control_url},
            )
            wait_for_source_marker(
                webdriver_base,
                session_id,
                "control navigation",
                timeout,
                "control HTML navigation",
            )
            print("HTML control navigation passed")
            valid_url = f"http://127.0.0.1:{server_port}/valid.pdf"
            invalid_url = f"http://127.0.0.1:{server_port}/invalid.pdf"

            navigation = webdriver_request(
                webdriver_base,
                "POST",
                f"/session/{session_id}/url",
                {"url": valid_url},
            )
            print(f"Navigate valid PDF: {navigation}")
            valid_source = wait_for_viewer(webdriver_base, session_id, timeout)
            if "PDF —" not in valid_source or "renderTextLayer" not in valid_source:
                raise RuntimeError("valid PDF did not produce the Nomad viewer document")

            large_url = f"http://127.0.0.1:{server_port}/large.pdf"
            navigation = webdriver_request(
                webdriver_base,
                "POST",
                f"/session/{session_id}/url",
                {"url": large_url},
            )
            print(f"Navigate large 30-page PDF: {navigation}")
            large_source = wait_for_viewer(webdriver_base, session_id, timeout)
            if "PDF —" not in large_source or "renderTextLayer" not in large_source:
                raise RuntimeError("large PDF did not load the Nomad viewer")
            # The viewer exposes page navigation, download, and print controls.
            for marker in ("previous", "next", "download", "print"):
                if marker not in large_source:
                    raise RuntimeError(f"large PDF viewer is missing the {marker!r} control")
            print("Large PDF: bounded loading and navigation/download/print controls passed")

            navigation = webdriver_request(
                webdriver_base,
                "POST",
                f"/session/{session_id}/url",
                {"url": invalid_url},
            )
            print(f"Navigate invalid PDF: {navigation}")
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                invalid_source = webdriver_request(
                    webdriver_base, "GET", f"/session/{session_id}/source"
                ).get("value", "")
                if "Unable to open this PDF" in invalid_source:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("malformed PDF did not produce the controlled error page")

            print("PDF smoke: valid viewer and malformed-file error path passed")
            succeeded = True
        finally:
            if session_id is not None:
                try:
                    webdriver_request(
                        webdriver_base, "DELETE", f"/session/{session_id}"
                    )
                except RuntimeError:
                    pass
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log_file.close()
            if not succeeded:
                print(log_path.read_text(encoding="utf-8", errors="replace")[-4000:])
            server.shutdown()
            server_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--timeout", type=float, default=20.0)
    arguments = parser.parse_args()
    if not arguments.binary.is_file():
        parser.error(f"native Nomad binary not found: {arguments.binary}")
    run(arguments.binary.resolve(), arguments.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
