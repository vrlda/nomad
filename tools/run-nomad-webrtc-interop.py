#!/usr/bin/env python3
"""Nomad <-> Chrome WebRTC interop: Chrome offers (controlling), Nomad answers.
Proves Nomad's ICE/DTLS/SCTP receive path and data flow against a real peer.
"""
import functools
import json
import os
import queue
import socket
import subprocess
import threading
import time
import urllib.request
import websocket

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NOMAD_BIN = os.environ.get("NOMAD_BINARY", "/Users/danilrybalkin/Desktop/Projects/nomad-browser/target/debug/nomad-browser")
CHROME_BIN = os.environ.get("CHROME_BINARY", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

MAILBOXES = {"to-nomad": queue.Queue(), "to-chrome": queue.Queue()}


class RelayHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        body = self._json()
        if self.path == "/send":
            MAILBOXES[body["to"]].put(body["msg"])
            self._reply({"ok": True})
        else:
            self._reply({}, 404)

    def do_GET(self):
        if self.path == "/blank":
            data = b"<!doctype html><title>blank</title><p>blank</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        # /recv?box=to-nomad&timeout=5 -> {"msg": ...} or {"msg": null}
        from urllib.parse import urlparse, parse_qs
        parts = urlparse(self.path)
        if parts.path == "/recv":
            box = parse_qs(parts.query)["box"][0]
            try:
                msg = MAILBOXES[box].get(timeout=5)
                self._reply({"msg": msg})
            except queue.Empty:
                self._reply({"msg": None})
        else:
            self._reply({}, 404)

    def _reply(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class Nomad:
    def __init__(self, port, log_path="/tmp/nomad-interop-browser.log"):
        self.base = f"http://127.0.0.1:{port}"
        self.log_file = open(log_path, "wb")
        self.proc = subprocess.Popen(
            [NOMAD_BIN, "--webdriver", str(port), "about:blank"],
            stdout=self.log_file, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.req("GET", "/status")
                break
            except OSError:
                time.sleep(0.2)
        self.sid = self.req("POST", "/session", {"capabilities": {
            "alwaysMatch": {}, "firstMatch": []}})["value"]["sessionId"]

    def req(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        r = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"} if data else {}, method=method)
        with urllib.request.urlopen(r, timeout=60) as resp:
            return json.loads(resp.read().decode())

    def js(self, script):
        return self.req("POST", f"/session/{self.sid}/execute/sync",
                        {"script": script, "args": []}).get("value")

    def close(self):
        try:
            self.req("DELETE", f"/session/{self.sid}")
        except OSError:
            pass
        self.proc.terminate()
        self.proc.wait(timeout=10)
        try:
            self.log_file.close()
        except OSError:
            pass


class Chrome:
    def __init__(self, port, dbg, page_url):
        self.proc = subprocess.Popen(
            [CHROME_BIN, "--headless=new", f"--remote-debugging-port={dbg}", "--remote-allow-origins=*",
             "--no-first-run", "--disable-gpu", "--use-fake-device-for-media-stream",
             "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required", page_url],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        tabs = []
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{dbg}/json/list", timeout=5) as resp:
                    all_tabs = json.loads(resp.read().decode())
                    print("targets:", [(t.get("type"), t.get("url")) for t in all_tabs],
                          flush=True)
                    tabs = [t for t in all_tabs
                            if t.get("type") == "page" and "/blank" in t.get("url", "")]
                    if tabs:
                        break
            except OSError:
                pass
            time.sleep(0.3)
        ws_url = tabs[0]["webSocketDebuggerUrl"]
        self.ws = websocket.create_connection(ws_url, timeout=60)
        self.msg_id = 0

    def js(self, script):
        self.msg_id += 1
        mid = self.msg_id
        self.ws.send(json.dumps({"id": mid, "method": "Runtime.evaluate",
                                 "params": {"expression": script,
                                            "awaitPromise": True,
                                            "returnByValue": True}}))
        while True:
            raw = self.ws.recv()
            msg = json.loads(raw)
            if msg.get("id") == mid:
                result = msg["result"]["result"]
                if result.get("subtype") == "error":
                    return f"JSERROR: {result.get('description')}"
                return result.get("value")

    def close(self):
        try:
            self.ws.close()
        except OSError:
            pass
        self.proc.terminate()
        self.proc.wait(timeout=10)


CHROME_PAGE = """window.__log = [];
window.pc = new RTCPeerConnection();
window.pc.onicecandidate = (e) => {
  if (!e.candidate) return;
  fetch(RELAY + "/send", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({to: "to-nomad", msg: {kind: "ice", c: e.candidate}})
  });
};
(async () => {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio: true});
    stream.getTracks().forEach((track) => window.pc.addTrack(track, stream));
    window.__log.push("c-got-audio");
  } catch (e) {
    window.__log.push("c-no-audio:" + e.name);
  }
  const dc = window.pc.createDataChannel("xinterop");
  dc.onopen = () => {
    window.__log.push("c-open");
    dc.send("hello-nomad");
  };
  dc.onmessage = (m) => {
    window.__log.push("c-msg:" + m.data);
  };
  const offer = await window.pc.createOffer();
  await window.pc.setLocalDescription(offer);
  await fetch(RELAY + "/send", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      to: "to-nomad",
      msg: {kind: "offer", sdp: window.pc.localDescription}
    })
  });
  window.__log.push("offer-sent");
})().catch((e) => {
  window.__log.push("ERR:" + e.name);
});
"poll-started"
"""

NOMAD_SETUP = """
window.pcb = new RTCPeerConnection();
window.__nlog = [];
window.pcb.onicecandidate = (e) => {
  if (e.candidate) fetch(RELAY + "/send", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({to: "to-chrome", msg: {kind: "ice", c: e.candidate}})});
};
window.pcb.ondatachannel = (e) => {
  window.__nlog.push("n-dc");
  e.channel.onmessage = (m) => { window.__nlog.push("n-msg:" + m.data); };
  e.channel.onopen = () => { e.channel.send("hello-chrome"); window.__nlog.push("n-open-sent"); };
};
window.pcb.ontrack = (e) => {
  window.__nlog.push("n-track:" + e.track.kind + ":" + e.track.readyState);
};
"nomad-ready"
"""

SYNC_IO = """
function nomadFetch(url, body) {
  const xhr = new XMLHttpRequest();
  xhr.open(body ? "POST" : "GET", url, false);
  if (body) xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(body ? JSON.stringify(body) : null);
  return JSON.parse(xhr.responseText);
}
function nomadSend(to, msg) {
  nomadFetch(RELAY + "/send", {to: to, msg: msg});
}
"""

NOMAD_POLL = """
return (() => {
  const r = nomadFetch(RELAY + "/recv?box=to-nomad");
  if (!r.msg) return "nomad-wait";
  const m = r.msg;
  if (m.kind === "offer") {
    window.__offer = m.sdp;
    return "nomad-offer-seen";
  }
  if (m.kind === "ice" && m.c) {
    (window.__iceQ = window.__iceQ || []).push(m.c);
    return "nomad-ice-queued";
  }
  if (m.kind === "bye") return "nomad-bye";
  return "nomad-unknown";
})()
"""

NOMAD_STEP = """
return (() => {
  const out = [];
  if (window.__offer && !window.__answered) {
    window.__answered = true;
    window.pcb.setRemoteDescription(window.__offer)
      .then(() => window.pcb.createAnswer())
      .then((ans) => window.pcb.setLocalDescription(ans))
      .then(() => {
        nomadSend("to-chrome", {kind: "answer", sdp: {
          type: window.pcb.localDescription.type, sdp: window.pcb.localDescription.sdp}});
        // Flush queued remote candidates now that remote description exists.
        for (const c of (window.__iceQ || [])) {
          window.pcb.addIceCandidate(c).catch(() => {});
        }
        window.__iceQ = [];
      })
      .catch((e) => { window.__nlog.push("n-ans-err:" + e.name); });
    out.push("answering");
  }
  // Opportunistically flush any queued candidates.
  if (window.__answered && (window.__iceQ || []).length) {
    for (const c of window.__iceQ.splice(0)) {
      window.pcb.addIceCandidate(c).catch(() => {});
    }
    out.push("flushed");
  }
  out.push("st=" + window.pcb.connectionState + " log=" + (window.__nlog || []).join("|"));
  return out.join(" ");
})()
"""

CHROME_POLL = """
(() => {
  const r = nomadFetch(RELAY + "/recv?box=to-chrome");
  if (!r.msg) return "chrome-wait";
  const m = r.msg;
  if (m.kind === "answer") {
    window.__answer = m.sdp;
    return "chrome-answer-seen";
  }
  if (m.kind === "ice" && m.c) {
    (window.__iceQ = window.__iceQ || []).push(m.c);
    return "chrome-ice-queued";
  }
  return "chrome-unknown";
})()
"""

CHROME_STEP = """
(() => {
  const out = [];
  if (window.__answer && !window.__applied) {
    window.__applied = true;
    window.pc.setRemoteDescription(window.__answer)
      .then(() => {
        for (const c of (window.__iceQ || [])) {
          window.pc.addIceCandidate(c).catch(() => {});
        }
        window.__iceQ = [];
      })
      .catch((e) => { window.__log.push("c-ans-err:" + e.name); });
    out.push("applying");
  }
  if (window.__applied && (window.__iceQ || []).length) {
    for (const c of window.__iceQ.splice(0)) {
      window.pc.addIceCandidate(c).catch(() => {});
    }
    out.push("flushed");
  }
  out.push("st=" + window.pc.connectionState + " log=" + (window.__log || []).join("|"));
  return out.join(" ");
})()
"""


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Nomad<->Chrome WebRTC interop (Chrome offers).")
    parser.add_argument("--nomad-port", type=int, default=19680)
    parser.add_argument("--chrome-port", type=int, default=19681)
    parser.add_argument("--chrome-dbg-port", type=int, default=19682)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json-out", default=None)
    args = parser.parse_args()
    relay = ThreadingHTTPServer(("127.0.0.1", 0), RelayHandler)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    relay_base = f"http://127.0.0.1:{relay.server_address[1]}"

    nomad = Nomad(args.nomad_port)
    chrome = Chrome(args.chrome_port, args.chrome_dbg_port,
                      f"{relay_base}/blank")
    try:
        nomad.js(f"window.RELAY = '{relay_base}'; " + SYNC_IO + NOMAD_SETUP)
        print("nomad setup:", nomad.js("window.__nlog ? 'ready' : 'missing'"), flush=True)
        chrome.js(f"window.RELAY = '{relay_base}'; " + CHROME_PAGE)
        print("chrome offer kicked:", chrome.js("window.pc ? 'pc-ok' : 'no-pc'"), flush=True)
        deadline = time.monotonic() + args.timeout
        result = "timeout"
        while time.monotonic() < deadline:
            n = nomad.js(SYNC_IO + NOMAD_POLL)
            c = chrome.js(SYNC_IO + CHROME_POLL)
            nstate = nomad.js(SYNC_IO + NOMAD_STEP)
            cstate = chrome.js(SYNC_IO + CHROME_STEP)
            print(f"n={n} c={c}", flush=True)
            print(f"  nomad:{nstate} chrome:{cstate}", flush=True)
            if "hello-chrome" in str(cstate) and "hello-nomad" in str(nstate):
                result = "BOTH-DIRECTIONS-OK"
                break
            if "n-track:audio" in str(nstate):
                result = "AUDIO-TRACK-ONLY"
                break
            time.sleep(1)
        print("RESULT:", result, flush=True)
        report = {"result": result,
                  "nomad_state": nstate if "nstate" in dir() else None,
                  "chrome_state": cstate if "cstate" in dir() else None}
        if args.json_out:
            with open(args.json_out, "w") as handle:
                json.dump(report, handle, indent=2)
        return 0 if result == "BOTH-DIRECTIONS-OK" else 1
    finally:
        nomad.close()
        chrome.close()
        relay.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
