# DevTools and automation validation

Nomad exposes two explicit local automation boundaries:

* `--webdriver <PORT>` provides loopback W3C WebDriver sessions and the
  `nomad:capabilities` contract. WebDriver-created tabs are isolated from the
  user-shell tab stream, and ingress/event histories are bounded.
* `--devtools <PORT>` enables Servo's Firefox Remote Debugging Protocol server
  on `127.0.0.1` only. The native smoke test connects, reads the root actor, and
  requests the protocol description:

```text
python3 tools/run-nomad-devtools-smoke.py --timeout 15
{"protocol":"firefox-rdp-json","root":"root","types":["device","performance"],"tabActors":["accessibilityActor","consoleActor","cssPropertiesActor","inspectorActor","styleSheetsActor","threadActor"]}
```

The smoke now negotiates the root actors, lists the native tab, resolves its
browsing-context target, and verifies the inspector, console, CSS, stylesheet,
accessibility, and debugger-thread actor handles. The endpoint is disabled by
default. The remaining acceptance work is exercising those actors
panel-by-panel, plus storage/network/security/performance/memory/media/PDF
workflows and standards/real-site driving through the same protocol.
