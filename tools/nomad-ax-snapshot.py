#!/usr/bin/env python3
"""Snapshot the macOS accessibility tree of a running Nomad browser.

Uses the native AX API (the same tree VoiceOver consumes) to validate that
Nomad's chrome and web content expose roles, names, values, focus, and
live-region updates to assistive technology.
"""

from __future__ import annotations

import sys

import ApplicationServices
import Quartz


TRUSTED = ApplicationServices.AXIsProcessTrusted()


def ax_value(element, attr):
    try:
        result = ApplicationServices.AXUIElementCopyAttributeValue(element, attr, None)
    except Exception:
        return None
    if not isinstance(result, tuple) or len(result) != 2:
        return None
    error, value = result
    if error:
        return None
    return value


def find_nomad_pid():
    for option in (Quartz.kCGWindowListOptionOnScreenOnly,
                   Quartz.kCGWindowListOptionAll):
        windows = Quartz.CGWindowListCopyWindowInfo(option, Quartz.kCGNullWindowID)
        for window in windows or []:
            owner = window.get("kCGWindowOwnerName", "")
            if "nomad" in owner.lower():
                return int(window["kCGWindowOwnerPID"]), owner
    return None, None


def dump(element, depth=0, limit=200, out=None):
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    role = ax_value(element, "AXRole") or "?"
    title = (ax_value(element, "AXTitle") or ax_value(element, "AXDescription")
             or ax_value(element, "AXValue") or "")
    if isinstance(title, str):
        title = title.strip().replace("\n", " ")[:60]
    else:
        title = str(title)[:60]
    focused = ax_value(element, "AXFocused")
    out.append(f"{'  ' * depth}{role} :: {title}" + (" [focused]" if focused else ""))
    children = ax_value(element, "AXChildren") or []
    for child in children:
        dump(child, depth + 1, limit, out)
        if len(out) >= limit:
            break
    return out


def main() -> int:
    print(f"ax-trusted={TRUSTED}")
    if not TRUSTED:
        print("NOT-TRUSTED: grant Accessibility permission to the terminal, then rerun")
        return 2
    pid_owner = find_nomad_pid()
    if pid_owner[0] is None:
        print("NO-NOMAD-WINDOW")
        return 1
    pid, owner = pid_owner
    print(f"nomad pid={pid} owner={owner!r}")
    app = ApplicationServices.AXUIElementCreateApplication(pid)
    windows = ax_value(app, "AXWindows") or []
    print(f"ax-windows={len(windows)}")
    for window in windows:
        for line in dump(window, limit=120):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
