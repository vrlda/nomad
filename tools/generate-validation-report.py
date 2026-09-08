#!/usr/bin/env python3
"""Aggregate deterministic per-platform validation artifacts.

The report is intentionally evidence-only: it does not turn a blocked or
failed platform into a pass.  CI can publish the resulting JSON alongside the
raw WPT artifacts for release triage.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def repository_commit() -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture-set", default="tools/nomad-wpt-corpus.txt")
    parser.add_argument("--commit", default=None)
    parser.add_argument("--limitation", action="append", default=[])
    return parser.parse_args()


def load_artifacts(directory: Path) -> list[dict]:
    artifacts = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "validation-report.json":
            continue
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema_version") != 1 or "summary" not in value:
            continue
        artifacts.append(
            {
                "file": path.name,
                "platform": value.get("platform", "unknown"),
                "platform_detail": value.get("platform_detail", "unknown"),
                "commit": value.get("commit", "unknown"),
                "fixture_set": value.get("corpus", "unknown"),
                "tag": value.get("tag"),
                "runner_exit": value.get("wpt_runner_exit"),
                "summary": value["summary"],
                "discrepancies": value.get("discrepancies", []),
            }
        )
    return artifacts


def main() -> int:
    arguments = parse_args()
    artifacts = load_artifacts(arguments.artifacts_dir.resolve())
    failures = [
        {
            "platform": artifact["platform"],
            "file": artifact["file"],
            "discrepancies": artifact["discrepancies"],
        }
        for artifact in artifacts
        if artifact["discrepancies"] or artifact["summary"].get("tests_mismatch", 0)
    ]
    blocked = [
        artifact["platform"]
        for artifact in artifacts
        if artifact["summary"].get("tests_blocked", 0)
    ]
    report = {
        "schema_version": 1,
        "commit": arguments.commit or repository_commit(),
        "fixture_set": arguments.fixture_set,
        "platforms": artifacts,
        "platform_count": len(artifacts),
        "blocked_platforms": sorted(blocked),
        "failures": failures,
        "limitations": sorted(set(arguments.limitation)),
    }
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
