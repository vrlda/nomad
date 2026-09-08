#!/usr/bin/env python3
"""Compare pinned Xray config acceptance with Nomad's embedded parser."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_FIXTURES = Path("crates/nomad-engine/tests/fixtures/xray/v25.12.8.json")


def run_reference(reference: Path, profile: dict[str, object]) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
        json.dump(profile, handle)
        handle.flush()
        result = subprocess.run(
            [str(reference), "-test", "-config", handle.name],
            capture_output=True,
            text=True,
            check=False,
        )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def run_nomad(root: Path, fixture_path: Path) -> list[dict[str, object]]:
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "nomad-engine",
            "--bin",
            "xray-fixture-check",
            "--",
            str(fixture_path),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument(
        "--reference-bin",
        type=Path,
        default=(
            Path(os.environ["XRAY_REFERENCE_BIN"])
            if os.environ.get("XRAY_REFERENCE_BIN")
            else None
        ),
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixture_path = (
        (root / args.fixtures).resolve()
        if not args.fixtures.is_absolute()
        else args.fixtures
    )
    reference = args.reference_bin
    if reference is None:
        parser.error("--reference-bin or XRAY_REFERENCE_BIN is required")
    reference = reference.resolve()

    fixtures = json.loads(fixture_path.read_text())
    version = fixtures["reference"]["version"]
    version_result = subprocess.run(
        [str(reference), "version"], capture_output=True, text=True, check=False
    )
    if version_result.returncode or version.lstrip("v") not in version_result.stdout:
        print(
            f"reference version mismatch: expected {version}, "
            f"got {version_result.stdout.strip()!r}",
            file=sys.stderr,
        )
        return 1

    nomad_results = {result["id"]: result for result in run_nomad(root, fixture_path)}
    failures = 0
    for fixture in fixtures["fixtures"]:
        fixture_id = fixture["id"]
        reference_ok, reference_output = run_reference(reference, fixture["profile"])
        nomad = nomad_results[fixture_id]
        nomad_ok = bool(nomad["accepted"])
        expected = fixture.get("expected", {})
        signature_ok = not reference_ok or all(
            nomad.get(key) == expected.get(key)
            for key in ("protocol", "transport", "security")
        )
        status = "PASS" if reference_ok == nomad_ok and signature_ok else "FAIL"
        if status == "FAIL":
            failures += 1
        print(
            f"{status} {fixture_id}: reference={'accepted' if reference_ok else 'rejected'} "
            f"nomad={'accepted' if nomad_ok else 'rejected'} "
            f"signature={'match' if signature_ok else 'mismatch'}"
        )
        if status == "FAIL":
            print(f"  reference: {reference_output[-500:]}", file=sys.stderr)
            print(f"  nomad: {nomad}", file=sys.stderr)

    print(
        f"Xray differential: {len(fixtures['fixtures']) - failures}/"
        f"{len(fixtures['fixtures'])} fixtures matched reference {version}"
    )
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
