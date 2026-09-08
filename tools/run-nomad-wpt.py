#!/usr/bin/env python3
"""Run Nomad's declared WPT corpus through the native browser binary and emit
a deterministic JSON artifact per platform.

This reuses Servo's vendored WPT runner but replaces the browser executable
with Nomad. The native shell must be built with the ``native-servo`` feature
first.

The corpus manifest (tools/nomad-wpt-corpus.txt) declares the expected status
of every selected test on every supported platform. This script runs the whole
corpus, compares the recorded results against the declaration, and writes a
machine-readable artifact that can be used as release evidence.

Exit status is non-zero when any recorded result disagrees with the declared
expectation. Use ``--no-fail-on-mismatch`` only for exploratory runs.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SERVO_ROOT = REPOSITORY_ROOT / "vendor" / "servo"
DEFAULT_BINARY = REPOSITORY_ROOT / "target" / "debug" / "nomad-browser"
DEFAULT_CORPUS = REPOSITORY_ROOT / "tools" / "nomad-wpt-corpus.txt"
DEFAULT_ARTIFACTS = REPOSITORY_ROOT / "tools" / "wpt-results"
WPT_VENV = REPOSITORY_ROOT / "tools" / ".wpt-venv" / "bin" / "python"
_BUNDLED_PYTHON = Path(
    "/Users/danilrybalkin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
)


def _default_python() -> Path:
    if WPT_VENV.is_file():
        return WPT_VENV
    if _BUNDLED_PYTHON.is_file():
        return _BUNDLED_PYTHON
    return Path(sys.executable)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Nomad's declared WPT corpus through the native Servo embedder "
            "and emit a deterministic per-platform JSON artifact."
        )
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BINARY,
        help="native-servo Nomad executable (default: target/debug/nomad-browser)",
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=_default_python(),
        help="Python interpreter used by Servo's mach runner",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        help="corpus manifest (default: tools/nomad-wpt-corpus.txt)",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=DEFAULT_ARTIFACTS,
        help="directory for the deterministic artifact (default: tools/wpt-results)",
    )
    parser.add_argument(
        "--processes",
        type=int,
        default=1,
        help="number of WPT worker processes (default: 1)",
    )
    parser.add_argument(
        "--timeout-multiplier",
        type=float,
        default=2.0,
        help="multiplier relative to standard test timeout",
    )
    parser.add_argument(
        "--keep-wptreport",
        action="store_true",
        help="also keep the raw wptreport JSON next to the artifact",
    )
    parser.add_argument(
        "--no-fail-on-mismatch",
        action="store_true",
        help="exit 0 even when results disagree with the declared corpus",
    )
    parser.add_argument(
        "--platform-override",
        default=None,
        help="override the platform label recorded in the artifact (for CI labels like macOS-14)",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="arbitrary tag recorded in the artifact (e.g. a release or run identifier)",
    )
    parser.add_argument(
        "--blocked-reason",
        default=None,
        help=(
            "do not run the corpus; record every declared test as BLOCKED with the "
            "given reason (for platforms where the harness cannot execute)."
        ),
    )
    parser.add_argument(
        "tests",
        nargs="*",
        help="restrict the run to the given corpus test ids (must exist in the corpus)",
    )
    return parser.parse_args()


class CorpusEntry:
    __slots__ = ("test_id", "expected", "note", "fail_subtests")

    def __init__(self, test_id: str, expected: str, note: str, fail_subtests: list[str]) -> None:
        self.test_id = test_id
        self.expected = expected.upper()
        self.note = note
        self.fail_subtests = fail_subtests

    def as_dict(self) -> dict:
        return {
            "test": self.test_id,
            "expected": self.expected,
            "note": self.note,
            "fail_subtests": sorted(self.fail_subtests),
        }


def load_corpus(path: Path) -> dict[str, CorpusEntry]:
    if not path.is_file():
        raise SystemExit(f"Corpus manifest not found: {path}")
    entries: dict[str, CorpusEntry] = {}
    current: CorpusEntry | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            if current is None:
                raise SystemExit(f"Indented line without a parent test in {path}: {raw!r}")
            subtest = json.loads(stripped[2:] if stripped.startswith("- ") else stripped)
            current.fail_subtests.append(subtest)
            continue
        parts = [p.strip() for p in stripped.split("|")]
        if len(parts) < 2:
            raise SystemExit(f"Malformed corpus line in {path}: {raw!r}")
        test_id, expected = parts[0], parts[1].upper()
        note = parts[2] if len(parts) > 2 else ""
        if expected not in ("PASS", "FAIL", "BLOCKED"):
            raise SystemExit(f"Unknown expected status {expected!r} for {test_id} in {path}")
        current = CorpusEntry(test_id, expected, note, [])
        if test_id in entries:
            raise SystemExit(f"Duplicate corpus entry: {test_id}")
        entries[test_id] = current
    return entries


def _repo_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
    except OSError:
        pass
    return "unknown"


def run_wpt(
    binary: Path, python: Path, corpus: dict[str, CorpusEntry], args: argparse.Namespace
) -> tuple[int, dict]:
    test_ids = args.tests or list(corpus)
    missing = [t for t in test_ids if t not in corpus]
    if missing:
        raise SystemExit(f"Tests not present in corpus: {', '.join(missing)}")

    binary = binary.expanduser().resolve()
    python = python.expanduser().resolve()
    if not binary.is_file():
        raise SystemExit(
            f"Nomad binary not found: {binary}\n"
            "Build it with: cargo build -p nomad-browser --features native-servo"
        )
    if args.processes < 1:
        raise SystemExit("--processes must be at least 1")

    command = [
        str(SERVO_ROOT / "mach"),
        "test-wpt",
        "--bin",
        str(binary),
        "--no-manifest-download",
        "--processes",
        str(args.processes),
        "--test-types=testharness",
        "--timeout-multiplier",
        str(args.timeout_multiplier),
        # Nomad declares its expectations in the corpus manifest instead of
        # Servo's meta directory, so the upstream runner must not fail on
        # results that its own meta considers unexpected.
        "--no-fail-on-unexpected",
    ]
    command.extend(test_ids)

    env = os.environ.copy()
    env["PYTHON3"] = str(python)
    wpt_tests = SERVO_ROOT / "tests" / "wpt" / "tests"
    pythonpath = [str(wpt_tests)]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)

    with tempfile.TemporaryDirectory(prefix="nomad-wpt-") as tmp:
        report_path = Path(tmp) / "wptreport.json"
        command.append(f"--log-wptreport={report_path}")
        print("Running:", " ".join(command), flush=True)
        completed = subprocess.run(command, cwd=SERVO_ROOT, env=env, check=False)

        if report_path.is_file():
            with open(report_path, encoding="utf-8") as handle:
                report = json.load(handle)
        else:
            report = {"results": []}

        if args.keep_wptreport:
            args.artifacts_dir.mkdir(parents=True, exist_ok=True)
            keep = args.artifacts_dir / f"wptreport-{_platform_label(args)}.json"
            with open(keep, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)

        return completed.returncode, report


def _platform_label(args: argparse.Namespace) -> str:
    if args.platform_override:
        return args.platform_override
    mapping = {"darwin": "macos", "linux": "linux", "win32": "windows"}
    return mapping.get(sys.platform, sys.platform)


def compare_results(
    corpus: dict[str, CorpusEntry], report: dict, args: argparse.Namespace
) -> dict:
    # A targeted run is an intentional subset of the manifest.  Comparing it
    # against the whole corpus would turn every omitted test into a false
    # ``not-run`` discrepancy and make focused debugging unusable.
    selected_entries = (
        {test_id: corpus[test_id] for test_id in args.tests}
        if args.tests
        else corpus
    )
    selected_by_id = {test_id.lstrip("/"): entry for test_id, entry in selected_entries.items()}
    run_entries: dict[str, dict] = {}
    for result in report.get("results", []):
        variant = result["test"]
        base = variant.split("?")[0].lstrip("/")
        entry = run_entries.setdefault(
            base, {"variants": [], "pass": 0, "fail": [], "unexpected": [], "missing": []}
        )
        entry["variants"].append(variant)
        if result.get("status") in ("OK", "PASS"):
            sub_failures = [
                s["name"] for s in result.get("subtests", []) if s["status"] != "PASS"
            ]
            if sub_failures:
                entry["fail"].extend(sub_failures)
            else:
                entry["pass"] += 1
        else:
            entry["unexpected"].append(
                {"variant": variant, "status": result.get("status")}
            )

    corpus_ids = set(selected_by_id)
    results: dict[str, dict] = {}
    discrepancies: list[dict] = []

    for base, data in run_entries.items():
        if base not in corpus_ids:
            discrepancies.append(
                {"test": base, "kind": "unlisted-result", "detail": "ran but not in corpus"}
            )
            continue
        entry = selected_by_id[base]
        actual_fail = sorted(set(data["fail"]))
        declared_fail = sorted(entry.fail_subtests)
        extra_fail = [f for f in actual_fail if f not in declared_fail]
        missing_fail = [f for f in declared_fail if f not in actual_fail]

        if entry.expected == "PASS":
            ok = data["pass"] == len(data["variants"]) and not data["unexpected"]
            status = "pass" if ok else "mismatch"
        elif entry.expected == "FAIL":
            status = "pass"
            if extra_fail or missing_fail or data["unexpected"]:
                status = "mismatch"
        else:  # BLOCKED
            status = "blocked"

        if status != "pass":
            discrepancy = {
                "test": base,
                "kind": "expectation-mismatch",
                "expected": entry.expected,
                "pass_variants": data["pass"],
                "total_variants": len(data["variants"]),
                "unexpected": data["unexpected"],
                "extra_fail_subtests": extra_fail,
                "missing_declared_fail_subtests": missing_fail,
            }
            discrepancies.append(discrepancy)

        results[base] = {
            "expected": entry.expected,
            "status": status,
            "note": entry.note,
            "pass_variants": data["pass"],
            "total_variants": len(data["variants"]),
            "fail_subtests": actual_fail,
        }

    for test_id, entry in selected_entries.items():
        if test_id.lstrip("/") not in run_entries:
            results[test_id] = {
                "expected": entry.expected,
                "status": "not-run" if entry.expected != "BLOCKED" else "blocked",
                "note": entry.note,
                "pass_variants": 0,
                "total_variants": 0,
                "fail_subtests": [],
            }
            if entry.expected != "BLOCKED":
                discrepancies.append(
                    {"test": test_id, "kind": "not-run", "detail": "test did not run"}
                )

    counts = {"pass": 0, "mismatch": 0, "blocked": 0, "not-run": 0}
    for result in results.values():
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    return {
        "results": results,
        "discrepancies": discrepancies,
        "summary": {
            "tests_declared": len(selected_entries),
            "tests_checked": sum(
                1 for r in results.values() if r["status"] not in ("blocked", "not-run")
            ),
            "tests_passed": counts.get("pass", 0),
            "tests_mismatch": counts.get("mismatch", 0),
            "tests_blocked": counts.get("blocked", 0),
            "tests_not_run": counts.get("not-run", 0),
            "discrepancy_count": len(discrepancies),
        },
    }


def write_artifact(
    args: argparse.Namespace,
    corpus: dict[str, CorpusEntry],
    comparison: dict,
    wpt_returncode: int,
) -> Path:
    artifact = {
        "schema_version": 1,
        "platform": _platform_label(args),
        "platform_detail": platform.platform(),
        "commit": _repo_commit(),
        "corpus": args.corpus.resolve().name,
        "corpus_tests": len(corpus),
        "engine": "nomad-native-servo",
        "wpt_runner_exit": wpt_returncode,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tag": args.tag,
        "summary": comparison["summary"],
        "discrepancies": comparison["discrepancies"],
        "results": comparison["results"],
    }

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    commit = artifact["commit"][:12] if artifact["commit"] != "unknown" else "unknown"
    out = args.artifacts_dir / f"wpt-{_platform_label(args)}-{commit}.json"
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle, indent=2, sort_keys=True)
    return out


def main() -> int:
    args = parse_args()
    corpus = load_corpus(args.corpus.expanduser().resolve())

    if args.blocked_reason:
        results = {
            test_id: {
                "expected": entry.expected,
                "status": "blocked",
                "note": f"BLOCKED: {args.blocked_reason}. {entry.note}".rstrip(),
                "pass_variants": 0,
                "total_variants": 0,
                "fail_subtests": [],
            }
            for test_id, entry in corpus.items()
        }
        comparison = {
            "results": results,
            "discrepancies": [],
            "summary": {
                "tests_declared": len(corpus),
                "tests_checked": 0,
                "tests_passed": 0,
                "tests_mismatch": 0,
                "tests_blocked": len(corpus),
                "tests_not_run": 0,
                "discrepancy_count": 0,
            },
        }
        artifact_path = write_artifact(args, corpus, comparison, wpt_returncode=-1)
        print(f"Artifact (blocked): {artifact_path}", flush=True)
        print(json.dumps(comparison["summary"], indent=2, sort_keys=True), flush=True)
        return 0

    wpt_returncode, report = run_wpt(args.binary, args.python, corpus, args)
    comparison = compare_results(corpus, report, args)
    artifact_path = write_artifact(args, corpus, comparison, wpt_returncode)

    print(f"Artifact: {artifact_path}", flush=True)
    print(json.dumps(comparison["summary"], indent=2, sort_keys=True), flush=True)

    if comparison["discrepancies"]:
        print("\nDiscrepancies:", flush=True)
        for disc in comparison["discrepancies"]:
            print("  -", json.dumps(disc, sort_keys=True), flush=True)

    if args.no_fail_on_mismatch:
        return 0
    return 1 if comparison["discrepancies"] else 0


if __name__ == "__main__":
    sys.exit(main())
