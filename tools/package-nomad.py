#!/usr/bin/env python3
"""Create and validate a deterministic unsigned Nomad release archive.

The release workflow supplies platform signing/notarization after this step;
the archive itself always contains a manifest and SHA-256 inventory so the
signing job and clean-machine installer tests have stable inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import zipfile
import gzip


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _zip_info(path: Path, archive_name: str) -> zipfile.ZipInfo:
    """Return stable metadata for a file in a release ZIP."""
    info = zipfile.ZipInfo(archive_name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (0o100755 if path.stat().st_mode & 0o111 else 0o100644) << 16
    return info


def _normalized_tar_info(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Strip host-specific metadata while retaining executable file modes."""
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _safe_extract_members(names: list[str], destination: Path) -> None:
    root = destination.resolve()
    for name in names:
        target = (destination / name).resolve()
        if target != root and root not in target.parents:
            raise RuntimeError(f"archive path escapes validation directory: {name}")


def package(binary: Path, output: Path, version: str, platform: str) -> None:
    if not binary.is_file():
        raise RuntimeError(f"release binary not found: {binary}")
    if output.suffix not in {".zip", ".gz", ".tgz"}:
        raise RuntimeError("output must be .zip, .tar.gz, or .tgz")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nomad-package-") as temporary:
        root = Path(temporary) / f"nomad-browser-{platform}-{version}"
        root.mkdir()
        name = binary.name
        destination = root / "bin" / name
        destination.parent.mkdir()
        shutil.copy2(binary, destination)
        manifest = {
            "product": "nomad-browser",
            "version": version,
            "platform": platform,
            "binary": f"bin/{name}",
            "signing": "required-by-release-job",
        }
        (root / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        inventory = {
            path.relative_to(root).as_posix(): sha256(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        }
        (root / "SHA256SUMS").write_text(
            "".join(f"{digest}  {path}\n" for path, digest in inventory.items()),
            encoding="utf-8",
        )
        if output.suffix == ".zip":
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(root.rglob("*")):
                    if path.is_file():
                        name = path.relative_to(Path(temporary)).as_posix()
                        archive.writestr(_zip_info(path, name), path.read_bytes())
        else:
            with output.open("wb") as stream:
                with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as archive:
                        archive.add(root, arcname=root.name, recursive=True, filter=_normalized_tar_info)
    validate(output, version, platform)


def validate(archive: Path, version: str, platform: str) -> None:
    if not archive.is_file():
        raise RuntimeError(f"artifact not found: {archive}")
    with tempfile.TemporaryDirectory(prefix="nomad-validate-") as temporary:
        destination = Path(temporary)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as source:
                _safe_extract_members(source.namelist(), destination)
                source.extractall(destination)
        else:
            with tarfile.open(archive, "r:gz") as source:
                _safe_extract_members(source.getnames(), destination)
                source.extractall(destination)
        manifests = list(destination.glob("*/manifest.json"))
        if len(manifests) != 1:
            raise RuntimeError("artifact must contain exactly one manifest")
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        if manifest.get("version") != version or manifest.get("platform") != platform:
            raise RuntimeError(f"artifact manifest mismatch: {manifest}")
        sums = manifests[0].with_name("SHA256SUMS")
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            path = sums.parent / relative
            if sha256(path) != digest:
                raise RuntimeError(f"artifact hash mismatch: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--validate", action="store_true")
    arguments = parser.parse_args()
    if arguments.validate:
        validate(arguments.output.resolve(), arguments.version, arguments.platform)
    else:
        package(
            arguments.binary.resolve(),
            arguments.output.resolve(),
            arguments.version,
            arguments.platform,
        )
    print(arguments.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
