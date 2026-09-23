#!/usr/bin/env python3
"""Refresh the publication manifest and optionally build the versioned ZIP.

No network access. Repository metadata and generated verification directories
are excluded. ZIP entry times and permissions are fixed for reproducibility
given identical input bytes.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
RELEASE = "Octarine-Review-v1.0.1"
ROOT_FILES = """
.gitattributes .gitignore
README.md REPORT.md REPORT.tex REPORT.html REPORT.pdf
FINDINGS.md REPRODUCING.md PROVENANCE.md AI_DISCLOSURE.md
LICENSING.md LICENSE CITATION.cff CHANGES.md
ABSTRACT.txt references.bib
run.py verify_package.py build_documents.py package_release.py
""".split()
DIRECTORIES = ("code", "data", "evidence", "assets", "LICENSES")


def release_files():
    paths = [ROOT / name for name in ROOT_FILES]
    for directory in DIRECTORIES:
        base = ROOT / directory
        if not base.is_dir():
            raise SystemExit(f"Missing release directory: {directory}")
        for path in base.rglob("*"):
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            if path.is_file():
                paths.append(path)
    for path in paths:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise SystemExit(f"Missing or invalid release file: {path.name}")
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=ROOT.parent)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not args.manifest_only and output.is_relative_to(ROOT):
        parser.error("Put release archives outside the publication root.")
    paths = release_files()
    manifest = ROOT / "SHA256SUMS"
    manifest.write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}\n" for path in paths
    ), encoding="utf-8")
    print(f"Manifest: {len(paths)} files.")
    if args.manifest_only:
        return
    output.mkdir(parents=True, exist_ok=True)
    destination = output / (RELEASE + ".zip")
    with tempfile.TemporaryDirectory(prefix="octarine-release-", dir=output) as tmp:
        archive = Path(tmp) / destination.name
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as bundle:
            for path in sorted([*paths, manifest]):
                name = RELEASE + "/" + path.relative_to(ROOT).as_posix()
                entry = zipfile.ZipInfo(name, date_time=(2026, 9, 23, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                bundle.writestr(entry, path.read_bytes(),
                                compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        archive.replace(destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    sidecar = output / (destination.name + ".sha256")
    sidecar.write_text(f"{digest}  {destination.name}\n", encoding="utf-8")
    print(f"Archive: {destination}")
    print(f"Checksum: {sidecar}")


if __name__ == "__main__":
    main()
