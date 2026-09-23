#!/usr/bin/env python3
"""Build REPORT.html, REPORT.tex, and REPORT.pdf using Pandoc and Tectonic."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pandoc", default="pandoc")
    parser.add_argument("--tectonic", default="tectonic")
    args = parser.parse_args()
    common = [args.pandoc, "REPORT.md", "--standalone",
              "--from=markdown+tex_math_dollars", "--lua-filter=assets/layout.lua",
              "--fail-if-warnings"]
    subprocess.run([*common, "--to=html5", "--math-method=mathml", "--embed-resources",
                    "--toc", "--toc-depth=1",
                    "--css=assets/report.css", "--output=REPORT.html"], cwd=ROOT, check=True)
    subprocess.run([*common, "--to=latex", "--output=REPORT.tex"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="octarine-document-build-") as tmp:
        subprocess.run([args.tectonic, "--outdir", tmp, str(ROOT / "REPORT.tex")],
                       cwd=ROOT, check=True)
        shutil.copyfile(Path(tmp) / "REPORT.pdf", ROOT / "REPORT.pdf")
    print("Built REPORT.html, REPORT.tex, and REPORT.pdf.")


if __name__ == "__main__":
    main()
