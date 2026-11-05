#!/usr/bin/env python3
"""Build the small, reproducible suite ZIP without game data or secrets."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "README.md",
    "README_RU.md",
    "requirements.txt",
    "requirements-dev.txt",
    "docs/ULTIMATE_GAME_RE_GUIDE_RU.md",
    "tools/re_swiss_knife.py",
    "tools/package_suite.py",
    "templates/goldhen_cheat_sample.json",
    "templates/android_arm64_hook.cpp",
    "templates/local_ps4_server_emulator.py",
    "tests/test_swiss_knife.py",
    "tests/goldhen_generated_subset.schema.json",
    ".github/workflows/build_re_knowledge_suite.yml",
)
DEFAULT_NAME = "Ultimate_Game_RE_&_Modding_Suite.zip"


def build(output: Path, force: bool = False) -> None:
    output = output.resolve()
    sources = [ROOT / name for name in FILES]
    if output in (p.resolve() for p in sources):
        raise ValueError("Output must not replace a source file")
    missing = [str(p) for p in sources if not p.is_file()]
    if missing:
        raise ValueError("Missing suite files: " + ", ".join(missing))
    if output.exists() and not force:
        raise ValueError("Output already exists; pass --force to replace the ZIP")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".suite-", suffix=".zip", dir=output.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, source in sorted(zip(FILES, sources)):
                info = zipfile.ZipInfo(name, date_time=(2026, 11, 4, 0, 0, 0))
                info.create_system = 3
                mode = 0o100755 if name.endswith(".py") and (name.startswith("tools/") or name.startswith("templates/")) else 0o100644
                info.external_attr = mode << 16
                archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        with zipfile.ZipFile(temp) as archive:
            bad = archive.testzip()
            if bad:
                raise ValueError(f"Corrupt ZIP member: {bad}")
        os.replace(temp, output)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / DEFAULT_NAME)
    parser.add_argument("--force", action="store_true", help="replace an existing output archive")
    args = parser.parse_args(argv)
    try:
        build(args.output, args.force)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Created {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
