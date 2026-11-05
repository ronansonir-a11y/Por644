#!/usr/bin/env python3
"""Build the small, reproducible suite ZIP without game data or secrets."""
from __future__ import annotations

import argparse
import os
import struct
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
    "tests/test_suite_v2.py",
    "tests/goldhen_generated_subset.schema.json",
    ".github/workflows/build_re_knowledge_suite.yml",
)
DEFAULT_NAME = "Ultimate_Game_RE_&_Modding_Suite.zip"
ANDROID_MEMBER = "build/android_arm64/liboffline_patch.so"


def verify_android_elf(source: Path) -> None:
    """Check target ABI/type, not provenance or device compatibility."""
    with source.open("rb") as f:
        header = f.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("Android library must be a little-endian ELF64")
        etype, machine, version = struct.unpack_from("<HHI", header, 16)
        if (etype, machine, version) != (3, 183, 1):
            raise ValueError("Android library must be ET_DYN and EM_AARCH64")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        ehsize, phsize, phnum = struct.unpack_from("<HHH", header, 52)
        if ehsize != 64 or not 56 <= phsize <= 256 or not 1 <= phnum <= 4096 or phoff < 64 or phoff + phsize * phnum > os.fstat(f.fileno()).st_size:
            raise ValueError("Android ELF program-header table is invalid")
        f.seek(phoff)
        table = f.read(phsize * phnum)
        types = {struct.unpack_from("<I", table, i * phsize)[0] for i in range(phnum)}
        if not {1, 2}.issubset(types):
            raise ValueError("Android ELF must contain PT_LOAD and PT_DYNAMIC")


def build(output: Path, force: bool = False, android_so: Path | None = None) -> None:
    output = output.resolve()
    names = list(FILES)
    sources = [ROOT / name for name in names]
    if android_so is not None:
        android_so = Path(android_so).resolve()
        verify_android_elf(android_so)
        names.append(ANDROID_MEMBER)
        sources.append(android_so)
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
            for name, source in sorted(zip(names, sources)):
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
    parser.add_argument("--android-so", type=Path, help="verified arm64-v8a NDK-built .so to include; omission produces a source-only ZIP")
    args = parser.parse_args(argv)
    try:
        build(args.output, args.force, args.android_so)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Created {args.output}" + (" (includes Android ARM64 library)" if args.android_so else " (source-only; no Android binary)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
