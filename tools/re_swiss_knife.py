#!/usr/bin/env python3
"""Offline game RE helper v2.0. Python 3.10+; Capstone is needed for --make-aob.
Zstandard is optional except for FMF zstd streams; NSO LZ4 uses pure Python.

Do not use against live services, multiplayer titles or anti-cheat software.
All binary/engine detection is heuristic; never confuse a file offset with an
in-process cheat address. No DRM is removed or bypassed by this program.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import shutil
import struct
import sys
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

HEADER_LIMIT = 2 * 1024 * 1024
MAX_BINARIES = 100
MAX_FILES = 30000
MAX_PATTERN = 4096


class ToolError(Exception):
    """An actionable, user-facing error."""


@dataclass
class Region:
    file_offset: int
    size: int
    virtual_address: int


@dataclass
class BinaryReport:
    path: str
    format: str = "unknown / raw"
    architecture: str = "unknown"
    endian: str = "unknown"
    file_size: int | None = None
    image_base: int | None = None
    regions: list[Region] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    protection: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


MACHINES_ELF = {3: "x86", 20: "PowerPC", 21: "PowerPC64", 40: "ARM32", 62: "x86_64", 183: "ARM64"}
MACHINES_PE = {0x014C: "x86", 0x8664: "x86_64", 0x01C0: "ARM32", 0x01C4: "ARM32", 0xAA64: "ARM64", 0x01F0: "PowerPC"}
MACHINES_MACHO = {7: "x86", 0x01000007: "x86_64", 12: "ARM32", 0x0100000C: "ARM64", 18: "PowerPC", 0x01000012: "PowerPC64"}


def _unpack(data: bytes, fmt: str, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("truncated header")
    return struct.unpack_from(fmt, data, offset)


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _ascii_z(data: bytes, offset: int, maximum: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    return data[offset:min(len(data), offset + maximum)].split(b"\0", 1)[0].decode("ascii", "replace")


def _elf(data: bytes, report: BinaryReport) -> None:
    report.format = "ELF"
    if len(data) < 20 or data[4] not in (1, 2) or data[5] not in (1, 2):
        report.notes.append("Incomplete/invalid ELF identification")
        return
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    report.endian = "little" if endian == "<" else "big"
    report.format = f"ELF{bits}"
    report.architecture = MACHINES_ELF.get(_unpack(data, endian + "H", 18)[0], "unknown")
    if report.architecture == "ARM32":
        report.notes.append("EM_ARM alone does not identify ARMv7 or ARM/Thumb mode")
    elf_type = _unpack(data, endian + "H", 16)[0]
    report.notes.append({2: "ET_EXEC", 3: "ET_DYN (PIE/shared object)"}.get(elf_type, f"ELF type {elf_type}"))
    try:
        if bits == 64:
            phoff, shoff = _unpack(data, endian + "QQ", 32)
            phentsize, phnum, shentsize, shnum, shstr = _unpack(data, endian + "HHHHH", 54)
            pfmt, sfmt = endian + "IIQQQQQQ", endian + "IIQQQQIIQQ"
        else:
            phoff, shoff = _unpack(data, endian + "II", 28)
            phentsize, phnum, shentsize, shnum, shstr = _unpack(data, endian + "HHHHH", 42)
            pfmt, sfmt = endian + "IIIIIIII", endian + "IIIIIIIIII"
        bases: list[int] = []
        if phnum and phentsize >= struct.calcsize(pfmt):
            if phnum > 512:
                report.notes.append("Program header count truncated to 512")
            for i in range(min(phnum, 512)):
                fields = _unpack(data, pfmt, phoff + i * phentsize)
                if bits == 64:
                    ptype, _flags, off, va, _pa, filesz, memsz, align = fields
                else:
                    ptype, off, va, _pa, filesz, memsz, _flags, align = fields
                if ptype == 1 and memsz:  # PT_LOAD
                    alignment = align if align else 1
                    limit = 1 << bits
                    if (filesz > memsz or off + filesz > limit or va + memsz > limit or
                            (report.file_size is not None and off + filesz > report.file_size) or
                            (alignment > 1 and (alignment & (alignment - 1) or off % alignment != va % alignment))):
                        report.notes.append("Invalid PT_LOAD sizes/alignment; segment excluded from RVA mapping")
                        continue
                    bases.append(va - va % alignment)
                    if filesz:
                        report.regions.append(Region(off, filesz, va))
            if bases:
                report.image_base = min(bases)
        if shnum and shentsize >= struct.calcsize(sfmt) and shstr < shnum:
            if shnum > 4096:
                report.notes.append("Section count truncated to 4096")
            strhdr = _unpack(data, sfmt, shoff + shstr * shentsize)
            str_off, str_size = strhdr[4], strhdr[5]
            if str_off < len(data):
                strings = data[str_off:min(len(data), str_off + str_size)]
                for i in range(min(shnum, 4096)):
                    sh = _unpack(data, sfmt, shoff + i * shentsize)
                    name = _ascii_z(strings, sh[0])
                    if name == ".symtab":
                        _append_once(report.symbols, "ELF .symtab present (may contain local symbols)")
                    elif name.startswith(".debug_"):
                        _append_once(report.symbols, "ELF DWARF debug section present")
    except (ValueError, OverflowError):
        report.notes.append("Some ELF tables were invalid or outside the inspected prefix")


def _pe(data: bytes, report: BinaryReport) -> None:
    report.format = "PE (DOS MZ; header unverified)"
    try:
        peoff = _unpack(data, "<I", 0x3C)[0]
        if data[peoff:peoff + 4] != b"PE\0\0":
            report.notes.append("PE signature missing/outside inspected prefix")
            return
        machine, sections, _ts, symptr, symcount, optsize, _chars = _unpack(data, "<HHIIIHH", peoff + 4)
        report.format = "PE"
        report.architecture = MACHINES_PE.get(machine, "unknown")
        report.endian = "little"
        if symptr and symcount:
            report.symbols.append("COFF symbol table advertised")
        opt = peoff + 24
        magic = _unpack(data, "<H", opt)[0] if optsize >= 2 else 0
        if magic == 0x20B and optsize >= 64:
            report.image_base = _unpack(data, "<Q", opt + 24)[0]
        elif magic == 0x10B and optsize >= 64:
            report.image_base = _unpack(data, "<I", opt + 28)[0]
        if report.image_base is not None:
            headers_size = _unpack(data, "<I", opt + 60)[0]
            if headers_size and (report.file_size is None or headers_size <= report.file_size):
                report.regions.append(Region(0, headers_size, report.image_base))
            elif headers_size:
                report.notes.append("PE headers exceed file size; header RVA mapping omitted")
        if sections > 96:
            report.notes.append("Section count truncated to 96")
        for i in range(min(sections, 96)):
            off = opt + optsize + 40 * i
            if off + 40 > len(data):
                raise ValueError("truncated section table")
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, rva, raw_size, raw_ptr = _unpack(data, "<IIII", off + 8)
            if report.image_base is not None and raw_size:
                # Do not advertise raw padding beyond a non-zero virtual size as mapped.
                size = min(raw_size, virtual_size) if virtual_size else raw_size
                if report.file_size is None or raw_ptr + raw_size <= report.file_size:
                    report.regions.append(Region(raw_ptr, size, report.image_base + rva))
                else:
                    report.notes.append("PE section exceeds file size; section RVA mapping omitted")
            low = name.lower()
            if low.startswith(".upx"):
                _append_once(report.protection, "UPX-like PE section name (heuristic only)")
            if low.startswith(".vmp"):
                _append_once(report.protection, "VMProtect-like PE section name (heuristic only)")
            if "denuvo" in low:
                _append_once(report.protection, "Denuvo-like PE section name (heuristic only)")
    except (ValueError, OverflowError):
        report.notes.append("Some PE headers were invalid or outside the inspected prefix")


def _macho_thin(data: bytes, report: BinaryReport) -> None:
    magics = {
        b"\xcf\xfa\xed\xfe": ("<", 64), b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64), b"\xfe\xed\xfa\xce": (">", 32),
    }
    endian, bits = magics[data[:4]]
    report.format = f"Mach-O {bits}"
    report.endian = "little" if endian == "<" else "big"
    try:
        cpu = _unpack(data, endian + "I", 4)[0]
        report.architecture = MACHINES_MACHO.get(cpu, "unknown")
        ncmds = _unpack(data, endian + "I", 16)[0]
        cursor = 32 if bits == 64 else 28
        encrypted = False
        for _ in range(min(ncmds, 4096)):
            cmd, size = _unpack(data, endian + "II", cursor)
            if size < 8 or cursor + size > len(data):
                raise ValueError("truncated load command")
            if cmd in (0x21, 0x2C) and size >= 20:  # LC_ENCRYPTION_INFO[_64]
                cryptid = _unpack(data, endian + "I", cursor + 16)[0]
                report.protection.append(f"Mach-O cryptid={cryptid} (" +
                                         ("encrypted flag" if cryptid else "not encrypted by this command") + ")")
                encrypted = True
            elif cmd == 0x19 and bits == 64 and size >= 72:  # LC_SEGMENT_64
                vmaddr, vmsize, fileoff, filesize = _unpack(data, endian + "QQQQ", cursor + 24)
                if filesize and filesize <= vmsize and (report.file_size is None or fileoff + filesize <= report.file_size):
                    report.regions.append(Region(fileoff, filesize, vmaddr))
                elif filesize:
                    report.notes.append("Invalid Mach-O segment size; segment mapping omitted")
            elif cmd == 0x1 and bits == 32 and size >= 56:  # LC_SEGMENT
                vmaddr, vmsize, fileoff, filesize = _unpack(data, endian + "IIII", cursor + 24)
                if filesize and filesize <= vmsize and (report.file_size is None or fileoff + filesize <= report.file_size):
                    report.regions.append(Region(fileoff, filesize, vmaddr))
                elif filesize:
                    report.notes.append("Invalid Mach-O segment size; segment mapping omitted")
            cursor += size
        if ncmds > 4096:
            report.notes.append("Load commands truncated to 4096")
        if report.regions:
            report.image_base = min(r.virtual_address for r in report.regions)
        if not encrypted:
            report.protection.append("FairPlay status unknown: no encryption-info command observed")
    except (ValueError, OverflowError):
        report.notes.append("Some Mach-O load commands were invalid or outside the inspected prefix")


def _macho_fat(data: bytes, report: BinaryReport) -> None:
    # Fat header endianness is independent of the endianness of each slice.
    variants = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True),
    }
    endian, is64 = variants[data[:4]]
    report.format = "Mach-O universal/fat"
    arches: list[str] = []
    try:
        count = _unpack(data, endian + "I", 4)[0]
        if count > 64:
            report.notes.append("Fat slice count truncated to 64")
        for i in range(min(count, 64)):
            at = 8 + i * (32 if is64 else 20)
            if is64:
                cpu, _sub, off, size, _align, _reserved = _unpack(data, endian + "IIQQII", at)
            else:
                cpu, _sub, off, size, _align = _unpack(data, endian + "IIIII", at)
            _append_once(arches, MACHINES_MACHO.get(cpu, "unknown"))
            if off < len(data) and size >= 4 and (report.file_size is None or off + size <= report.file_size):
                slice_data = data[off:min(len(data), off + size)]
                if slice_data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
                    sub = BinaryReport(path=f"slice {i}", file_size=size)
                    _macho_thin(slice_data, sub)
                    for item in sub.protection:
                        _append_once(report.protection, f"slice {i}: {item}")
                else:
                    # Never recurse into another fat header: malformed slices can point at the parent.
                    report.notes.append(f"Slice {i} header invalid/unavailable")
            else:
                report.notes.append(f"Slice {i} outside inspected prefix; cryptid unknown")
        report.architecture = ", ".join(arches) if arches else "unknown"
        report.notes.append("File-to-VA mapping for fat Mach-O is not implemented")
    except (ValueError, OverflowError):
        report.notes.append("Fat header invalid or outside inspected prefix")


def parse_binary(data: bytes, name: str = "<buffer>", file_size: int | None = None) -> BinaryReport:
    """Inspect a bounded prefix; provide total file_size when data is only a prefix."""
    report = BinaryReport(path=name, file_size=len(data) if file_size is None else file_size)
    try:
        if data.startswith(b"\x7fELF"):
            _elf(data, report)
        elif data.startswith(b"MZ"):
            _pe(data, report)
        elif data[:4] == b"\x4f\x15\x3d\x1d":
            report.format = "PS4 SELF/FSELF container"
            report.protection.append("SELF/FSELF magic; fake-signing/encryption state cannot be determined from magic")
            report.notes.append("No decryption or container-to-memory mapping is performed")
        elif data[:4] == b"NSO0":
            report.format = "Nintendo Switch NSO0"
            report.notes.append("NSO0 does not encode CPU architecture; ARM64 is common but not proven")
            report.notes.append("Segments may be compressed; no file-to-memory mapping is attempted")
        elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            _macho_thin(data, report)
        elif data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            _macho_fat(data, report)
    except (ValueError, OverflowError, struct.error):
        report.notes.append("Invalid/truncated binary header")
    lower = data.lower()
    if b"denuvo" in lower:
        _append_once(report.protection, "Denuvo string found in inspected prefix (not proof of DRM or activation)")
    if b"gcc: (" in lower or b"gnu c" in lower:
        _append_once(report.symbols, "GCC/GNU compiler string (heuristic)")
    if b"clang version" in lower or b"apple clang" in lower:
        _append_once(report.symbols, "Clang compiler string (heuristic)")
    if b".pdb\x00" in lower or b".pdb\r" in lower:
        _append_once(report.symbols, "PDB path/string present (debug-symbol hint)")
    if b"microsoft (r)" in lower or b"microsoft c/c++" in lower:
        _append_once(report.symbols, "Microsoft compiler string (heuristic)")
    if b"_zstd" in lower or b"_zn" in lower or b"?av" in lower:
        _append_once(report.symbols, "Possible C++ mangled-name marker (heuristic)")
    if "lib/armeabi-v7a/" in name.lower() and report.architecture == "ARM32":
        report.notes.append("APK path advertises ARMv7-A (armeabi-v7a) ABI; this path is only a hint, verify actual instructions")
    return report


def map_file_offset(report: BinaryReport, offset: int) -> dict | None:
    """Map file bytes only, not BSS, to a preferred image address and relative VA."""
    if offset < 0 or report.image_base is None:
        return None
    addresses = {r.virtual_address + offset - r.file_offset for r in report.regions
                 if r.file_offset <= offset < r.file_offset + r.size}
    if len(addresses) != 1:
        return None  # includes unmapped and ambiguous overlapping segments
    va = addresses.pop()
    return {"image_va": va, "rva": va - report.image_base, "image_base": report.image_base}


PLAYBOOKS = {
    "unity-il2cpp": ["Pair global-metadata.dat with the matching GameAssembly.dll/libil2cpp.so and Unity version.",
                     "Use Il2CppDumper for metadata/addresses, then AssetRipper or UABEA for owned assets; compare exact builds."],
    "unity-mono": ["Inspect Managed assemblies with ILSpy; use a compatible BepInEx Mono release for offline plugins.",
                   "Back up bundles and use the correct Unity version when exporting/importing assets."],
    "unreal": ["Determine the actual UE version and whether assets are .pak or IoStore .utoc/.ucas; IoStore alone is not proof of UE5.",
               "Use version-matched Unreal tools/UAssetGUI on unencrypted assets; do not assume PC cooked data works on PS4/Android."],
    "source": ["Inspect gameinfo.txt and VPK mounts; use supported loose-file/mod folders before changing binaries.",
               "Match engine branch, platform, materials and models when rebuilding assets."],
    "frostbite": ["Treat .toc/.sb/.cas as version-specific catalog clues; map chunks and bundles before replacing any owned assets.",
                  "A filename is not proof of engine version or encryption; use documented, authorized tooling."],
    "godot": ["Check project.godot and the matching Godot major version; use the original project and export templates where possible.",
              "Verify Android rendering/backend and platform export requirements rather than assuming a PCK is portable."],
    "renpy": ["Check Ren'Py SDK/game version and script/archive files; use documented project/mod facilities.",
              "Test on a copy; bytecode/archive versions and assets may differ across releases."],
    "custom": ["Identify file format, ABI, imports, assets and renderer first; use debugger/profilers on authorized offline copies.",
               "Build a compatibility layer or recreate the engine only after mapping I/O, memory and system APIs."],
}


class Evidence:
    def __init__(self) -> None:
        self.items: dict[str, list[str]] = {}

    def add(self, key: str, message: str) -> None:
        values = self.items.setdefault(key, [])
        if message not in values and len(values) < 8:
            values.append(message)

    def observe(self, path: str, data: bytes = b"") -> None:
        p = path.replace("\\", "/").lower()
        name = p.rsplit("/", 1)[-1]
        if name in ("global-metadata.dat", "gameassembly.dll", "libil2cpp.so"):
            self.add("unity-il2cpp", path)
        if (name in ("mono-2.0-bdwgc.dll", "libmono.so", "libmonobdwgc-2.0.so", "mono.dll")
                or "monobleedingedge/" in p or (name == "assembly-csharp.dll" and "/managed/" in "/" + p)):
            self.add("unity-mono", path)
        if "unityplayer" in name or name == "globalgamemanagers":
            self.add("unity", path)
        if name.endswith(".utoc"):
            self.add("utoc", path)
        if name.endswith(".ucas"):
            self.add("ucas", path)
        if name.endswith(".pak") and "/content/paks/" in "/" + p:
            self.add("ue-pak", path)
        if name.endswith((".uasset", ".umap")):
            self.add("ue-assets", path)
        if "ue5game" in p or "unrealengine5" in p or "/ue5/" in "/" + p or name.startswith("ue5-"):
            self.add("ue5", path)
        if "ue4game" in p or "unrealengine4" in p or "/ue4/" in "/" + p or name.startswith("ue4-"):
            self.add("ue4", path)
        if name in ("gameinfo.txt", "hl2.exe") or name.endswith("_dir.vpk"):
            self.add("source", path)
        if "frostbite" in p:
            self.add("frostbite", path)
        if name.endswith(".toc"):
            self.add("toc", path)
        if name.endswith((".sb", ".cas")):
            self.add("cas", path)
        if name == "project.godot" or name.startswith("godot"):
            self.add("godot", path)
        if "/renpy/" in "/" + p or name in ("renpy.exe", "renpy.py", "renpy.sh"):
            self.add("renpy", path)
        if name.endswith(".rpa"):
            self.add("rpa", path)
        if name.endswith((".rpy", ".rpyc")):
            self.add("rpy", path)
        if data:
            lower = data.lower()
            for marker, key in ((b"libil2cpp", "unity-il2cpp"), (b"unityplayer", "unity"),
                                (b"unrealengine", "ue-generic"), (b"frostbite", "frostbite"),
                                (b"godot engine", "godot"), (b"ren'py", "renpy")):
                if marker in lower:
                    self.add(key, f"{path}: embedded {marker.decode('ascii')} marker")

    def engines(self) -> list[dict]:
        e, result = self.items, []
        def add(key: str, name: str, keys: Sequence[str], confidence: str, note: str = "") -> None:
            result.append({"key": key, "name": name, "confidence": confidence,
                           "evidence": [item for k in keys for item in e.get(k, [])], "note": note})
        if "unity-il2cpp" in e:
            add("unity-il2cpp", "Unity (IL2CPP)", ["unity-il2cpp", "unity"], "high" if "unity" in e else "medium")
        if "unity-mono" in e:
            add("unity-mono", "Unity (Mono)", ["unity-mono", "unity"], "medium",
                "Both runtime markers may exist; verify the active game build." if "unity-il2cpp" in e else "")
        if "unity" in e and "unity-il2cpp" not in e and "unity-mono" not in e:
            add("unity-mono", "Unity (backend unknown)", ["unity"], "medium", "Do not assume Mono or IL2CPP without more evidence.")
        if any(k in e for k in ("utoc", "ucas", "ue-pak", "ue-assets", "ue4", "ue5", "ue-generic")):
            io = "utoc" in e or "ucas" in e
            if "ue5" in e and "ue4" not in e:
                name = "Unreal Engine 5" + (" (IoStore)" if io else "")
            elif "ue4" in e and "ue5" not in e:
                name = "Unreal Engine 4" + (" (IoStore)" if io else "")
            else:
                name = "Unreal Engine (IoStore; UE4.25+ or UE5)" if io else "Unreal Engine (version unknown)"
            note = "IoStore also exists in UE4; file extension alone cannot prove a UE major version." if io else "PAK names and asset extensions are heuristics."
            add("unreal", name, ["utoc", "ucas", "ue-pak", "ue-assets", "ue4", "ue5", "ue-generic"],
                "medium" if io or "ue5" in e or "ue4" in e else "low", note)
        if "source" in e:
            add("source", "Source Engine (or derivative)", ["source"], "medium")
        if "frostbite" in e or ("toc" in e and "cas" in e):
            add("frostbite", "Frostbite (possible)", ["frostbite", "toc", "cas"], "medium" if "frostbite" in e else "low")
        if "godot" in e:
            add("godot", "Godot", ["godot"], "medium")
        if "renpy" in e or ("rpa" in e and "rpy" in e):
            add("renpy", "Ren'Py", ["renpy", "rpa", "rpy"], "medium")
        if not result:
            add("custom", "Unknown / possible Custom C++ Engine", [], "unknown", "No engine can be inferred from missing markers.")
        return result


def _binary_candidate(name: str) -> bool:
    low = name.lower()
    return low == "eboot.bin" or low.endswith((".exe", ".dll", ".elf", ".so", ".sprx", ".nso", ".dylib"))


def analyze_path(path: str | Path) -> dict:
    target = Path(path)
    if not target.exists():
        raise ToolError(f"Path does not exist: {target}")
    evidence, binaries, notes = Evidence(), [], []
    count = 0

    def inspect_header(name: str, header: bytes, file_size: int) -> None:
        evidence.observe(name, header)
        if len(binaries) < MAX_BINARIES:
            binaries.append(asdict(parse_binary(header, name, file_size)))
        elif "Binary inspection limited to first 100 candidates" not in notes:
            notes.append("Binary inspection limited to first 100 candidates")

    def inspect_archive(archive: Path, prefix: str) -> None:
        nonlocal count
        try:
            with zipfile.ZipFile(archive) as zf:
                for entry in zf.infolist():
                    if count >= MAX_FILES:
                        _append_once(notes, f"File/entry limit of {MAX_FILES} reached")
                        break
                    if entry.is_dir():
                        continue
                    count += 1
                    label = f"{prefix}!/{entry.filename}"
                    evidence.observe(entry.filename)
                    if entry.flag_bits & 1:
                        _append_once(notes, "Encrypted ZIP entries not opened; filename evidence only")
                        continue
                    # IPA executables often lack a suffix. Read .app root entries as candidates.
                    parts = entry.filename.split("/")
                    app_executable = len(parts) >= 3 and parts[-2].lower().endswith(".app") and "." not in parts[-1]
                    if _binary_candidate(entry.filename) or app_executable:
                        if len(binaries) >= MAX_BINARIES:
                            _append_once(notes, f"Binary inspection limited to first {MAX_BINARIES} candidates")
                            continue
                        try:
                            with zf.open(entry) as f:
                                inspect_header(label, f.read(HEADER_LIMIT), entry.file_size)
                        except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, NotImplementedError, zlib.error) as exc:
                            _append_once(notes, f"Could not inspect archive entry {label}: {exc}")
        except (OSError, zipfile.BadZipFile) as exc:
            raise ToolError(f"Cannot inspect APK/IPA ZIP {archive}: {exc}") from exc

    if target.is_dir():
        evidence.observe(target.name + "/")
        for root, dirs, files in os.walk(target, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
            for dirname in dirs:
                evidence.observe(str((Path(root) / dirname).relative_to(target)) + "/")
            for name in sorted(files):
                if count >= MAX_FILES:
                    _append_once(notes, f"File/entry limit of {MAX_FILES} reached")
                    break
                candidate = Path(root) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                count += 1
                label = str(candidate.relative_to(target)).replace(os.sep, "/")
                evidence.observe(label)
                try:
                    if name.lower().endswith((".apk", ".ipa")):
                        inspect_archive(candidate, label)
                    elif _binary_candidate(name):
                        if len(binaries) >= MAX_BINARIES:
                            _append_once(notes, f"Binary inspection limited to first {MAX_BINARIES} candidates")
                        else:
                            with candidate.open("rb") as f:
                                inspect_header(label, f.read(HEADER_LIMIT), os.fstat(f.fileno()).st_size)
                except (OSError, ToolError) as exc:
                    _append_once(notes, f"Could not inspect {label}: {exc}")
            if count >= MAX_FILES:
                break
    elif target.is_file():
        evidence.observe(target.name)
        if target.suffix.lower() in (".apk", ".ipa"):
            inspect_archive(target, target.name)
        else:
            try:
                with target.open("rb") as f:
                    inspect_header(target.name, f.read(HEADER_LIMIT), os.fstat(f.fileno()).st_size)
                count = 1
            except OSError as exc:
                raise ToolError(f"Cannot read {target}: {exc}") from exc
    else:
        raise ToolError("Input must be a regular file or directory")
    return {"path": str(target), "files_seen": count, "engines": evidence.engines(),
            "binaries": binaries, "notes": notes,
            "limitations": [f"Binary signatures inspected only in first {HEADER_LIMIT} bytes",
                            "Heuristics are not proof of engine, DRM, CPU revision, or compatibility"]}


def print_analysis(report: dict) -> None:
    print(f"Analyzed: {report['path']} ({report['files_seen']} files/entries)")
    for engine in report["engines"]:
        print(f"\nEngine: {engine['name']} [confidence: {engine['confidence']}]")
        for item in engine["evidence"]:
            print(f"  evidence: {item}")
        if engine["note"]:
            print(f"  note: {engine['note']}")
        print("  Modding & Porting Playbook:")
        for step in PLAYBOOKS[engine["key"]]:
            print(f"    - {step}")
    for binary in report["binaries"]:
        print(f"\nBinary: {binary['path']}")
        print(f"  format: {binary['format']}; architecture: {binary['architecture']}; endian: {binary['endian']}")
        if binary["image_base"] is not None:
            print(f"  preferred image base: 0x{binary['image_base']:X} (not a runtime address)")
        for label in ("symbols", "protection", "notes"):
            for value in binary[label]:
                print(f"  {label}: {value}")
    for note in report["notes"] + report["limitations"]:
        print(f"\nNote: {note}")


def parse_pattern(text: str) -> list[int | None]:
    parts = text.split()
    if not parts:
        raise ToolError("Pattern must contain space-separated hex bytes and ?/?? wildcards")
    if len(parts) > MAX_PATTERN:
        raise ToolError(f"Pattern may contain at most {MAX_PATTERN} bytes")
    pattern: list[int | None] = []
    for part in parts:
        if part in ("?", "??"):
            pattern.append(None)
        elif re.fullmatch(r"[0-9a-fA-F]{2}", part):
            pattern.append(int(part, 16))
        else:
            raise ToolError(f"Invalid AOB token {part!r}; use two hex digits or ??")
    if all(byte is None for byte in pattern):
        raise ToolError("An all-wildcard pattern is unsafe and cannot identify a location")
    return pattern


def iter_aob_matches(data, pattern: Sequence[int | None]) -> Iterator[int]:
    """Yield all overlapping file offsets. data may be bytes or a read-only mmap."""
    if not pattern or len(pattern) > MAX_PATTERN or all(b is None for b in pattern):
        raise ToolError("Pattern must contain at least one fixed byte")
    best_start = best_len = run_start = run_len = 0
    for i in range(len(pattern) + 1):
        if i < len(pattern) and pattern[i] is not None:
            if not run_len:
                run_start = i
            run_len += 1
        else:
            if run_len > best_len:
                best_start, best_len = run_start, run_len
            run_len = 0
    anchor = bytes(pattern[best_start:best_start + best_len])
    start, total = 0, len(data)
    while True:
        hit = data.find(anchor, start)
        if hit < 0:
            return
        candidate = hit - best_start
        if candidate >= 0 and candidate + len(pattern) <= total:
            if all(value is None or data[candidate + i] == value for i, value in enumerate(pattern)):
                yield candidate
        start = hit + 1


def parse_hex_bytes(text: str, label: str) -> bytes:
    try:
        value = bytes.fromhex(text)
    except ValueError as exc:
        raise ToolError(f"{label} must be complete hex bytes without wildcards") from exc
    if not value:
        raise ToolError(f"{label} must not be empty")
    if len(value) > MAX_PATTERN:
        raise ToolError(f"{label} is limited to {MAX_PATTERN} bytes")
    return value


def _capstone(required: bool = False):
    try:
        import capstone
        return capstone
    except (ImportError, OSError) as exc:
        if required:
            raise ToolError("Capstone is required for --make-aob: python -m pip install -r requirements.txt") from exc
        return None


def choose_arch(report: BinaryReport, requested: str) -> str | None:
    inferred = {"x86_64": "x86_64", "ARM64": "arm64"}.get(report.architecture)
    if requested != "auto":
        known = {"x86_64", "x86", "ARM64", "ARM32", "PowerPC", "PowerPC64"}
        header_arches = set(report.architecture.split(", ")) & known
        expected_name = {"x86_64": "x86_64", "arm64": "ARM64"}[requested]
        if header_arches and expected_name not in header_arches:
            raise ToolError(f"Requested {requested}, but the binary header identifies {report.architecture}")
        return requested
    return inferred


def _disassembler(arch: str):
    cs = _capstone(required=True)
    if arch == "x86_64":
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    elif arch == "arm64":
        md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    else:
        raise ToolError("Disassembly/signature generation supports x86_64 and little-endian ARM64 only")
    md.detail = True
    return md


def make_aob(data: bytes, arch: str, minimum_length: int, address: int = 0) -> tuple[str, list[str]]:
    """Build a byte-wildcard signature from complete instructions starting at a known boundary.

    x86 memory displacements and relative branch immediates are masked. On ARM64,
    split bitfields cannot be represented by byte wildcards, so common PC-relative
    and memory-displacement instructions are conservatively masked in full.
    """
    if not 1 <= minimum_length <= MAX_PATTERN:
        raise ToolError(f"--length must be between 1 and {MAX_PATTERN}")
    if arch == "arm64" and (address % 4 or minimum_length % 4):
        raise ToolError("ARM64 start offset and --length must be 4-byte aligned")
    cs = _capstone(required=True)
    md = _disassembler(arch)
    masked: list[int | None] = []
    descriptions: list[str] = []
    consumed = 0
    for insn in md.disasm(data, address):
        if insn.address != address + consumed:
            break
        local: list[int | None] = list(insn.bytes)
        reasons = []
        if arch == "x86_64":
            # Capstone exposes encoding byte ranges, not just decoded operands.
            disp_offset, disp_size = insn.disp_offset, insn.disp_size
            if disp_size:
                if disp_offset + disp_size > len(local):
                    raise ToolError("Capstone reported an invalid displacement range")
                local[disp_offset:disp_offset + disp_size] = [None] * disp_size
                reasons.append("memory displacement")
            from capstone.x86_const import X86_OP_IMM
            direct_branch = (insn.group(cs.CS_GRP_JUMP) or insn.group(cs.CS_GRP_CALL)) and any(
                op.type == X86_OP_IMM for op in insn.operands)
            if direct_branch:
                imm_offset, imm_size = insn.imm_offset, insn.imm_size
                if imm_size and imm_offset + imm_size <= len(local):
                    local[imm_offset:imm_offset + imm_size] = [None] * imm_size
                else:
                    local = [None] * len(local)  # don't pretend an unknown encoding is stable
                reasons.append("relative branch")
        else:
            from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM
            direct_branch = (insn.group(cs.CS_GRP_JUMP) or insn.group(cs.CS_GRP_CALL)) and any(
                op.type == ARM64_OP_IMM for op in insn.operands)
            mnemonic = insn.mnemonic.lower()
            pc_address = mnemonic in ("adr", "adrp")
            literal = mnemonic in ("ldr", "ldrsw", "prfm") and any(op.type == ARM64_OP_IMM for op in insn.operands)
            has_memory = any(op.type == ARM64_OP_MEM for op in insn.operands)
            displacement = any(op.type == ARM64_OP_MEM and op.mem.disp != 0 for op in insn.operands)
            # In post-index addressing Capstone reports disp=0 and a separate
            # immediate operand (including an encoded zero), with writeback set.
            post_index = has_memory and insn.writeback and any(op.type == ARM64_OP_IMM for op in insn.operands)
            if direct_branch or pc_address or literal or displacement or post_index:
                local = [None] * len(local)
                if direct_branch: reasons.append("relative branch")
                if pc_address: reasons.append("PC-relative address")
                if literal: reasons.append("PC-relative literal")
                if displacement or post_index: reasons.append("memory displacement")
        masked.extend(local)
        consumed += insn.size
        descriptions.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}" +
                            (f"  [masked: {', '.join(reasons)}]" if reasons else ""))
        if consumed >= minimum_length:
            break
    if consumed < minimum_length:
        raise ToolError("Cannot decode enough complete instructions from that offset; check architecture, boundary and length")
    if len(masked) > MAX_PATTERN:
        raise ToolError("Instruction rounding exceeded the maximum pattern length")
    if not any(v is not None for v in masked):
        raise ToolError("All decoded bytes were masked; choose a longer distinctive region")
    return " ".join("??" if v is None else f"{v:02X}" for v in masked), descriptions


def _read_report(fileobj, path: str) -> BinaryReport:
    fileobj.seek(0)
    data = fileobj.read(HEADER_LIMIT)
    return parse_binary(data, path, os.fstat(fileobj.fileno()).st_size)


def _print_disassembly(mm, match: int, length: int, context: int, arch: str) -> None:
    md = _disassembler(arch)
    start = max(0, match - context)
    if arch == "arm64":
        start -= start % 4
    end = min(len(mm), match + length + context)
    print("    Approximate context (addresses are FILE offsets; earlier instruction boundaries may be wrong):")
    md.skipdata = True
    for insn in md.disasm(mm[start:end], start):
        marker = " ->" if insn.address == match else "   "
        raw = bytes(insn.bytes).hex(" ").upper()
        print(f"   {marker} 0x{insn.address:X}: {raw:<32} {insn.mnemonic} {insn.op_str}")
    if start != match:
        print("    Decode from the match itself (valid only if it is an instruction boundary):")
        md.skipdata = False
        for insn in md.disasm(mm[match:min(len(mm), match + length + context)], match):
            print(f"      0x{insn.address:X}: {bytes(insn.bytes).hex(' ').upper():<32} {insn.mnemonic} {insn.op_str}")


def scan_file(path: str | Path, pattern_text: str, arch: str = "auto", context: int = 16,
              max_matches: int = 0) -> int:
    pattern = parse_pattern(pattern_text)
    if not 0 <= context <= 128 or max_matches < 0:
        raise ToolError("--context must be 0..128 and --max-matches must be non-negative")
    try:
        with open(path, "rb") as f:
            report = _read_report(f, str(path))
            selected = choose_arch(report, arch)
            if selected == "arm64" and report.endian == "big":
                raise ToolError("Big-endian ARM64 disassembly is not supported")
            size = os.fstat(f.fileno()).st_size
            if not size:
                print("0 matches (empty file)")
                return 0
            if report.format.startswith(("PS4 SELF", "Nintendo Switch NSO", "Mach-O universal")):
                print("Warning: container/compression prevents reliable file-to-memory mapping; no decryption is performed.")
            cs = _capstone()
            if context and (not cs or not selected):
                print("Note: disassembly unavailable (install Capstone and select --arch x86_64/arm64).")
            count, truncated = 0, False
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for offset in iter_aob_matches(mm, pattern):
                    if max_matches and count >= max_matches:
                        truncated = True
                        break
                    count += 1
                    mapped = map_file_offset(report, offset)
                    line = f"Match {count}: file offset 0x{offset:X}"
                    if mapped:
                        line += f"; RVA 0x{mapped['rva']:X}; preferred image VA 0x{mapped['image_va']:X}"
                    else:
                        line += "; RVA unavailable (unmapped, ambiguous, or unsupported format)"
                    print(line)
                    if context and cs and selected:
                        _print_disassembly(mm, offset, len(pattern), context, selected)
            print(f"Matches: {count}" + (" (truncated by --max-matches)" if truncated else ""))
            print("RVA/VA are derived from file headers, not the live process or a verified GoldHEN offset.")
            return count
    except (OSError, ValueError) as exc:
        raise ToolError(f"Cannot scan {path}: {exc}") from exc


def make_file_aob(path: str | Path, offset: int, length: int, requested_arch: str) -> tuple[str, int]:
    if offset < 0:
        raise ToolError("--offset must be non-negative")
    try:
        with open(path, "rb") as f:
            report = _read_report(f, str(path))
            if report.format.startswith(("PS4 SELF", "Nintendo Switch NSO", "Mach-O universal")):
                raise ToolError("Make signatures from a verified unpacked executable, not this container")
            arch = choose_arch(report, requested_arch)
            if not arch:
                raise ToolError("Could not infer architecture; pass --arch x86_64 or --arch arm64")
            if arch == "arm64" and report.endian == "big":
                raise ToolError("Only little-endian ARM64 is supported")
            size = os.fstat(f.fileno()).st_size
            if offset >= size:
                raise ToolError("--offset is outside the file")
            if not 1 <= length <= MAX_PATTERN:
                raise ToolError(f"--length must be between 1 and {MAX_PATTERN}")
            f.seek(offset)
            # x86 instructions may extend beyond the requested minimum length.
            pattern, instructions = make_aob(f.read(length + 15), arch, length, offset)
            print(f"Architecture: {arch}; start must be a verified instruction boundary")
            for line in instructions:
                print("  " + line)
            print(f"AOB: {pattern}")
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                matches = sum(1 for _ in iter_aob_matches(mm, parse_pattern(pattern)))
            print(f"Matches in this file: {matches}")
            if matches != 1:
                print("WARNING: signature is not unique; expand the region and verify all candidate builds.")
            print("Relocations, changed constants, compiler choices and ARM64 bitfields can still invalidate signatures.")
            return pattern, matches
    except OSError as exc:
        raise ToolError(f"Cannot read {path}: {exc}") from exc


ANDROID_TEMPLATE = r'''// Explicit, offline patch primitives for memory owned by the calling application.
// No injector, automatic hook, or architecture translation is provided.
// Android NDK, arm64-v8a/API 24 example (join the two lines into one command):
//   $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++
//     -std=c++17 -fPIC -shared -fno-exceptions -fno-rtti -nostdlib++ android_arm64_hook.cpp -o liboffline_patch.so
// The absolute jump is a 16-byte branch stub, NOT a complete trampoline: it
// clobbers X17, and does not save or relocate displaced PC-relative instructions.
// Never substitute PS4/x86 bytes for independently verified Android ARM64 bytes.
// Stop all threads which might use the page; ensure it is readable, mapped,
// uniformly protected, and does not contain this patcher's currently executing code.
// Some Android kernels/policies reject permission changes. No operation is atomic.
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Return: 0 success; -1 invalid arguments; -2 expected bytes differ;
// -3 mprotect for writing failed; -4 bytes changed but restoring protection failed.
extern "C" int apply_offline_patch(void* address, const unsigned char* expected,
                                   const unsigned char* replacement, size_t size,
                                   int original_prot) {
    if (!address || !expected || !replacement || size == 0 ||
        !(original_prot & PROT_READ)) return -1;
    const long page_size_raw = sysconf(_SC_PAGESIZE);
    if (page_size_raw <= 0) return -1;
    const uintptr_t page_size = static_cast<uintptr_t>(page_size_raw);
    const uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    if (size > UINTPTR_MAX - addr || addr + size > UINTPTR_MAX - (page_size - 1)) return -1;
    const uintptr_t start = addr - addr % page_size;
    const uintptr_t end_unaligned = addr + size;
    const uintptr_t end = (end_unaligned + page_size - 1) / page_size * page_size;
    const size_t span = static_cast<size_t>(end - start);
    if (memcmp(address, expected, size) != 0) return -2;
#if defined(OFFLINE_PATCH_ALLOW_RWX)
    // Opt-in only: RWX can violate platform policy and weakens W^X isolation.
    const int writable = original_prot | PROT_READ | PROT_WRITE | PROT_EXEC;
#else
    // Safer default: temporarily remove execute while writing. Stop other threads.
    const int writable = (original_prot | PROT_READ | PROT_WRITE) & ~PROT_EXEC;
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, writable) != 0) return -3;
    memcpy(address, replacement, size);
#if defined(__GNUC__) || defined(__clang__)
    char* first = static_cast<char*>(address);
    __builtin___clear_cache(first, first + size);
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, original_prot) != 0) return -4;
    return 0;
}

// Emit little-endian: LDR X17, #8; BR X17; destination (64 bits).
// The caller owns output[0..15]. This encoder alone does not touch code pages.
extern "C" int encode_arm64_absolute_jump(unsigned char* output, size_t capacity,
                                          uint64_t destination) {
    if (!output || capacity < 16) return -1;
    const uint32_t words[2] = {0x58000051u, 0xD61F0220u};
    for (size_t i = 0; i < 2; ++i) {
        for (size_t byte = 0; byte < 4; ++byte)
            output[i * 4 + byte] = static_cast<unsigned char>(words[i] >> (byte * 8));
    }
    for (size_t byte = 0; byte < 8; ++byte)
        output[8 + byte] = static_cast<unsigned char>(destination >> (byte * 8));
    return 0;
}

// Caller must separately check the entire overwritten 16-byte ARM64 instruction
// sequence and provide an aligned, valid destination in the SAME process.
extern "C" int apply_offline_arm64_jump(void* address, const unsigned char* expected,
                                        uint64_t destination, int original_prot) {
    if (!address || !expected || !destination ||
        (reinterpret_cast<uintptr_t>(address) & 3u) || (destination & 3u)) return -1;
    unsigned char jump[16];
    if (encode_arm64_absolute_jump(jump, sizeof(jump), destination) != 0) return -1;
    return apply_offline_patch(address, expected, jump, sizeof(jump), original_prot);
}

#if defined(OFFLINE_PATCH_ENABLE_CONSTRUCTOR)
// Explicit opt-in initialization point. Intentionally does NOT discover targets
// or patch anything automatically; integrate it into your own application only.
__attribute__((constructor)) static void offline_patch_initialize() {
}
#endif
'''


def make_goldhen(title_id: str, version: str, game_name: str, mod_name: str,
                 process: str, runtime_offset: int, original: bytes, replacement: bytes,
                 author: str) -> dict:
    """Emit the well-observed GoldHEN repository subset, not an official JSON Schema."""
    if not re.fullmatch(r"CUSA[0-9]{5}", title_id):
        raise ToolError("--title-id must match CUSA followed by five digits")
    if not re.fullmatch(r"[0-9]{2}\.[0-9]{2}", version):
        raise ToolError("--version must be NN.NN (for example 01.00)")
    if not process or process in (".", "..") or "/" in process or "\\" in process or "\0" in process:
        raise ToolError("--process must be a single module filename")
    if not game_name.strip() or not mod_name.strip() or not author.strip():
        raise ToolError("Game name, mod name and author must not be empty")
    if not 0 <= runtime_offset <= 0xFFFFFFFFFFFFFFFF:
        raise ToolError("--goldhen-offset must be a non-negative 64-bit value")
    if not original or len(original) != len(replacement) or original == replacement:
        raise ToolError("ON and OFF must be different, nonempty and the same length")
    return {"name": game_name, "id": title_id, "version": version, "process": process,
            "mods": [{"name": mod_name, "type": "checkbox", "memory": [{
                "offset": f"{runtime_offset:X}", "on": replacement.hex().upper(),
                "off": original.hex().upper()}]}], "credits": [author]}


def _hash_original_and_patched(path: Path, offset: int, original: bytes, replacement: bytes) -> tuple[str, str]:
    before, after = hashlib.sha256(), hashlib.sha256()
    pos = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            before.update(chunk)
            left, right = max(offset, pos), min(offset + len(original), pos + len(chunk))
            if left < right:
                start, end = left - pos, right - pos
                repl_start = left - offset
                if chunk[start:end] != original[repl_start:repl_start + (right - left)]:
                    raise ToolError("Target bytes changed during generation")
                chunk = chunk[:start] + replacement[repl_start:repl_start + (right - left)] + chunk[end:]
            after.update(chunk)
            pos += len(chunk)
    return before.hexdigest(), after.hexdigest()


def make_patcher_source(offset: int, original: bytes, replacement: bytes,
                        original_sha: str, patched_sha: str) -> str:
    # Literal constants only; no supplied strings are executable code.
    constants = (f"OFFSET = {offset}\nORIGINAL = bytes.fromhex({original.hex()!r})\n"
                 f"PATCHED = bytes.fromhex({replacement.hex()!r})\n"
                 f"ORIGINAL_SHA256 = {original_sha!r}\nPATCHED_SHA256 = {patched_sha!r}\n")
    return '''#!/usr/bin/env python3
"""Patch only a verified offline copy; always writes a NEW file, never in-place."""
import argparse
import hashlib
from pathlib import Path
import sys

''' + constants + '''

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new file; existing files are never overwritten")
    parser.add_argument("--undo", action="store_true", help="restore from the exact patched copy")
    args = parser.parse_args()
    source, dest = args.input, args.output
    before, after = (PATCHED, ORIGINAL) if args.undo else (ORIGINAL, PATCHED)
    want_hash = PATCHED_SHA256 if args.undo else ORIGINAL_SHA256
    result_hash = ORIGINAL_SHA256 if args.undo else PATCHED_SHA256
    try:
        if source.resolve() == dest.resolve():
            raise ValueError("input and output must be different paths")
        if digest(source) != want_hash:
            raise ValueError("SHA-256 mismatch: this is not the exact expected build/copy")
        with source.open("rb") as src:
            src.seek(OFFSET)
            if src.read(len(before)) != before:
                raise ValueError("original bytes mismatch at offset")
            src.seek(0)
            # Exclusive creation prevents accidental overwrite, including via symlinks.
            created = False
            try:
                with dest.open("xb") as out:
                    created = True
                    remaining = OFFSET
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError("input became truncated")
                        out.write(chunk)
                        remaining -= len(chunk)
                    if src.read(len(before)) != before:
                        raise ValueError("input changed during patching")
                    out.write(after)
                    for chunk in iter(lambda: src.read(1024 * 1024), b""):
                        out.write(chunk)
                if digest(dest) != result_hash:
                    raise ValueError("output hash mismatch (input changed during patching)")
            except Exception:
                if created:
                    dest.unlink(missing_ok=True)
                raise
        print("Created", dest, "SHA-256", result_hash)
        return 0
    except (OSError, ValueError) as exc:
        print("Error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
'''


def generate_patch(args) -> list[Path]:
    path = Path(args.generate_patch)
    original = parse_hex_bytes(args.off, "--off (original bytes)")
    replacement = parse_hex_bytes(args.on, "--on (replacement bytes)")
    if len(original) != len(replacement) or original == replacement:
        raise ToolError("ON and OFF must be different, nonempty and the same length")
    # Validate user-supplied cheat metadata before touching outputs. The offset
    # is filled in later if it must be derived from a verified ELF64 mapping.
    cheat = None if args.file_only else make_goldhen(
        args.title_id, args.version, args.game_name, args.mod_name,
        args.process, args.goldhen_offset if args.goldhen_offset is not None else 0,
        original, replacement, args.author)
    derivation = None
    if (args.offset is None) == (args.aob is None):
        raise ToolError("Supply exactly one of --offset or --aob for the patch site")
    if args.aob is None and args.match_delta:
        raise ToolError("--match-delta applies only with --aob")
    try:
        with path.open("rb") as f:
            report = _read_report(f, str(path))
            # The GoldHEN JSON is PS4 x86-64. It must not silently reuse ARM or PC bytes.
            if not args.file_only:
                if args.arch not in ("auto", "x86_64"):
                    raise ToolError("GoldHEN output is x86_64; --arch must be auto or x86_64")
                if report.format.startswith(("PS4 SELF", "Nintendo Switch NSO", "PE", "Mach-O")):
                    raise ToolError("GoldHEN generation requires the exact PS4 x86_64 ELF or an explicitly verified raw dump, not a container/PC binary")
                if report.architecture != "unknown" and report.architecture != "x86_64":
                    raise ToolError(f"GoldHEN needs PS4 x86_64 bytes, not {report.architecture}")
                if report.architecture == "unknown":
                    if report.format != "unknown / raw":
                        raise ToolError("Unverified ELF architecture; use a valid PS4 x86_64 ELF or a verified raw dump")
                    if args.arch != "x86_64":
                        raise ToolError("For a raw dump, explicitly pass --arch x86_64 after verifying its origin")
            size = os.fstat(f.fileno()).st_size
            if not size:
                raise ToolError("Target file is empty")
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                if args.aob is not None:
                    matches = iter_aob_matches(mm, parse_pattern(args.aob))
                    first = next(matches, None)
                    if first is None:
                        raise ToolError("AOB did not match the target")
                    if next(matches, None) is not None:
                        raise ToolError("AOB matched more than once; refuse to choose a patch location")
                    offset = first + args.match_delta
                else:
                    offset = args.offset
                if offset < 0 or offset + len(original) > size:
                    raise ToolError("Patch extends outside the file")
                if mm[offset:offset + len(original)] != original:
                    raise ToolError("--off bytes do not match the target at the selected file offset")
                if not args.file_only and args.goldhen_offset is None:
                    if report.format != "ELF64":
                        raise ToolError("Automatic GoldHEN candidate requires ELF64; supply an independently verified --goldhen-offset for a raw dump")
                    derivation = derive_goldhen_candidate(mm, offset, len(original))
                    cheat = make_goldhen(args.title_id, args.version, args.game_name, args.mod_name,
                                         args.process, derivation["candidate_offset"], original, replacement, args.author)
                scanned_sha256 = hashlib.sha256(mm).hexdigest()
            before, after = _hash_original_and_patched(path, offset, original, replacement)
            if before != scanned_sha256:
                raise ToolError("Target changed during generation; no files were written")
    except OSError as exc:
        raise ToolError(f"Cannot read target: {exc}") from exc
    output = Path(args.out_dir)
    try:
        output.mkdir(parents=True, exist_ok=True)
        files = {output / "offline_file_patcher.py": make_patcher_source(offset, original, replacement, before, after)}
        if cheat is not None:
            files[output / f"{args.title_id}_{args.version}.json"] = json.dumps(cheat, indent=2, ensure_ascii=False) + "\n"
            files[output / "android_patch_template.cpp"] = ANDROID_TEMPLATE
            if derivation is not None:
                metadata = {"target_file": str(path), "target_sha256": before,
                            "title_id": args.title_id, "version": args.version,
                            "process": args.process, "derivation": derivation,
                            "warning": "Candidate only; GoldHEN module base, ASLR and game build must be independently verified."}
                files[output / "patch_metadata.json"] = json.dumps(metadata, indent=2, ensure_ascii=False) + "\n"
        if any(p.exists() or p.is_symlink() for p in files):
            raise ToolError("An output already exists; choose a new --out-dir (no files were overwritten)")
        created: list[Path] = []
        try:
            for outfile, content in files.items():
                with outfile.open("x", encoding="utf-8", newline="\n") as out:
                    created.append(outfile)
                    out.write(content)
        except Exception:
            for outfile in created:
                outfile.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise ToolError(f"Cannot write output: {exc}") from exc
    print(f"Verified target file offset 0x{offset:X}; original SHA-256 {before}")
    mapping = map_file_offset(report, offset)
    if mapping:
        print(f"Header-derived RVA 0x{mapping['rva']:X} (NOT necessarily a GoldHEN offset)")
    if cheat is not None:
        if derivation is None:
            print(f"GoldHEN offset 0x{args.goldhen_offset:X} was supplied by you and has NOT been verified.")
        else:
            seg = derivation["segment"]
            print(f"ELF64 PT_LOAD #{derivation['program_header_index']}: p_offset=0x{seg['p_offset']:X}, "
                  f"p_vaddr=0x{seg['p_vaddr']:X}, p_filesz=0x{seg['p_filesz']:X}, "
                  f"p_memsz=0x{seg['p_memsz']:X}, p_align=0x{seg['p_align']:X}, p_flags=0x{seg['p_flags']:X}")
            print("All PT_LOAD p_vaddr values: " + ", ".join(
                f"#{p['index']}=0x{p['p_vaddr']:X}" for p in derivation["load_segments"]))
            print(f"base_vaddr=min(PT_LOAD.p_vaddr)=0x{derivation['base_vaddr']:X}")
            print(f"vaddr=p_vaddr+(file_offset-p_offset)=0x{seg['p_vaddr']:X}+(0x{offset:X}-0x{seg['p_offset']:X})=0x{derivation['virtual_address']:X}")
            print(f"Candidate GoldHEN offset=vaddr-base_vaddr=0x{derivation['virtual_address']:X}-0x{derivation['base_vaddr']:X}=0x{derivation['candidate_offset']:X}")
            print("WARNING: candidate is NOT verified against GoldHEN runtime module base, ASLR or this game build.")
        print("Android template contains NO PS4 bytes: supply separately verified ARM64 address and code.")
    else:
        print("File-only mode: no GoldHEN cheat or Android template was generated.")
    for file in files:
        print(f"Wrote {file}")
    return list(files)



# v2: file formats and recovery. The CLI remains a single, copyable Python file.
# The bounds are intentional: do not trust lengths supplied by game archives.
MAX_OUTPUT_DEFAULT = 1024 * 1024 * 1024
MAX_DIRECTORY_SIZE = 16 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 50000
MAX_STREAM_CANDIDATES = 4096
SELF_MAGIC = b"\x4f\x15\x3d\x1d"
FMF_MAGIC = b"\x02\x01fmf"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _elf64_headers(data, start: int = 0, header_end: int | None = None,
                   backing_size: int | None = None) -> tuple[dict, list[dict]]:
    """Strict ELF64 header reader; offsets are relative to the ELF, not start."""
    bound = len(data) if header_end is None else min(header_end, len(data))
    if start < 0 or start + 64 > bound or data[start:start + 4] != b"\x7fELF":
        raise ToolError("Invalid or truncated ELF64 header")
    ident = data[start:start + 16]
    if ident[4] != 2 or ident[5] not in (1, 2) or ident[6] != 1:
        raise ToolError("A valid ELF64 with known endianness and ELF version is required")
    endian = "<" if ident[5] == 1 else ">"
    values = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, start)
    _, etype, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = values
    if version != 1 or ehsize != 64 or phnum == 0 or phnum >= 0xffff or phnum > 4096 or phsize < 56:
        raise ToolError("Invalid/unsupported ELF64 program-header count or sizes")
    if phoff < ehsize or start + phoff + phsize * phnum > bound:
        raise ToolError("ELF64 program-header table is truncated or overlaps the ELF header")
    header = dict(endian=endian, type=etype, machine=machine, entry=entry, phoff=phoff,
                  phentsize=phsize, phnum=phnum, shoff=shoff, flags=flags,
                  shentsize=shsize, shnum=shnum, shstrndx=shstr)
    programs = []
    for index in range(phnum):
        fields = struct.unpack_from(endian + "IIQQQQQQ", data, start + phoff + index * phsize)
        typ, pflags, off, va, pa, filesz, memsz, align = fields
        if off + filesz > (1 << 64) or va + memsz > (1 << 64):
            raise ToolError(f"ELF program header {index}: 64-bit range overflow")
        if typ == 1:  # PT_LOAD; validate all, never quietly ignore an invalid base.
            if filesz > memsz:
                raise ToolError(f"ELF PT_LOAD {index}: p_filesz exceeds p_memsz")
            if align > 1 and (align & (align - 1) or off % align != va % align):
                raise ToolError(f"ELF PT_LOAD {index}: invalid alignment/congruence")
            if backing_size is not None and off + filesz > backing_size:
                raise ToolError(f"ELF PT_LOAD {index}: file-backed range is truncated")
        programs.append(dict(index=index, type=typ, flags=pflags, offset=off, vaddr=va,
                             paddr=pa, filesz=filesz, memsz=memsz, align=align))
    return header, programs


def derive_goldhen_candidate(data, file_offset: int, length: int) -> dict:
    """The requested min(p_vaddr) formula, distinct from loader-aligned RVA."""
    header, programs = _elf64_headers(data, backing_size=len(data))
    if header["machine"] != 62 or header["endian"] != "<":
        raise ToolError("GoldHEN candidate requires a little-endian x86-64 ELF64")
    loads = [p for p in programs if p["type"] == 1]
    if not loads:
        raise ToolError("ELF has no PT_LOAD; supply an independently verified --goldhen-offset")
    if length <= 0 or file_offset < 0 or file_offset + length > len(data):
        raise ToolError("Patch range extends outside the ELF")
    overlapping = [p for p in loads if p["filesz"] and
                   file_offset < p["offset"] + p["filesz"] and
                   file_offset + length > p["offset"]]
    containing = [p for p in overlapping if p["offset"] <= file_offset and
                  file_offset + length <= p["offset"] + p["filesz"]]
    if len(overlapping) > 1:
        raise ToolError("Patch range overlaps multiple PT_LOAD segments; mapping is ambiguous; use a verified --goldhen-offset")
    if len(containing) != 1:
        raise ToolError("Entire patch range is not within one file-backed PT_LOAD; use a verified --goldhen-offset")
    seg = containing[0]
    base = min(p["vaddr"] for p in loads)
    va = seg["vaddr"] + file_offset - seg["offset"]
    candidate = va - base
    if not 0 <= candidate <= 0xffffffffffffffff:
        raise ToolError("ELF-derived candidate is outside the 64-bit range")
    return {
        "method": "ELF64 PT_LOAD image-relative candidate (not runtime verified)",
        "formula": "p_vaddr + (file_offset - p_offset) - min(PT_LOAD.p_vaddr)",
        "file_offset": file_offset, "patch_length": length,
        "base_vaddr": base, "program_header_index": seg["index"],
        "load_segments": [{"index": p["index"], "p_offset": p["offset"],
                           "p_vaddr": p["vaddr"], "p_filesz": p["filesz"],
                           "p_memsz": p["memsz"], "p_align": p["align"], "p_flags": p["flags"]}
                          for p in loads],
        "segment": {"p_offset": seg["offset"], "p_vaddr": seg["vaddr"],
                    "p_filesz": seg["filesz"], "p_memsz": seg["memsz"],
                    "p_align": seg["align"], "p_flags": seg["flags"]},
        "virtual_address": va, "candidate_offset": candidate,
        "runtime_verified": False,
    }


def _inflate_at(data, offset: int, end: int, limit: int, *, exact: bool = False) -> tuple[bytes, int]:
    """Decode one zlib stream incrementally, capped before allocating output."""
    decoder = zlib.decompressobj()
    parts = bytearray()
    pos = offset
    try:
        while pos < end and not decoder.eof:
            chunk = data[pos:min(end, pos + 65536)]
            pos += len(chunk)
            while chunk and not decoder.eof:
                result = decoder.decompress(chunk, limit + 1 - len(parts))
                parts.extend(result)
                if len(parts) > limit:
                    raise ToolError("zlib decompressed data exceeds the configured output limit")
                chunk = decoder.unconsumed_tail
        if not decoder.eof:
            raise ToolError("Truncated zlib stream")
        consumed = pos - len(decoder.unused_data) - offset
        if exact and consumed != end - offset:
            raise ToolError("Unexpected trailing bytes after zlib stream")
        return bytes(parts), consumed
    except zlib.error as exc:
        raise ToolError(f"Invalid or unsupported zlib stream: {exc}") from exc


def _zstd_at(data, offset: int, end: int, limit: int, *, exact: bool = False) -> tuple[bytes, int]:
    """Decode one Zstandard frame with small input chunks and an output cap."""
    try:
        import zstandard as zstd
    except ImportError as exc:
        raise ToolError("Zstandard support requires: python -m pip install zstandard") from exc
    # Small compressed chunks bound temporary expansion before we can check it.
    try:
        params = zstd.get_frame_parameters(bytes(data[offset:min(end, offset + 18)]))
        max_window = max(limit, 1024 * 1024)
        if params.window_size > max_window:
            raise ToolError("Zstandard frame window exceeds the configured output limit")
        if params.content_size not in (zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR) and params.content_size > limit:
            raise ToolError("Zstandard decompressed data exceeds the configured output limit")
        if params.dict_id:
            raise ToolError("Zstandard frames requiring a dictionary are unsupported")
        decoder = zstd.ZstdDecompressor(max_window_size=max_window).decompressobj()
        parts = bytearray()
        pos = offset
        while pos < end and not decoder.eof:
            chunk = data[pos:min(end, pos + 256)]
            pos += len(chunk)
            parts.extend(decoder.decompress(chunk))
            if len(parts) > limit:
                raise ToolError("Zstandard decompressed data exceeds the configured output limit")
        if not decoder.eof:
            raise ToolError("Truncated Zstandard frame")
        consumed = pos - len(decoder.unused_data) - offset
        if exact and consumed != end - offset:
            raise ToolError("Unexpected trailing bytes after Zstandard frame")
        return bytes(parts), consumed
    except zstd.ZstdError as exc:
        raise ToolError(f"Invalid or unsupported Zstandard frame: {exc}") from exc


def lz4_raw_decode(data: bytes, expected_size: int) -> bytes:
    """Decode a raw LZ4 block, with no C extension or stored size prefix."""
    if expected_size < 0:
        raise ToolError("Negative LZ4 output size")
    if not data:
        if expected_size == 0:
            return b""
        raise ToolError("Empty LZ4 block")
    out = bytearray()
    pos = 0

    def extended_length(initial: int) -> int:
        nonlocal pos
        count = initial
        if initial == 15:
            while True:
                if pos >= len(data):
                    raise ToolError("Truncated LZ4 length")
                value = data[pos]
                pos += 1
                count += value
                if count > expected_size:
                    raise ToolError("LZ4 output exceeds the declared segment size")
                if value != 255:
                    break
        return count

    while pos < len(data):
        token = data[pos]
        pos += 1
        literal_length = extended_length(token >> 4)
        if pos + literal_length > len(data) or len(out) + literal_length > expected_size:
            raise ToolError("Invalid LZ4 literal range or output size")
        out.extend(data[pos:pos + literal_length])
        pos += literal_length
        if pos == len(data):
            break
        if pos + 2 > len(data):
            raise ToolError("Truncated LZ4 match offset")
        distance = data[pos] | data[pos + 1] << 8
        pos += 2
        if distance == 0 or distance > len(out):
            raise ToolError("Invalid LZ4 match offset")
        match_length = extended_length(token & 15) + 4
        if len(out) + match_length > expected_size:
            raise ToolError("LZ4 match exceeds the declared segment size")
        # LZ4 matches can overlap their own output: repeat the referenced pattern.
        pattern = bytes(out[-distance:])
        out.extend((pattern * ((match_length + distance - 1) // distance))[:match_length])
    if len(out) != expected_size:
        raise ToolError(f"LZ4 size mismatch: expected {expected_size}, got {len(out)}")
    return bytes(out)


def _bounded_range(offset: int, size: int, end: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > end or size > end - offset:
        raise ToolError(f"{label} is outside the input file")


def _write_sized_at(out, offset: int, payload: bytes, previous: list[tuple[int, int]]) -> None:
    """Write a range only if overlaps with previously written ranges agree."""
    end = offset + len(payload)
    for low, high in previous:
        a, b = max(low, offset), min(high, end)
        if a < b:
            out.seek(a)
            if out.read(b - a) != payload[a - offset:b - offset]:
                raise ToolError("Conflicting overlapping SELF segments")
    out.seek(offset)
    out.write(payload)
    previous.append((offset, end))


def _range_covered(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    pos = start
    for a, b in sorted(ranges):
        if a > pos:
            break
        pos = max(pos, b)
        if pos >= end:
            return True
    return start == end


def _unpack_self(data, out, max_output: int) -> list[str]:
    if len(data) < 32 or data[:4] != SELF_MAGIC:
        raise ToolError("Not a PS4 SELF/FSELF")
    _, version, _mode, endian, _attr, _key, header_size, _meta, file_size, count, _flags, _pad = struct.unpack_from("<IBBBBIHHQHHI", data, 0)
    if endian != 1 or count == 0 or count > 4096:
        raise ToolError("Unsupported SELF header endianness or entry count")
    if file_size < 32 or file_size > len(data):
        raise ToolError("Invalid SELF declared file size")
    elf_start = 32 + count * 32
    if header_size > file_size or header_size < elf_start + 64:
        raise ToolError("SELF header size does not contain the ELF header")
    header, phdrs = _elf64_headers(data, elf_start, header_size)
    if header["endian"] != "<" or header["machine"] != 62:
        raise ToolError("Only little-endian x86-64 PS4 SELF/FSELF is supported")
    ph_end = header["phoff"] + header["phentsize"] * header["phnum"]
    segments: list[tuple[dict, int, int, int, int]] = []
    seen: set[int] = set()
    for index in range(count):
        props, off, size, mem_size = struct.unpack_from("<QQQQ", data, 32 + 32 * index)
        if not props & 0x800:
            continue  # non-blocked digest/metadata entry, not program payload
        seg_id = (props >> 20) & 0xfff
        if props & 0x2:
            raise ToolError(f"SELF segment {seg_id} is encrypted; retail decryption is not supported")
        if seg_id >= len(phdrs) or seg_id in seen:
            raise ToolError("SELF blocked entries have invalid or duplicate program-header indices")
        if off < header_size:
            raise ToolError("SELF payload overlaps its header")
        _bounded_range(off, size, file_size, f"SELF segment {seg_id}")
        ph = phdrs[seg_id]
        if ph["filesz"] > max_output or ph["offset"] + ph["filesz"] > max_output:
            raise ToolError("SELF reconstructed ELF exceeds --max-output-mb")
        if mem_size != ph["filesz"]:
            raise ToolError(f"SELF segment {seg_id} uncompressed size does not match ELF p_filesz")
        seen.add(seg_id)
        segments.append((ph, props, off, size, mem_size))
    if not segments:
        raise ToolError("SELF has no supported unencrypted blocked segments")
    output_size = max([ph_end] + [p["offset"] + p["filesz"] for p in phdrs])
    if output_size > max_output:
        raise ToolError("SELF reconstructed ELF exceeds --max-output-mb")
    ranges: list[tuple[int, int]] = []
    for ph, props, off, size, mem_size in segments:
        if props & 0x8:
            payload, _ = _inflate_at(data, off, off + size, mem_size, exact=True)
        else:
            payload = bytes(data[off:off + size])
        if len(payload) != ph["filesz"]:
            raise ToolError(f"SELF segment {ph['index']} size mismatch; unsupported compression or encryption")
        _write_sized_at(out, ph["offset"], payload, ranges)
    # Some ELF metadata program headers point inside a stored segment. Do not
    # silently invent missing content except the known optional PS4 version blob.
    missing_versions = []
    for ph in phdrs:
        if ph["filesz"] and not _range_covered(ph["offset"], ph["offset"] + ph["filesz"], ranges + [(0, ph_end)]):
            if ph["type"] == 0x6fffff01:  # PT_SCE_VERSION is often absent
                missing_versions.append(ph["index"])
            else:
                raise ToolError(f"SELF ELF program header {ph['index']} has no reconstructible data")
    # Only ELF headers and program headers are reliably embedded; strip stale
    # section-table references. Preserve program header stride/extensions.
    elf_head = bytearray(data[elf_start:elf_start + ph_end])
    struct.pack_into("<Q", elf_head, 40, 0)       # e_shoff
    struct.pack_into("<HHH", elf_head, 58, 0, 0, 0)
    for index in missing_versions:
        struct.pack_into("<Q", elf_head, header["phoff"] + index * header["phentsize"] + 32, 0)
    out.seek(0)
    out.write(elf_head)
    out.truncate(output_size)
    result = [f"PS4 SELF v{version}: reconstructed {len(segments)} plaintext segment(s); section table omitted.",
              "SELF flags are not proof of authenticity or plaintext; no decryption was attempted."]
    if missing_versions:
        result.append("WARNING: missing PT_SCE_VERSION data omitted from ELF program header(s): " + ", ".join(map(str, missing_versions)))
    return result


def _unpack_nso(data, out, max_output: int) -> list[str]:
    if len(data) < 0x100 or data[:4] != b"NSO0":
        raise ToolError("Not a complete NSO0 header")
    version, _reserved, flags = struct.unpack_from("<III", data, 4)
    if version != 0:
        raise ToolError(f"Unsupported NSO0 version {version}")
    if flags & 0x80:
        raise ToolError("NSO ZBIC compression is unsupported; it is not raw LZ4")
    bss = struct.unpack_from("<I", data, 0x3c)[0]
    stored_sizes = struct.unpack_from("<III", data, 0x60)
    descriptors = []
    ranges = []
    memory_ranges = []
    for i, name in enumerate(("text", "rodata", "data")):
        off, va, size, _extra = struct.unpack_from("<IIII", data, 0x10 + 0x10 * i)
        stored = stored_sizes[i] if flags & (1 << i) else size
        if size > max_output or stored > max_output:
            raise ToolError(f"NSO {name} exceeds --max-output-mb")
        if stored and off < 0x100:
            raise ToolError(f"NSO {name} overlaps its header")
        _bounded_range(off, stored, len(data), f"NSO {name}")
        if stored and any(off < b and a < off + stored for a, b in ranges):
            raise ToolError("NSO input segments overlap")
        ranges.append((off, off + stored))
        memsz = size + (bss if i == 2 else 0)
        if va + memsz > (1 << 32):
            raise ToolError(f"NSO {name} memory range overflows")
        if memsz and any(va < b and a < va + memsz for a, b in memory_ranges):
            raise ToolError("NSO memory segments overlap")
        memory_ranges.append((va, va + memsz))
        descriptors.append((name, off, va, size, stored, memsz))
    if not descriptors[0][3]:
        raise ToolError("NSO text segment is empty")
    # Valid ELF64 ET_DYN with no entry point/sections: analysis artifact only.
    phoff, phsize = 64, 56
    cursor = phoff + 3 * phsize
    phdrs = []
    segments = []
    for i, (name, off, va, size, stored, memsz) in enumerate(descriptors):
        payload = bytes(data[off:off + stored])
        if flags & (1 << i):
            payload = lz4_raw_decode(payload, size)
        if len(payload) != size:
            raise ToolError(f"NSO {name} size mismatch")
        if flags & (1 << (i + 3)):
            if hashlib.sha256(payload).digest() != data[0xa0 + i * 32:0xc0 + i * 32]:
                raise ToolError(f"NSO {name} SHA-256 mismatch")
        # ELF PT_LOAD offset/vaddr must be congruent modulo p_align.
        file_off = ((cursor + 0xfff) // 0x1000) * 0x1000 + (va % 0x1000)
        cursor = file_off + size
        if cursor > max_output:
            raise ToolError("NSO reconstructed ELF exceeds --max-output-mb")
        phdrs.append((1, (5, 4, 6)[i], file_off, va, va, size, memsz, 0x1000))
        segments.append((file_off, payload))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, phoff, 0, 0, 64, phsize, 3, 0, 0, 0)
    out.seek(0)
    out.write(ehdr)
    for ph in phdrs:
        out.write(struct.pack("<IIQQQQQQ", *ph))
    for file_off, payload in segments:
        out.seek(file_off)
        out.write(payload)
    out.truncate(cursor)
    return ["NSO0 -> ELF64 ET_DYN, EM_AARCH64, text/rodata/data and BSS reconstructed for analysis.",
            "WARNING: NSO0 does not encode the CPU; ARM64 is an assumption, not detection. This ELF is not guaranteed runnable."]


def unpack_binary(source: Path, destination: Path, max_output: int = MAX_OUTPUT_DEFAULT) -> None:
    if max_output <= 0:
        raise ToolError("--max-output-mb must be positive")
    if source.resolve() == destination.resolve():
        raise ToolError("Input and output must be different files")
    if destination.exists() or destination.is_symlink():
        raise ToolError("Output already exists; no file was overwritten")
    with source.open("rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            raise ToolError("Input file is empty")
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if data[:4] not in (SELF_MAGIC, b"NSO0"):
                raise ToolError("Unsupported input: expected PS4 SELF/FSELF or NSO0")
            destination.parent.mkdir(parents=True, exist_ok=True)
            created = False
            try:
                with destination.open("x+b") as out:
                    created = True
                    if data[:4] == SELF_MAGIC:
                        messages = _unpack_self(data, out, max_output)
                    else:
                        messages = _unpack_nso(data, out, max_output)
            except Exception:
                if created:
                    destination.unlink(missing_ok=True)
                raise
    for line in messages:
        print(line)
    print(f"Wrote {destination}")


class _FMFLayoutError(Exception):
    """Directory bytes did not match a known FMF layout."""


class _FMFReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise _FMFLayoutError("truncated directory")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "little")

    def name(self, modern: bool, *, root: bool = False) -> str:
        count = self.number(4)
        if count > 4096:
            raise _FMFLayoutError("directory name length is out of range")
        raw = self.take(count if modern else count * 2)
        if not modern and (count or not root):
            if self.take(2) != b"\0\0":
                raise _FMFLayoutError("missing UTF-16 name terminator")
        try:
            if modern:
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1")  # GameExtractor byte-string fallback
            return raw.decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise _FMFLayoutError("invalid name encoding") from exc


def _safe_fmf_component(name: str) -> None:
    # Reject Windows and POSIX path separators, drives, stream suffixes and
    # special names regardless of the platform on which extraction is run.
    if (not name or name in (".", "..") or len(name) > 255 or
            any(ord(c) < 32 or c in '/\\:*?"<>|' for c in name) or
            name[-1:] in (".", " ") or
            re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", name)):
        raise ToolError(f"Unsafe or non-portable FMF path component: {name!r}")


def _parse_fmf_directory(raw: bytes, modern: bool, data_end: int) -> list[dict]:
    reader = _FMFReader(raw)
    entries: list[dict] = []
    seen_paths: set[str] = set()
    seen_files: set[str] = set()
    seen_dirs: set[str] = set()
    directory_count = 0

    def key(parts: tuple[str, ...]) -> str:
        return "/".join(unicodedata.normalize("NFC", p).casefold() for p in parts)

    def read_dir(parent: tuple[str, ...], depth: int) -> None:
        nonlocal directory_count
        directory_count += 1
        if directory_count > MAX_ARCHIVE_ENTRIES:
            raise ToolError("FMF directory count exceeds the safety limit")
        if depth > 64:
            raise ToolError("FMF directory nesting exceeds the safety limit")
        name = reader.name(modern, root=(depth == 0))
        if name:
            _safe_fmf_component(name)
            parent = parent + (name,)
            dkey = key(parent)
            if dkey in seen_dirs or dkey in seen_files:
                raise ToolError("FMF contains case-insensitive directory/path collisions")
            seen_dirs.add(dkey)
        elif depth:
            raise _FMFLayoutError("empty non-root directory")
        count = reader.number(4 if modern else 2)
        if count > MAX_ARCHIVE_ENTRIES or len(entries) + count > MAX_ARCHIVE_ENTRIES:
            raise _FMFLayoutError("file count is out of range")
        for _ in range(count):
            stem = reader.name(modern)
            ext = reader.name(modern)
            filename = stem + ext
            _safe_fmf_component(filename)
            parts = parent + (filename,)
            pkey = key(parts)
            if pkey in seen_paths or pkey in seen_dirs:
                raise ToolError("FMF contains case-insensitive duplicate/colliding paths")
            seen_paths.add(pkey)
            seen_files.add(pkey)
            width = 8 if modern else 4
            offset, size, expanded = reader.number(width), reader.number(width), reader.number(width)
            if modern:
                reader.take(16)  # timestamps/unknowns
            offset += 26 if modern else 18
            if offset > data_end or size > data_end - offset:
                raise _FMFLayoutError("payload range extends beyond the file-data area")
            entries.append({"path": "/".join(parts), "offset": offset, "size": size,
                            "expanded_size": expanded if expanded else size,
                            "compressed": expanded != 0 and expanded != size})
        dirs = reader.number(4 if modern else 2)
        if dirs > 1000:
            raise _FMFLayoutError("subdirectory count is out of range")
        for _ in range(dirs):
            read_dir(parent, depth + 1)

    read_dir((), 0)
    if reader.data[reader.pos:].strip(b"\0"):
        raise _FMFLayoutError("unrecognized directory trailer")
    return entries


def _fmf_index(data) -> dict | None:
    if len(data) < 5 or data[:5] != FMF_MAGIC:
        raise ToolError("Not an FMF file: expected magic 02 01 66 6D 66")
    if len(data) < 13:
        return None
    # Modern archives use a 64-bit relative pointer; the older layout uses 32.
    relatives = []
    if len(data) >= 17:
        relatives.append(struct.unpack_from("<Q", data, 9)[0])
    relatives.append(struct.unpack_from("<I", data, 9)[0])
    directory = next((value + 9 for value in relatives if value + 9 >= 13 and
                      value + 18 <= len(data) and data[value + 9:value + 14] == FMF_MAGIC), None)
    if directory is None:
        return None
    start = directory + 9
    # Some resource archives prefix the frame with a u32 compressed length;
    # other known archives place the frame directly after the nested header.
    def looks_compressed(position: int) -> bool:
        if data[position:position + 4] == ZSTD_MAGIC:
            return True
        if position + 2 > len(data):
            return False
        cmf, flg = data[position], data[position + 1]
        return cmf & 15 == 8 and cmf >> 4 <= 7 and not (flg & 0x20) and ((cmf << 8) + flg) % 31 == 0

    declared = None
    if start + 6 <= len(data) and not looks_compressed(start) and looks_compressed(start + 4):
        declared = struct.unpack_from("<I", data, start)[0]
        start += 4
        _bounded_range(start, declared, len(data), "FMF directory frame")
    end = start + declared if declared is not None else len(data)
    if data[start:start + 4] == ZSTD_MAGIC:
        directory_data, consumed = _zstd_at(data, start, end, MAX_DIRECTORY_SIZE, exact=declared is not None)
        codec = "zstd"
    else:
        directory_data, consumed = _inflate_at(data, start, end, MAX_DIRECTORY_SIZE, exact=declared is not None)
        codec = "zlib"
    errors = []
    for modern in (True, False):
        try:
            entries = _parse_fmf_directory(directory_data, modern, directory)
            if modern and len(data) > 25 and data[25] == 3:
                for entry in entries:
                    if entry["size"] and data[entry["offset"]:entry["offset"] + 4] != ZSTD_MAGIC:
                        raise ToolError(f"FMF declares Zstandard but {entry['path']} is not a Zstandard frame; unsupported or encrypted payload")
                    if entry["size"]:
                        entry["compressed"] = True
            return {"format": "FMF 2020-style" if modern else "FMF legacy UTF-16",
                    "directory_offset": directory, "directory_codec": codec,
                    "directory_length_prefix": declared, "directory_compressed_size": consumed, "entries": entries}
        except _FMFLayoutError as exc:
            errors.append(str(exc))
    raise ToolError("FMF directory exists but its layout is unsupported or corrupt (" + "; ".join(errors) + "); use --carve only for approximate stream recovery")


# RFC 1950 headers with no preset dictionary; lookahead catches overlaps.
_ZLIB_HEADERS = b"|".join(
    re.escape(bytes((cmf, flg)))
    for cmf in range(8, 0x79, 16)
    for flg in range(256)
    if not (flg & 0x20) and ((cmf << 8) + flg) % 31 == 0
)
_STREAM_RE = re.compile(b"(?=(" + re.escape(ZSTD_MAGIC) + b"|" + _ZLIB_HEADERS + b"))")


def _fmf_stream_headers(data, maximum: int = MAX_STREAM_CANDIDATES) -> tuple[list[tuple[int, str]], bool]:
    candidates = []
    for match in _STREAM_RE.finditer(data, 5):
        candidates.append((match.start(), "zstd" if match.group(1) == ZSTD_MAGIC else "zlib"))
        if len(candidates) >= maximum:
            return candidates, True
    return candidates, False


def fmf_info(path: Path, as_json: bool = False) -> None:
    with path.open("rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            raise ToolError("FMF input is empty")
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            index = _fmf_index(data)
            headers, capped = _fmf_stream_headers(data)
            info = {"file": str(path), "size": len(data), "magic": "02 01 66 6D 66",
                    "index": index, "stream_candidates": [{"offset": off, "codec": codec} for off, codec in headers],
                    "candidate_limit_reached": capped,
                    "warning": "Stream headers are candidates, not proof of a valid stream. FMF versions and variants are not comprehensively verified."}
    if as_json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
    else:
        print(f"FMF: {path} ({info['size']} bytes), magic {info['magic']}")
        if index:
            print(f"Index: {index['format']}, {index['directory_codec']} directory at 0x{index['directory_offset']:X}; {len(index['entries'])} file(s)")
            for entry in index["entries"]:
                print(f"  {entry['path']}: offset 0x{entry['offset']:X}, stored {entry['size']}, expanded {entry['expanded_size']}" + (" (compressed)" if entry["compressed"] else ""))
        else:
            print("No supported directory index found; --fmf-unpack can only recover unnamed streams.")
        print(f"Possible stream headers: {len(headers)}" + (" (limit reached)" if capped else ""))
        for offset, codec in headers[:100]:
            print(f"  0x{offset:X} {codec} (unverified)")
        print(info["warning"])


def _fmf_indexed_payload(data, entry: dict, remaining: int) -> bytes:
    start, size, expanded = entry["offset"], entry["size"], entry["expanded_size"]
    if expanded > remaining:
        raise ToolError("FMF extraction exceeds --max-output-mb")
    if not entry["compressed"]:
        return bytes(data[start:start + size])
    if data[start:start + 4] == ZSTD_MAGIC:
        payload, _ = _zstd_at(data, start, start + size, expanded, exact=True)
    else:
        payload, _ = _inflate_at(data, start, start + size, expanded, exact=True)
    if len(payload) != expanded:
        raise ToolError(f"FMF payload size mismatch for {entry['path']}")
    return payload


def _carve_fmf_streams(data, max_output: int) -> tuple[list[dict], bool]:
    headers, capped = _fmf_stream_headers(data)
    recovered: list[dict] = []
    consumed_until = 5
    remaining = max_output
    zstd_missing = False
    for offset, codec in headers:
        if offset < consumed_until:
            continue
        try:
            if codec == "zstd":
                payload, length = _zstd_at(data, offset, len(data), remaining)
            else:
                payload, length = _inflate_at(data, offset, len(data), remaining)
        except ToolError as exc:
            message = str(exc)
            if "exceeds the configured output limit" in message:
                raise ToolError("FMF stream recovery exceeds --max-output-mb") from exc
            if "requires: python -m pip install zstandard" in message:
                zstd_missing = True
            continue  # a candidate signature is often a false positive
        consumed_until = offset + length
        remaining -= len(payload)
        extension = ".xml" if payload.lstrip().startswith(b"<?xml") else ".bin"
        recovered.append({"path": f"stream_{offset:08x}{extension}", "payload": payload,
                          "offset": offset, "codec": codec})
    if zstd_missing:
        print("WARNING: zstd candidates could not be examined; install zstandard.", file=sys.stderr)
    if not recovered:
        raise ToolError("No valid zlib/zstd streams recovered; the FMF variant or compression may be unsupported")
    return recovered, capped


def fmf_unpack(source: Path, destination: Path, max_output: int = MAX_OUTPUT_DEFAULT, *, carve: bool = False) -> None:
    if destination.exists() or destination.is_symlink():
        raise ToolError("Output directory already exists; no files were overwritten")
    if max_output <= 0:
        raise ToolError("--max-output-mb must be positive")
    with source.open("rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            raise ToolError("FMF input is empty")
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if data[:5] != FMF_MAGIC:
                raise ToolError("Not an FMF file: expected magic 02 01 66 6D 66")
            index = None if carve else _fmf_index(data)
            if index:
                if sum(e["expanded_size"] for e in index["entries"]) > max_output:
                    raise ToolError("FMF total expanded size exceeds --max-output-mb")
                records = index["entries"]
                print(f"Using {index['format']} directory; preserving indexed paths.")
            else:
                records, capped = _carve_fmf_streams(data, max_output)
                print("WARNING: stream carving is approximate; original filenames/directories cannot be recovered without an index.")
                if capped:
                    print("WARNING: stream candidate limit reached; recovery may be incomplete.")
            destination.parent.mkdir(parents=True, exist_ok=True)
            created = False
            try:
                destination.mkdir()
                created = True
                total = 0
                for entry in records:
                    # Indexed components were validated before any writes. Carved
                    # names are generated by us, never taken from input bytes.
                    target = destination.joinpath(*entry["path"].split("/"))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    payload = entry["payload"] if index is None else _fmf_indexed_payload(data, entry, max_output - total)
                    total += len(payload)
                    with target.open("xb") as out:
                        out.write(payload)
                    print(f"  {entry['path']} ({len(payload)} bytes)")
            except Exception:
                if created:
                    shutil.rmtree(destination)
                raise
    print(f"Wrote {len(records)} file(s) to {destination}")


_XML_PARTS = re.compile(r"(<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>)", re.DOTALL)
_XML_TAG = re.compile(r"<(?![!?/])(?:[^<>\"']|\"[^\"]*\"|'[^']*')*>" , re.DOTALL)
_XML_ATTR = re.compile(r"(?P<name>[^\s/=<>\"']+)\s*=\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)", re.DOTALL)
_PATH_ATTRIBUTES = {"from", "path", "file", "filename", "src"}


def _rewrite_config_paths(raw: bytes, known_paths: set[str] | None = None,
                          config_dir: tuple[str, ...] = ()) -> tuple[bytes, int, int]:
    if len(raw) > 4 * 1024 * 1024:
        raise ToolError("config.xml exceeds the 4 MiB safety limit")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif raw.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"
    try:
        text = raw.decode(encoding)
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ToolError("config.xml with DTD/entity declarations is not supported")
        ET.fromstring(text)
    except (UnicodeError, ET.ParseError) as exc:
        raise ToolError(f"Cannot safely parse config.xml: {exc}") from exc
    changed, skipped = 0, 0

    def resolves_to_local(value: str) -> bool:
        # FM configs use both from/to as virtual IDs in some contexts and real
        # paths in others. Change them only if a local file/directory (or a
        # filename without its extension) actually matches.
        if known_paths is None or value.startswith(("/", "\\")) or ":" in value:
            return False
        parts = value.replace("\\", "/").split("/")
        for base in ((), config_dir):
            stack = list(base)
            for part in parts:
                if part in ("", "."):
                    continue
                if part == "..":
                    if not stack:
                        break
                    stack.pop()
                else:
                    stack.append(part)
            else:
                key = "/".join(unicodedata.normalize("NFC", c).casefold() for c in stack)
                if key in known_paths:
                    return True
        return False

    def update_tag(match):
        nonlocal changed, skipped
        tag = match.group()
        attrs = list(_XML_ATTR.finditer(tag))
        id_value = next((a.group("value").lower() for a in attrs if a.group("name").split(":")[-1].lower() == "id"), "")
        result = []
        pos = 0
        for attr in attrs:
            name = attr.group("name").split(":")[-1].lower()
            value = attr.group("value")
            is_path = (name in (_PATH_ATTRIBUTES - {"from"}) or
                       (name == "value" and id_value in _PATH_ATTRIBUTES) or
                       (name in {"from", "to"} and resolves_to_local(value)))
            if is_path and value:
                if "&" in value or "://" in value:
                    skipped += 1  # don't change entities or URLs without understanding them
                else:
                    new = unicodedata.normalize("NFC", value).replace("\\", "/").lower()
                    if new != value:
                        changed += 1
                        result.append(tag[pos:attr.start("value")])
                        result.append(new)
                        pos = attr.end("value")
        result.append(tag[pos:])
        return "".join(result)

    sections = _XML_PARTS.split(text)
    for i in range(0, len(sections), 2):
        sections[i] = _XML_TAG.sub(update_tag, sections[i])
    result = "".join(sections)
    try:
        ET.fromstring(result)
    except ET.ParseError as exc:
        raise ToolError(f"Rewritten config.xml is invalid: {exc}") from exc
    return result.encode(encoding), changed, skipped


def fix_mod_case(source: Path, destination: Path | None = None, *, dry_run: bool = False) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ToolError("--fix-mod-case requires a real directory (not a symlink)")
    source = source.resolve()
    if destination is None:
        destination = source.with_name(source.name + "_lowercase")
    resolved_dest = destination.resolve()
    if resolved_dest == source or source in resolved_dest.parents:
        raise ToolError("Normalized output must be outside the input directory")
    if destination.exists() or destination.is_symlink():
        raise ToolError("Normalized output already exists; no files were overwritten")
    plan = []
    total_entries = 0

    def walk_error(exc: OSError) -> None:
        raise ToolError(f"Cannot traverse mod directory: {exc}") from exc

    for root, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        total_entries += len(dirs) + len(files)
        if total_entries > MAX_ARCHIVE_ENTRIES:
            raise ToolError("Too many files/directories in mod tree")
        rel = Path(root).relative_to(source)
        local_keys = set()
        for name in sorted(dirs + files):
            child = Path(root) / name
            if child.is_symlink():
                raise ToolError(f"Symlinks are not copied: {child}")
            lower = unicodedata.normalize("NFC", name).lower()
            _safe_fmf_component(lower)
            key = unicodedata.normalize("NFC", lower).casefold()
            if key in local_keys:
                raise ToolError(f"Case/Unicode collision in {root}: {name!r}; input was not changed")
            local_keys.add(key)
        normalized = tuple(unicodedata.normalize("NFC", c).lower() for c in rel.parts)
        plan.append((Path(root), normalized, sorted(dirs), sorted(files)))
        if len(plan) > MAX_ARCHIVE_ENTRIES:
            raise ToolError("Too many directories in mod tree")
    # Build a case-insensitive inventory for distinguishing local references
    # from engine virtual IDs, including names where the extension is omitted.
    known_paths: set[str] = set()
    for root, _, dirs, files in plan:
        relative = root.relative_to(source)
        for name in dirs + files:
            parts = relative.parts + (name,)
            key = "/".join(unicodedata.normalize("NFC", c).casefold() for c in parts)
            known_paths.add(key)
            if name in files and "." in name and not name.startswith("."):
                known_paths.add(key.rsplit(".", 1)[0])
    # Parse every config before creating output, so an invalid XML does not leave a partial copy.
    configs = {}
    for root, _, _, files in plan:
        for name in files:
            child = root / name
            if not child.is_file():
                raise ToolError(f"Only regular files can be copied: {child}")
            if name.lower() == "config.xml":
                if child.stat().st_size > 4 * 1024 * 1024:
                    raise ToolError("config.xml exceeds the 4 MiB safety limit")
                configs[child] = _rewrite_config_paths(child.read_bytes(), known_paths, root.relative_to(source).parts)
    if dry_run:
        print(f"Dry run: would copy and normalize {source} -> {destination}")
        print(f"{sum(len(row[3]) for row in plan)} file(s); {len(configs)} config.xml file(s)")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        destination.mkdir()
        created = True
        for root, normalized, dirs, files in plan:
            output_root = destination.joinpath(*normalized)
            output_root.mkdir(parents=True, exist_ok=True)
            for directory in dirs:
                (output_root / unicodedata.normalize("NFC", directory).lower()).mkdir()
            for name in files:
                child = root / name
                target = output_root / unicodedata.normalize("NFC", name).lower()
                if child in configs:
                    payload, changes, skipped = configs[child]
                    target.write_bytes(payload)
                    print(f"  {target.relative_to(destination)}: {changes} path value(s) normalized; {skipped} entity/URL value(s) left unchanged")
                else:
                    shutil.copy2(child, target)
    except Exception:
        if created:
            shutil.rmtree(destination)
        raise
    print(f"Normalized COPY written to {destination}; source left unchanged. Unresolved virtual from/to identifiers were preserved.")

def number(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use a decimal integer or 0x-prefixed hex integer") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", metavar="PATH", help="fingerprint a file, APK/IPA, or directory")
    mode.add_argument("--scan-aob", metavar="FILE", help="scan file bytes for --pattern")
    mode.add_argument("--make-aob", metavar="FILE", help="build an instruction-aware AOB from --offset")
    mode.add_argument("--generate-patch", metavar="PS4_ELF_OR_DUMP", help="generate offline PS4 patch + independent Android template")
    mode.add_argument("--unpack-binary", metavar="SELF_OR_NSO", help="reconstruct a plaintext PS4 SELF/FSELF or Switch NSO0 as an analysis ELF")
    mode.add_argument("--fmf-info", metavar="FMF", help="inspect known FMF directory layouts and possible compressed streams")
    mode.add_argument("--fmf-unpack", metavar="FMF", help="extract a supported FMF index, or recover unnamed compressed streams")
    mode.add_argument("--fix-mod-case", metavar="DIRECTORY", help="write a normalized copy of a mod directory; never modify the input")
    parser.add_argument("--json", action="store_true", help="machine-readable output for --analyze or --fmf-info")
    parser.add_argument("--output", metavar="PATH", help="new ELF, FMF extraction directory, or normalized mod directory")
    parser.add_argument("--carve", action="store_true", help="recover unnamed FMF streams instead of using the index (approximate)")
    parser.add_argument("--dry-run", action="store_true", help="preview --fix-mod-case without writing")
    parser.add_argument("--max-output-mb", type=int, default=1024, help="reconstructed/extracted byte limit in MiB (default 1024, max 16384)")
    parser.add_argument("--arch", choices=("auto", "x86_64", "arm64"), default="auto")
    parser.add_argument("--pattern", help="space-separated bytes and ?/?? wildcards for --scan-aob")
    parser.add_argument("--context", type=int, default=16, help="surrounding bytes to disassemble (0 disables, max 128)")
    parser.add_argument("--max-matches", type=int, default=0, help="limit displayed matches; 0 means all")
    parser.add_argument("--offset", type=number, help="FILE offset, decimal or 0x-prefixed hex")
    parser.add_argument("--length", type=number, default=24, help="minimum signature length in bytes")
    parser.add_argument("--aob", help="uniquely matching AOB instead of --offset for patch generation")
    parser.add_argument("--match-delta", type=number, default=0, help="signed byte offset relative to the AOB match")
    parser.add_argument("--off", help="original bytes as hex, verified against the target")
    parser.add_argument("--on", help="replacement bytes as hex, same length as --off")
    parser.add_argument("--title-id", help="PS4 title ID, e.g. CUSA12345")
    parser.add_argument("--version", help="exact game version, e.g. 01.00")
    parser.add_argument("--goldhen-offset", type=number, help="manual GoldHEN offset; if omitted for ELF64, derive an unverified PT_LOAD candidate")
    parser.add_argument("--process", default="eboot.bin", help="GoldHEN process/module filename")
    parser.add_argument("--game-name", default="Offline game (verify exact build)")
    parser.add_argument("--mod-name", default="Offline patch (verify before use)")
    parser.add_argument("--author", default="Local user")
    parser.add_argument("--out-dir", default="generated_patch", help="directory for new outputs")
    parser.add_argument("--file-only", action="store_true", help="generate only the copy-on-write patcher for any offline file; no GoldHEN cheat")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.analyze:
            report = analyze_path(args.analyze)
            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                print_analysis(report)
        elif args.scan_aob:
            if not args.pattern:
                raise ToolError("--scan-aob requires --pattern")
            scan_file(args.scan_aob, args.pattern, args.arch, args.context, args.max_matches)
        elif args.make_aob:
            if args.offset is None:
                raise ToolError("--make-aob requires --offset")
            make_file_aob(args.make_aob, args.offset, args.length, args.arch)
        elif args.unpack_binary or args.fmf_unpack:
            if not args.output:
                raise ToolError("--unpack-binary and --fmf-unpack require --output")
            if not 1 <= args.max_output_mb <= 16384:
                raise ToolError("--max-output-mb must be between 1 and 16384")
            max_output = args.max_output_mb * 1024 * 1024
            if args.unpack_binary:
                unpack_binary(Path(args.unpack_binary), Path(args.output), max_output)
            else:
                fmf_unpack(Path(args.fmf_unpack), Path(args.output), max_output, carve=args.carve)
        elif args.fmf_info:
            fmf_info(Path(args.fmf_info), as_json=args.json)
        elif args.fix_mod_case:
            fix_mod_case(Path(args.fix_mod_case), Path(args.output) if args.output else None, dry_run=args.dry_run)
        else:
            required = ("off", "on") if args.file_only else ("off", "on", "title_id", "version")
            for attr in required:
                if getattr(args, attr) is None:
                    raise ToolError(f"--generate-patch requires --{attr.replace('_', '-')}")
            generate_patch(args)
        return 0
    except (ToolError, OSError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
