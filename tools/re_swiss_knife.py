#!/usr/bin/env python3
"""Offline game RE helper.  Python 3.10+; Capstone is optional except for --make-aob.

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
import struct
import sys
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


ANDROID_TEMPLATE = r'''// Offline patch primitive for code owned/controlled by the calling application.
// No injector, automatic hook, or platform/architecture translation is provided.
// Compile with the Android NDK, for example:
//   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++
//     -std=c++17 -fPIC -shared android_arm64_hook.cpp -o liboffline_patch.so
// (join those two lines into one shell command)
// The application must call apply_offline_patch itself, with verified ARM64 bytes
// and a separately resolved address. Never substitute x86-64 GoldHEN bytes.
// Stop all threads that might execute/read the page and ensure the entire range
// is readable, mapped, has uniform original_prot, and remains mapped throughout.
// Some Android kernels/policies forbid changing executable-page permissions.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

// Return: 0 success; -1 invalid arguments; -2 expected bytes differ;
// -3 mprotect for writing failed; -4 bytes changed but restoring protection failed.
extern "C" int apply_offline_patch(void* address, const unsigned char* expected,
                                   const unsigned char* replacement, std::size_t size,
                                   int original_prot) {
    if (!address || !expected || !replacement || size == 0 ||
        !(original_prot & PROT_READ)) return -1;
    const long page_size_raw = sysconf(_SC_PAGESIZE);
    if (page_size_raw <= 0) return -1;
    const auto page_size = static_cast<std::uintptr_t>(page_size_raw);
    const auto addr = reinterpret_cast<std::uintptr_t>(address);
    const auto max = std::numeric_limits<std::uintptr_t>::max();
    if (size > max - addr || addr + size > max - (page_size - 1)) return -1;
    const auto start = addr - addr % page_size;
    const auto end_unaligned = addr + size;
    const auto end = (end_unaligned + page_size - 1) / page_size * page_size;
    const auto span = static_cast<std::size_t>(end - start);
    // The caller guarantees the memory is readable before this comparison.
    if (std::memcmp(address, expected, size) != 0) return -2;
    // W^X: temporarily remove execute while writing. Threads must be stopped.
    const int writable = (original_prot | PROT_READ | PROT_WRITE) & ~PROT_EXEC;
    if (mprotect(reinterpret_cast<void*>(start), span, writable) != 0) return -3;
    std::memcpy(address, replacement, size);
#if defined(__GNUC__) || defined(__clang__)
    auto* first = static_cast<char*>(address);
    __builtin___clear_cache(first, first + size);
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, original_prot) != 0) return -4;
    return 0;
}
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
    cheat = None if args.file_only else make_goldhen(
        args.title_id, args.version, args.game_name, args.mod_name,
        args.process, args.goldhen_offset, original, replacement, args.author)
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
            before, after = _hash_original_and_patched(path, offset, original, replacement)
    except OSError as exc:
        raise ToolError(f"Cannot read target: {exc}") from exc
    output = Path(args.out_dir)
    try:
        output.mkdir(parents=True, exist_ok=True)
        files = {output / "offline_file_patcher.py": make_patcher_source(offset, original, replacement, before, after)}
        if cheat is not None:
            files[output / f"{args.title_id}_{args.version}.json"] = json.dumps(cheat, indent=2, ensure_ascii=False) + "\n"
            files[output / "android_patch_template.cpp"] = ANDROID_TEMPLATE
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
        print(f"GoldHEN offset 0x{args.goldhen_offset:X} was supplied by you and has NOT been verified.")
        print("Android template contains NO PS4 bytes: supply separately verified ARM64 address and code.")
    else:
        print("File-only mode: no GoldHEN cheat or Android template was generated.")
    for file in files:
        print(f"Wrote {file}")
    return list(files)


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
    parser.add_argument("--json", action="store_true", help="machine-readable output for --analyze")
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
    parser.add_argument("--goldhen-offset", type=number, help="independently verified GoldHEN memory offset (never inferred from file offset)")
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
        else:
            required = ("off", "on") if args.file_only else ("off", "on", "title_id", "version", "goldhen_offset")
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
