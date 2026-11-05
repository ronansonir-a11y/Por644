#!/usr/bin/env python3
"""Read-only Granny/Unity APK and split-bundle reconnaissance; Python stdlib only.

This is a bounded inventory, not a Unity deserializer, installer, verifier, or
extractor. It never modifies input files. Nested APKs are spooled to a private,
automatically deleted temporary file if they exceed the in-memory threshold.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

TOOL_VERSION = "2.1"
PACKAGE = "com.dvloper.granny"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
MIB = 1024 * 1024
CHUNK = 64 * 1024
MANIFEST_LIMIT = 4 * MIB
MAX_APK_SIZE = 2 * 1024 * MIB
MAX_NESTED_TOTAL = 4 * 1024 * MIB
MAX_APKS = 128
MAX_ENTRIES = 50000
MAX_NAME = 2048
MAX_CANDIDATES = 1024
MAX_EVIDENCE_PER_MARKER = 16
SPOOL_MEMORY = 8 * MIB
MAX_RATIO = 1000  # only applied to nested APKs larger than 1 MiB
UNKNOWN = 0xFFFFFFFF
VERSION_RE = re.compile(rb"(?<![0-9])(?:[1-9][0-9]{0,3})\.[0-9]+\.[0-9]+[abfp][0-9]+(?![0-9])")

# Strings can be in metadata, serialized objects, DLLs, or incidental text.
# A hit is not proof that a component/FSM is instantiated or functional.
MARKERS = {
    "playmaker": ("HutongGames.PlayMaker", "HutongGames", "PlayMakerFSM", "FsmStateAction", "FsmState", "FsmEvent"),
    "astar": ("AstarPathfindingProject", "AstarPath", "Pathfinding.AIPath"),
    "input_and_gameplay": ("CNJoystick", "CNTouchpad", "Joystick", "moveTouchPad", "rotateTouchPad", "FPSControllerNEW", "EnemyAIGranny", "InventoryController", "PickUp", "OpenCloseDoors"),
}
PATTERNS = tuple((group, text, encoding, text.encode(encoding))
                 for group, texts in MARKERS.items() for text in texts
                 for encoding in ("ascii", "utf-16le"))
MAX_PATTERN = max(len(item[3]) for item in PATTERNS)
# Android ABIs below are little-endian and require a matching ELF class as well as e_machine.
ABI_LAYOUTS = {"armeabi-v7a": (40, 32, 1), "arm64-v8a": (183, 64, 1),
               "x86": (3, 32, 1), "x86_64": (62, 64, 1), "armeabi": (40, 32, 1)}
MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64"}


class ReconError(ValueError):
    """A fatal invalid input or safety-limit error."""


def _u16(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 2 > len(data):
        raise ReconError("truncated binary XML")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(data):
        raise ReconError("truncated binary XML")
    return struct.unpack_from("<I", data, pos)[0]


class StringPool:
    """Lazy and bounded Android resource-string-pool reader."""

    def __init__(self, data: bytes, start: int, header: int, size: int):
        if header < 28 or size < header:
            raise ReconError("invalid binary XML string-pool header")
        self.data = data
        self.start = start
        self.end = start + size
        self.count = _u32(data, start + 8)
        styles = _u32(data, start + 12)
        self.utf8 = bool(_u32(data, start + 16) & 0x100)
        strings_start = _u32(data, start + 20)
        styles_start = _u32(data, start + 24)
        if self.count > 100000 or styles > 100000:
            raise ReconError("binary XML string-pool count exceeds limit")
        offsets_end = header + (self.count + styles) * 4
        if offsets_end > size or strings_start < offsets_end or strings_start > size:
            raise ReconError("invalid binary XML string-pool offsets")
        if styles_start and not strings_start <= styles_start <= size:
            raise ReconError("invalid binary XML style offset")
        self.offsets = start + header
        self.strings = start + strings_start
        self.limit = start + (styles_start or size)
        self.cache: dict[int, str] = {}
        self.decoded_bytes = 0

    def _length8(self, pos: int) -> tuple[int, int]:
        if pos >= self.limit:
            raise ReconError("truncated binary XML UTF-8 length")
        first = self.data[pos]
        pos += 1
        if first & 0x80:
            if pos >= self.limit:
                raise ReconError("truncated binary XML UTF-8 length")
            return ((first & 0x7F) << 8) | self.data[pos], pos + 1
        return first, pos

    def _length16(self, pos: int) -> tuple[int, int]:
        if pos + 2 > self.limit:
            raise ReconError("truncated binary XML UTF-16 length")
        first = _u16(self.data, pos)
        pos += 2
        if first & 0x8000:
            if pos + 2 > self.limit:
                raise ReconError("truncated binary XML UTF-16 length")
            return ((first & 0x7FFF) << 16) | _u16(self.data, pos), pos + 2
        return first, pos

    def get(self, index: int) -> str | None:
        if index == UNKNOWN:
            return None
        if index >= self.count:
            raise ReconError("binary XML string index out of range")
        if index in self.cache:
            return self.cache[index]
        pos = self.strings + _u32(self.data, self.offsets + index * 4)
        if pos < self.strings or pos >= self.limit:
            raise ReconError("binary XML string offset out of range")
        if self.utf8:
            _, pos = self._length8(pos)  # UTF-16 code-unit count
            length, pos = self._length8(pos)
            terminator, encoding = 1, "utf-8"
        else:
            length, pos = self._length16(pos)
            length *= 2
            terminator, encoding = 2, "utf-16le"
        if length > 65536 or pos + length + terminator > self.limit:
            raise ReconError("binary XML string length exceeds bounds")
        if self.data[pos + length:pos + length + terminator] != b"\0" * terminator:
            raise ReconError("unterminated binary XML string")
        self.decoded_bytes += length
        if self.decoded_bytes > 8 * MIB:
            raise ReconError("binary XML decoded-string budget exceeded")
        try:
            value = self.data[pos:pos + length].decode(encoding)
        except UnicodeDecodeError as exc:
            raise ReconError("invalid binary XML string encoding") from exc
        self.cache[index] = value
        return value


def _manifest_fields() -> dict:
    return {"format": None, "package": None, "version_name": None,
            "version_code": None, "version_code_major": None, "split": None,
            "config_for_split": None, "is_split_required": None,
            "required_split_types": None, "min_sdk": None, "target_sdk": None,
            "uses_splits": [], "unresolved": {}}


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 0xFFFFFFFF else None
    if isinstance(value, str):
        try:
            result = int(value, 16 if value.lower().startswith("0x") else 10)
            return result if 0 <= result <= 0xFFFFFFFF else None
        except ValueError:
            pass
    return None


def _assign_element(result: dict, element: str, attrs: dict[tuple[str | None, str], object]) -> None:
    def get(name: str, android: bool = True) -> object:
        return attrs.get((ANDROID_NS if android else None, name))

    def assign(field: str, value: object, kind: str = "string") -> None:
        if value is None:
            return
        if kind == "int":
            parsed = _integer(value)
        elif kind == "bool":
            if isinstance(value, bool):
                parsed = value
            elif isinstance(value, str) and value.lower() in ("true", "false"):
                parsed = value.lower() == "true"
            else:
                parsed = None
        else:
            parsed = value if isinstance(value, str) and not value.startswith("@") else None
        if parsed is None:
            result["unresolved"][field] = str(value)
        else:
            result[field] = parsed

    if element == "manifest":
        assign("package", get("package", False))
        assign("split", get("split", False))
        assign("version_name", get("versionName"))
        assign("version_code", get("versionCode"), "int")
        assign("version_code_major", get("versionCodeMajor"), "int")
        assign("config_for_split", get("configForSplit"))
        assign("is_split_required", get("isSplitRequired"), "bool")
        assign("required_split_types", get("requiredSplitTypes"))
    elif element == "uses-sdk":
        assign("min_sdk", get("minSdkVersion"), "int")
        assign("target_sdk", get("targetSdkVersion"), "int")
    elif element == "uses-split":
        name = get("name")
        if isinstance(name, str) and name not in result["uses_splits"]:
            result["uses_splits"].append(name)


def parse_manifest(data: bytes) -> dict:
    """Parse selected manifest fields, without resolving resources. Raises ReconError."""
    if len(data) > MANIFEST_LIMIT:
        raise ReconError("AndroidManifest.xml exceeds 4 MiB")
    result = _manifest_fields()
    text_probe = data[3:] if data.startswith(b"\xef\xbb\xbf") else data
    if text_probe.lstrip().startswith(b"<"):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ReconError("text manifest must be UTF-8") from exc
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
            raise ReconError("DTD/entity declarations are not supported")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ReconError("invalid text manifest XML") from exc
        if root.tag != "manifest":
            raise ReconError("manifest XML root is not manifest")
        result["format"] = "text-xml"
        for node in (root, *(item for item in root if item.tag in ("uses-sdk", "uses-split"))):
            attrs = {}
            for key, value in node.attrib.items():
                if key.startswith("{") and "}" in key:
                    ns, name = key[1:].split("}", 1)
                    attrs[(ns, name)] = value
                else:
                    attrs[(None, key)] = value
            _assign_element(result, node.tag, attrs)
        return result
    if len(data) < 8 or _u16(data, 0) != 3:
        raise ReconError("unsupported AndroidManifest.xml encoding")
    header, total = _u16(data, 2), _u32(data, 4)
    if header < 8 or total < header or total > len(data):
        raise ReconError("invalid binary XML root chunk")
    pool = None
    seen_manifest = False
    stack: list[tuple[str | None, str]] = []
    nodes = attributes = 0
    pos = header
    while pos < total:
        if pos + 8 > total:
            raise ReconError("truncated binary XML chunk")
        chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_header < 8 or chunk_size < chunk_header or pos + chunk_size > total:
            raise ReconError("invalid binary XML chunk bounds")
        if chunk_type == 1:
            if pool is not None:
                raise ReconError("multiple binary XML string pools")
            pool = StringPool(data, pos, chunk_header, chunk_size)
        elif chunk_type == 0x0102:  # RES_XML_START_ELEMENT_TYPE
            nodes += 1
            if nodes > 50000 or chunk_header < 16 or pool is None:
                raise ReconError("invalid or excessive binary XML elements")
            ext = pos + chunk_header
            if ext + 20 > pos + chunk_size:
                raise ReconError("truncated binary XML element")
            namespace = pool.get(_u32(data, ext))
            name = pool.get(_u32(data, ext + 4))
            if not name or (not stack and (seen_manifest or name != "manifest" or namespace not in (None, ""))):
                raise ReconError("invalid binary XML root element")
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, ext + 8)
            attributes += attr_count
            if (attr_start < 20 or attr_size < 20 or attributes > 100000 or
                    ext + attr_start + attr_count * attr_size > pos + chunk_size):
                raise ReconError("invalid or excessive binary XML attributes")
            relevant = (namespace in (None, "") and
                        ((not stack and name == "manifest") or (len(stack) == 1 and name in ("uses-sdk", "uses-split"))))
            if relevant:
                if name == "manifest":
                    seen_manifest = True
                attrs = {}
                for index in range(attr_count):
                    attr = ext + attr_start + index * attr_size
                    ns = pool.get(_u32(data, attr))
                    key = pool.get(_u32(data, attr + 4))
                    raw = _u32(data, attr + 8)
                    value_size, zero, kind, value_data = struct.unpack_from("<HBBI", data, attr + 12)
                    if value_size < 8 or zero != 0 or key is None:
                        raise ReconError("invalid binary XML typed value")
                    if raw != UNKNOWN:
                        value: object = pool.get(raw)
                    elif kind == 3:
                        value = pool.get(value_data)
                    elif kind in (0x10, 0x11):
                        value = value_data
                    elif kind == 0x12:
                        value = bool(value_data)
                    elif kind in (1, 2, 7, 8):
                        value = f"@0x{value_data:08x}"
                    else:
                        value = f"<type 0x{kind:02x}:0x{value_data:08x}>"
                    pair = (ns, key)
                    if pair in attrs:
                        raise ReconError("duplicate binary XML attribute")
                    attrs[pair] = value
                _assign_element(result, name, attrs)
            stack.append((namespace, name))
        elif chunk_type == 0x0103:  # RES_XML_END_ELEMENT_TYPE
            ext = pos + chunk_header
            if chunk_header < 16 or ext + 8 > pos + chunk_size or pool is None:
                raise ReconError("truncated binary XML end element")
            namespace = pool.get(_u32(data, ext))
            name = pool.get(_u32(data, ext + 4))
            if not stack or stack.pop() != (namespace, name):
                raise ReconError("unbalanced binary XML elements")
        pos += chunk_size
    if not seen_manifest or stack:
        raise ReconError("binary XML has no complete manifest element")
    result["format"] = "binary-axml"
    return result


def _safe_member(name: str) -> bool:
    return (bool(name) and len(name) <= MAX_NAME and "\\" not in name and "\x00" not in name
            and not name.startswith("/") and not any(part in ("..", ".") for part in name.split("/")))


def _checked_infos(archive: zipfile.ZipFile) -> tuple[list[zipfile.ZipInfo], list[str]]:
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ReconError(f"archive exceeds {MAX_ENTRIES} ZIP entries")
    names: set[str] = set()
    good, warnings = [], []
    for info in infos:
        if not _safe_member(info.filename):
            warnings.append(f"Unsafe ZIP member skipped: {info.filename!r}")
            continue
        if info.filename in names:
            raise ReconError(f"duplicate ZIP member: {info.filename!r}")
        names.add(info.filename)
        if not info.is_dir():
            good.append(info)
    return good, warnings


def _read_prefix(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.flag_bits & 1:
        raise ReconError("encrypted ZIP member is unsupported")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ReconError("unsupported ZIP compression method")
    with archive.open(info, "r") as source:
        return source.read(limit)


def _hash_stream(stream, maximum: int = MAX_APK_SIZE) -> tuple[str, int]:
    digest, total = hashlib.sha256(), 0
    while True:
        data = stream.read(CHUNK)
        if not data:
            break
        total += len(data)
        if total > maximum:
            raise ReconError("input exceeds size limit")
        digest.update(data)
    return digest.hexdigest(), total


def _native_header(data: bytes, abi: str) -> dict:
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        return {"elf_valid_header": False, "machine": None, "bits": None, "matches_abi": None}
    machine = struct.unpack_from("<H" if data[5] == 1 else ">H", data, 18)[0]
    bits = 32 if data[4] == 1 else 64
    expected = ABI_LAYOUTS.get(abi)
    return {"elf_valid_header": True, "machine": MACHINES.get(machine, f"EM_{machine}"),
            "machine_id": machine, "bits": bits, "byte_order": "little" if data[5] == 1 else "big",
            "matches_abi": (machine, bits, data[5]) == expected if expected is not None else None}


def _unity_header(data: bytes, actual_size: int) -> tuple[str, str] | None:
    # UnityFS: signature, BE format version, player version, engine revision.
    for sig in (b"UnityFS\0", b"UnityWeb\0", b"UnityRaw\0"):
        if data.startswith(sig) and len(data) >= len(sig) + 4:
            version = struct.unpack_from(">I", data, len(sig))[0]
            tail = data[len(sig) + 4:].split(b"\0", 2)
            if 1 <= version <= 20 and len(tail) >= 3 and VERSION_RE.fullmatch(tail[1]):
                return tail[1].decode("ascii"), "bundle-header"
    # Unity SerializedFile v9+ starts with four BE u32 and endian/reserved;
    # v22+ extends the header to 48 bytes. Older layouts need a real parser.
    if len(data) >= 21:
        metadata_size, file_size, version, data_offset = struct.unpack_from(">IIII", data, 0)
        at = 20
        if 22 <= version <= 100 and len(data) >= 49:
            metadata_size = struct.unpack_from(">I", data, 20)[0]
            file_size, data_offset = struct.unpack_from(">QQ", data, 24)
            at = 48
        if (9 <= version <= 100 and file_size == actual_size and
                0 < metadata_size <= file_size and at <= data_offset <= file_size):
            end = data.find(b"\0", at, min(len(data), at + 128))
            if end >= 0 and VERSION_RE.fullmatch(data[at:end]):
                return data[at:end].decode("ascii"), "serialized-file-header"
    return None


def _candidate_priority(name: str) -> int | None:
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    if base == "global-metadata.dat":
        return 0
    if base == "globalgamemanagers":
        return 1
    if re.fullmatch(r"level\d+", base) and "/data/" in low:
        return 2
    if (low.endswith((".assets", ".bundle", ".unity3d")) or
            ("/managed/" in low and low.endswith(".dll"))):
        return 3
    if base == "libil2cpp.so" and low.startswith("lib/"):
        return 4
    return None


def _backend(signals: dict) -> str:
    il2cpp = bool(signals["il2cpp_libraries"] and signals["metadata_files"])
    mono = bool(signals["managed_game_assemblies"])
    if il2cpp and mono:
        return "mixed-or-ambiguous"
    if il2cpp:
        return "il2cpp-indicated"
    if mono and not signals["il2cpp_libraries"] and not signals["metadata_files"]:
        return "mono-indicated"
    if mono or signals["il2cpp_libraries"] or signals["metadata_files"]:
        return "partial-or-ambiguous"
    return "unknown"


def _record_markers(report: dict, name: str, chunk: bytes, offset: int, seen: set) -> None:
    for group, marker, encoding, pattern in PATTERNS:
        key = (group, marker, encoding)
        if key in seen:
            continue
        at = chunk.find(pattern)
        if at < 0:
            continue
        seen.add(key)
        entries = report["markers"][group]
        if len(entries) < MAX_EVIDENCE_PER_MARKER:
            entries.append({"marker": marker, "source": name, "offset": offset + at,
                            "encoding": encoding, "kind": "raw-byte-string"})


def scan_apk(stream, label: str, digest: str, size: int, budget: dict, per_file: int) -> dict:
    report = {"source": label, "size": size, "sha256": digest, "manifest": _manifest_fields(),
              "native_libraries": [], "unity_versions": [], "asset_files": [],
              "signals": {"il2cpp_libraries": [], "metadata_files": [], "managed_game_assemblies": [],
                          "playmaker_assemblies": [], "unity_libraries": []},
              "metadata_headers": [], "markers": {group: [] for group in MARKERS},
              "scanned_members": [], "warnings": [], "inspection_incomplete": False}
    try:
        archive = zipfile.ZipFile(stream)
    except zipfile.BadZipFile as exc:
        raise ReconError(f"not a valid APK ZIP: {label!r}") from exc
    with archive:
        infos, warnings = _checked_infos(archive)
        report["warnings"].extend(warnings)
        if warnings:
            report["inspection_incomplete"] = True
        info_map = {item.filename: item for item in infos}
        manifest = info_map.get("AndroidManifest.xml")
        if manifest is None:
            report["warnings"].append("AndroidManifest.xml is missing; identity is unknown")
            report["inspection_incomplete"] = True
        else:
            try:
                if manifest.file_size > MANIFEST_LIMIT:
                    raise ReconError("AndroidManifest.xml exceeds 4 MiB")
                data = _read_prefix(archive, manifest, MANIFEST_LIMIT + 1)
                report["manifest"] = parse_manifest(data)
            except (ReconError, OSError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError) as exc:
                report["warnings"].append(f"Manifest unreadable: {exc}")
                report["inspection_incomplete"] = True

        candidates = []
        for info in infos:
            name, low = info.filename, info.filename.lower()
            base = low.rsplit("/", 1)[-1]
            if low.startswith("lib/") and low.endswith(".so") and len(name.split("/")) == 3:
                abi = name.split("/")[1]
                native = {"path": name, "abi": abi}
                try:
                    native.update(_native_header(_read_prefix(archive, info, 64), abi))
                    if not native["elf_valid_header"] or native["matches_abi"] is False:
                        report["warnings"].append(f"Invalid or ABI-mismatched ELF header: {name!r}")
                except (ReconError, OSError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError) as exc:
                    native.update({"elf_valid_header": False, "machine": None, "bits": None, "matches_abi": None})
                    report["warnings"].append(f"Native header unreadable for {name!r}: {exc}")
                    report["inspection_incomplete"] = True
                report["native_libraries"].append(native)
                if base == "libil2cpp.so":
                    report["signals"]["il2cpp_libraries"].append(name)
                if base == "libunity.so":
                    report["signals"]["unity_libraries"].append(name)
            if base == "global-metadata.dat":
                report["signals"]["metadata_files"].append(name)
                try:
                    header = _read_prefix(archive, info, 8)
                    valid = len(header) == 8 and struct.unpack_from("<I", header)[0] == 0xFAB11BAF
                    version = struct.unpack_from("<I", header, 4)[0] if valid else None
                    report["metadata_headers"].append({"path": name, "magic_valid": valid, "version": version})
                    if not valid:
                        report["warnings"].append(f"IL2CPP metadata header missing/invalid/obfuscated: {name!r}")
                except (ReconError, OSError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError) as exc:
                    report["warnings"].append(f"Metadata header unreadable for {name!r}: {exc}")
                    report["inspection_incomplete"] = True
            if "/managed/" in low and base == "assembly-csharp.dll":
                report["signals"]["managed_game_assemblies"].append(name)
            if "/managed/" in low and base in ("playmaker.dll", "hutonggames.playmaker.dll"):
                report["signals"]["playmaker_assemblies"].append(name)
            priority = _candidate_priority(name)
            if priority is not None:
                candidates.append((priority, name, info))
                if len(report["asset_files"]) < MAX_CANDIDATES and not low.startswith("lib/"):
                    report["asset_files"].append({"path": name, "size": info.file_size})
        report["asset_files"].sort(key=lambda item: item["path"])
        candidates.sort(key=lambda item: (item[0], item[1]))
        if len(candidates) > MAX_CANDIDATES:
            report["warnings"].append(f"Only the first {MAX_CANDIDATES} candidate members are inspected")
            report["inspection_incomplete"] = True
        for _, name, info in candidates[:MAX_CANDIDATES]:
            amount = min(info.file_size, per_file, budget["remaining"])
            if amount <= 0:
                report["inspection_incomplete"] = True
                continue
            scanned, head, tail, seen = 0, bytearray(), b"", set()
            try:
                if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ReconError("encrypted or unsupported compression")
                with archive.open(info, "r") as source:
                    while scanned < amount:
                        block = source.read(min(CHUNK, amount - scanned))
                        if not block:
                            break
                        if len(head) < 4096:
                            head.extend(block[:4096 - len(head)])
                        combined = tail + block
                        _record_markers(report, name, combined, scanned - len(tail), seen)
                        tail = combined[-(MAX_PATTERN - 1):]
                        scanned += len(block)
                        budget["remaining"] -= len(block)
                completed = scanned == info.file_size
                if not completed:
                    report["inspection_incomplete"] = True
                report["scanned_members"].append({"path": name, "bytes_scanned": scanned,
                                                  "size": info.file_size, "complete": completed})
                header_version = _unity_header(bytes(head), info.file_size)
                if header_version:
                    value, method = header_version
                    report["unity_versions"].append({"version": value, "source": name,
                                                     "method": method, "confidence": "header"})
                elif name.lower().rsplit("/", 1)[-1] in ("globalgamemanagers", "data.unity3d"):
                    for match in list(VERSION_RE.finditer(bytes(head)))[:3]:
                        report["unity_versions"].append({"version": match.group().decode("ascii"),
                                                         "source": name, "method": "raw-string",
                                                         "confidence": "heuristic", "offset": match.start()})
            except (ReconError, OSError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError) as exc:
                report["warnings"].append(f"Candidate unreadable {name!r}: {exc}")
                report["inspection_incomplete"] = True
        if budget["remaining"] == 0:
            report["warnings"].append("Global marker scan budget exhausted; negative results are inconclusive")
    report["backend"] = _backend(report["signals"])
    return report


def _combine(apks: list[dict]) -> dict:
    manifests = [item["manifest"] for item in apks]
    packages = {m["package"] for m in manifests if m["package"]}
    unknown_package = any(not m["package"] for m in manifests)
    versions = {(m["version_code_major"] or 0, m["version_code"]) for m in manifests
                if m["version_code"] is not None and "version_code_major" not in m["unresolved"]}
    names = {m["version_name"] for m in manifests if m["version_name"]}
    unknown_version = any(m["version_code"] is None or "version_code_major" in m["unresolved"] for m in manifests)
    bases = [m for m in manifests if m["format"] and not m["split"] and "split" not in m["unresolved"]]
    splits = [m["split"] for m in manifests if m["split"]]
    if len(apks) == 1:
        grouping = "single-apk"
    elif len(packages) > 1 or len(versions) > 1 or len(names) > 1:
        grouping = "conflicting-identities"
    elif (unknown_package or unknown_version or len(bases) != 1 or
          len(splits) != len(apks) - 1 or len(set(splits)) != len(splits)):
        grouping = "ambiguous-do-not-combine"
    else:
        grouping = "manifest-consistent-not-signature-verified"
    if len(packages) > 1:
        identity = "conflict"
    elif unknown_package or not packages:
        identity = "unknown"
    else:
        identity = "matches-granny" if packages == {PACKAGE} else "different-package"
    safe_combine = grouping in ("single-apk", "manifest-consistent-not-signature-verified")
    signals = {name: [] for name in apks[0]["signals"]}
    if safe_combine:
        for apk in apks:
            for kind, values in apk["signals"].items():
                signals[kind].extend({"apk": apk["source"], "path": value} for value in values)
    versions_found = []
    for apk in apks:
        for version in apk["unity_versions"]:
            versions_found.append({"apk": apk["source"], **version})
    groups = {}
    for group in MARKERS:
        evidence = [{"apk": apk["source"], **item} for apk in apks for item in apk["markers"][group]]
        assemblies = signals["playmaker_assemblies"] if group == "playmaker" and safe_combine else []
        status = ("unresolved-see-individual-apks" if not safe_combine else
                  "file-indicator" if assemblies else "raw-string-indicator" if evidence else "unknown")
        groups[group] = {"status": status, "evidence": evidence[:MAX_EVIDENCE_PER_MARKER],
                         "assembly_evidence": assemblies}
    warnings = ["APK signatures, installation completeness, OBBs, Unity objects and runtime behaviour are not verified."]
    if grouping not in ("single-apk", "manifest-consistent-not-signature-verified"):
        warnings.append("Multiple bases, missing/conflicting manifest identity, or duplicate splits: signals are not combined.")
    if len(apks) == 1 and manifests[0]["split"]:
        warnings.append("Only a split APK is present; the base APK is missing.")
    if any(m["is_split_required"] or m["required_split_types"] or m["uses_splits"] for m in manifests):
        warnings.append("Manifest declares split requirements; this scanner cannot prove all required splits are present.")
    if len({v["version"] for v in versions_found if v["confidence"] == "header"}) > 1:
        warnings.append("Multiple Unity header versions found; assets/builds may differ. Inspect each source.")
    return {"grouping": grouping, "identity": identity,
            "package": next(iter(packages)) if len(packages) == 1 and not unknown_package else None,
            "version_code": next(iter(versions))[1] if len(versions) == 1 and not unknown_version else None,
            "version_code_major": next(iter(versions))[0] if len(versions) == 1 and not unknown_version else None,
            "version_names": sorted({m["version_name"] for m in manifests if m["version_name"]}),
            "backend": _backend(signals) if safe_combine else "unresolved-see-individual-apks",
            "backend_evidence": signals, "unity_versions": versions_found,
            "abis": sorted({lib["abi"] for apk in apks for lib in apk["native_libraries"]}) if safe_combine else [],
            "indicators": groups, "warnings": warnings}


def _spool_nested(archive: zipfile.ZipFile, info: zipfile.ZipInfo, total: dict):
    if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ReconError(f"unsupported/encrypted nested APK: {info.filename!r}")
    if info.file_size > MAX_APK_SIZE or total["bytes"] + info.file_size > MAX_NESTED_TOTAL:
        raise ReconError("nested APK size or aggregate limit exceeded")
    if info.file_size > MIB and info.file_size > max(info.compress_size, 1) * MAX_RATIO:
        raise ReconError("nested APK compression ratio exceeds safety limit")
    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY, mode="w+b")
    digest, size = hashlib.sha256(), 0
    try:
        with archive.open(info, "r") as source:
            while True:
                block = source.read(CHUNK)
                if not block:
                    break
                size += len(block)
                if size > MAX_APK_SIZE or total["bytes"] + size > MAX_NESTED_TOTAL:
                    raise ReconError("nested APK exceeds declared or aggregate size limit")
                digest.update(block)
                spool.write(block)
        if size != info.file_size:
            raise ReconError("nested APK length differs from ZIP metadata")
        total["bytes"] += size
        spool.seek(0)
        return spool, digest.hexdigest(), size
    except Exception:
        spool.close()
        raise


def inspect_input(path: Path, scan_limit_mib: int = 128, per_file_mib: int = 32) -> dict:
    if not 1 <= scan_limit_mib <= 1024 or not 1 <= per_file_mib <= 256:
        raise ReconError("scan limit must be 1..1024 MiB and per-file limit 1..256 MiB")
    path = Path(path)
    if path.is_symlink():
        raise ReconError("input symlinks are not followed")
    if not path.exists():
        raise ReconError("input does not exist")
    budget = {"remaining": scan_limit_mib * MIB}
    apks, warnings = [], []
    input_info = {"path": str(path), "kind": None, "sha256": None}
    if path.is_dir():
        input_info["kind"] = "split-directory"
        entries = sorted((p for p in path.iterdir() if p.suffix.lower() == ".apk"), key=lambda p: p.name)
        if not entries or len(entries) > MAX_APKS:
            raise ReconError(f"directory must contain 1..{MAX_APKS} top-level APKs")
        if any(p.is_symlink() or not p.is_file() for p in entries):
            raise ReconError("APK entries in the directory must be regular non-symlink files")
        aggregate_size = 0
        for entry in entries:
            with entry.open("rb") as source:
                digest, size = _hash_stream(source, MAX_APK_SIZE)
                aggregate_size += size
                if aggregate_size > MAX_NESTED_TOTAL:
                    raise ReconError("aggregate APK size exceeds limit")
                source.seek(0)
                apks.append(scan_apk(source, entry.name, digest, size, budget, per_file_mib * MIB))
    elif path.is_file() and path.suffix.lower() in (".apk", ".apks", ".xapk", ".zip"):
        with path.open("rb") as source:
            # The outer ZIP may contain several APKs, so its cap is the aggregate limit.
            digest, size = _hash_stream(source, MAX_NESTED_TOTAL)
            input_info["sha256"], input_info["size"] = digest, size
            source.seek(0)
            try:
                outer = zipfile.ZipFile(source)
            except zipfile.BadZipFile as exc:
                raise ReconError("input is not a valid ZIP/APK") from exc
            with outer:
                infos, outer_warnings = _checked_infos(outer)
                warnings.extend(outer_warnings)
                by_name = {info.filename: info for info in infos}
                nested = sorted((info for info in infos if info.filename.lower().endswith(".apk")), key=lambda x: x.filename)
                if path.suffix.lower() == ".apk" or "AndroidManifest.xml" in by_name:
                    if nested:
                        warnings.append("APK also contains nested APKs; nested entries are not treated as splits.")
                    input_info["kind"] = "apk"
                else:
                    input_info["kind"] = "split-bundle"
                    if not nested or len(nested) > MAX_APKS:
                        raise ReconError(f"bundle must contain 1..{MAX_APKS} APKs")
                    if any(info.filename.lower().endswith(".obb") for info in infos):
                        warnings.append("Bundle contains OBB data; OBB content is not inspected.")
                    if "toc.pb" in by_name:
                        warnings.append("bundletool toc.pb/variants are not parsed; multiple bases are ambiguous.")
                    totals = {"bytes": 0}
                    for info in nested:
                        spool, apk_hash, apk_size = _spool_nested(outer, info, totals)
                        with spool:
                            apks.append(scan_apk(spool, info.filename, apk_hash, apk_size, budget, per_file_mib * MIB))
            if input_info["kind"] == "apk":
                if size > MAX_APK_SIZE:
                    raise ReconError("APK exceeds size limit")
                source.seek(0)
                apks.append(scan_apk(source, path.name, digest, size, budget, per_file_mib * MIB))
    else:
        raise ReconError("expected an APK, APKS, XAPK, ZIP, or directory of APK splits")
    summary = _combine(apks)
    if warnings:
        summary["warnings"].extend(warnings)
    return {"schema_version": 1, "tool": f"granny-apk-recon/{TOOL_VERSION}",
            "input": input_info, "summary": summary, "apks": apks,
            "limits": {"marker_scan_mib": scan_limit_mib, "per_member_mib": per_file_mib,
                       "marker_bytes_read": scan_limit_mib * MIB - budget["remaining"]},
            "privacy": "No network access. Paths, manifest data and hashes in this report may be sensitive."}


def render_text(report: dict) -> str:
    summary = report["summary"]
    quote = lambda obj: json.dumps(obj, ensure_ascii=True)
    lines = [f"Granny APK recon {TOOL_VERSION} (read-only; no device or runtime test)",
             f"Input: {quote(report['input']['path'])} [{report['input']['kind']}]",
             f"Identity: {summary['identity']} | package: {summary['package'] or 'unknown'}",
             f"Grouping: {summary['grouping']} | backend: {summary['backend']}",
             f"Version code: {summary['version_code']} | version names: {quote(summary['version_names'])}",
             f"ABI directories: {quote(summary['abis'])}"]
    if summary["unity_versions"]:
        for version in summary["unity_versions"]:
            lines.append(f"Unity {version['version']} ({version['confidence']}, {version['method']}): {quote(version['apk'])}!{quote(version['source'])}")
    else:
        lines.append("Unity version: unknown")
    for group, indicator in summary["indicators"].items():
        lines.append(f"{group}: {indicator['status']}")
        for hit in indicator["evidence"]:
            lines.append(f"  {hit['marker']} {hit['encoding']} +0x{hit['offset']:x} in {quote(hit['apk'])}!{quote(hit['source'])}")
        for hit in indicator["assembly_evidence"]:
            lines.append(f"  assembly filename in {quote(hit['apk'])}!{quote(hit['path'])}")
    for apk in report["apks"]:
        m = apk["manifest"]
        lines.append(f"APK {quote(apk['source'])}: sha256={apk['sha256']} package={quote(m['package'])} split={quote(m['split'])} versionCode={m['version_code']} backend={apk['backend']}")
        for native in apk["native_libraries"]:
            lines.append(f"  ELF {quote(native['path'])}: {native['machine']} {native['bits']}bit ABI-match={native['matches_abi']}")
        for metadata in apk["metadata_headers"]:
            lines.append(f"  metadata {quote(metadata['path'])}: magic={metadata['magic_valid']} version={metadata['version']}")
        for warning in apk["warnings"]:
            lines.append(f"  WARNING: {quote(warning)}")
        if apk["inspection_incomplete"]:
            lines.append("  WARNING: inspection was incomplete or budget-limited")
    for warning in summary["warnings"]:
        lines.append(f"WARNING: {quote(warning)}")
    lines.append(f"Scanned {report['limits']['marker_bytes_read']} marker bytes; absence is unknown, not proof.")
    lines.append(report["privacy"])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="APK, APKS/XAPK/ZIP bundle, or directory containing APK splits")
    parser.add_argument("--json", action="store_true", help="write a structured report to stdout")
    parser.add_argument("--scan-limit-mib", type=int, default=128, help="aggregate raw-marker budget, 1..1024 MiB (default 128)")
    parser.add_argument("--per-file-mib", type=int, default=32, help="raw-marker budget per ZIP member, 1..256 MiB (default 32)")
    parser.add_argument("--require-granny", action="store_true", help="return exit 3 unless every manifest identifies com.dvloper.granny")
    args = parser.parse_args(argv)
    try:
        report = inspect_input(args.input, args.scan_limit_mib, args.per_file_mib)
    except (ReconError, OSError, zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError) as exc:
        print(f"Error: {str(exc)!r}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=True) if args.json else render_text(report))
    if args.require_granny and report["summary"]["identity"] != "matches-granny":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
