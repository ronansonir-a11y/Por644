from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import mmap
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from test_swiss_knife import ROOT, TOOL_PATH, SCHEMA, elf64, import_file, invoke

sk = import_file("re_swiss_knife_v2_under_test", TOOL_PATH)


def two_load_elf(second_offset=0x900, second_vaddr=0x900, second_size=0x80):
    data = bytearray(0xa00)
    data[:len(elf64())] = elf64(marker=bytes.fromhex("89 C0 48 8B 41 10 C3"))
    struct.pack_into("<H", data, 56, 2)
    struct.pack_into("<IIQQQQQQ", data, 0x78, 1, 4, second_offset, second_vaddr, 0,
                     second_size, second_size, 0x1000)
    return bytes(data)


def fake_self(*, compressed=False, encrypted=False, bad_index=False, payload=None):
    payload = payload if payload is not None else b"CODE" + bytes(range(92))
    stored = zlib.compress(payload) if compressed else payload
    header_size, segment_offset = 0x200, 0x300
    self_size = segment_offset + len(stored)
    data = bytearray(self_size)
    struct.pack_into("<IBBBBIHHQHHI", data, 0, 0x1d3d154f, 0, 1, 1, 0x12, 1,
                     header_size, 0, self_size, 2, 0x22, 0)
    struct.pack_into("<QQQQ", data, 32, 4, 0, 0, 0)  # digest metadata, not payload
    props = 0x804 | (0x8 if compressed else 0) | (0x2 if encrypted else 0)
    if bad_index:
        props |= 12 << 20
    struct.pack_into("<QQQQ", data, 64, props, segment_offset, len(stored), len(payload))
    elf_at = 96
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", data, elf_at, ident, 0xFE00, 62, 1,
                     0x400200, 0x40, 0xdead, 0, 64, 56, 2, 64, 3, 1)
    struct.pack_into("<IIQQQQQQ", data, elf_at + 64, 1, 5, 0x200, 0x400200, 0,
                     len(payload), len(payload), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, elf_at + 120, 2, 4, 0x210, 0x400210, 0,
                     8, 8, 1)  # alias wholly contained in first LOAD
    data[segment_offset:] = stored
    return bytes(data), payload


def lz4_literal(payload: bytes) -> bytes:
    size = len(payload)
    if size < 15:
        return bytes([size << 4]) + payload
    extra = size - 15
    return b"\xf0" + b"\xff" * (extra // 255) + bytes([extra % 255]) + payload


def fake_nso(*, flags=0x39, bad_hash=False):
    text, ro, rw = bytes.fromhex("1F 20 03 D5") * 4, b"read-only", b"DATA!!"
    block = lz4_literal(text) if flags & 1 else text
    parts = [block, ro, rw]
    data = bytearray(0x100 + sum(map(len, parts)))
    data[:4] = b"NSO0"
    struct.pack_into("<III", data, 4, 0, 0, flags)
    cursor = 0x100
    for i, (raw, stored, va) in enumerate(zip((text, ro, rw), parts, (0, 0x1000, 0x2000))):
        struct.pack_into("<IIII", data, 0x10 + i * 0x10, cursor, va, len(raw), 0)
        struct.pack_into("<I", data, 0x60 + i * 4, len(stored))
        data[0xa0 + i * 32:0xc0 + i * 32] = hashlib.sha256(raw).digest()
        data[cursor:cursor + len(stored)] = stored
        cursor += len(stored)
    struct.pack_into("<I", data, 0x3c, 0x80)  # BSS
    if bad_hash:
        data[0xa0] ^= 1
    return bytes(data), (text, ro, rw)


def _name_modern(value):
    encoded = value.encode("utf-8")
    return struct.pack("<I", len(encoded)) + encoded


def _name_legacy(value, root=False):
    encoded = value.encode("utf-16-le")
    return struct.pack("<I", len(encoded) // 2) + encoded + (b"" if root and not value else b"\0\0")


def fake_fmf(entries, *, modern=True, directory_codec="zlib", length_prefix=False, root_name=""):
    """entries: list of (tuple(path components), stored bytes, expanded size or 0)."""
    base = 26 if modern else 18
    body = bytearray(base)
    body[:5] = sk.FMF_MAGIC
    tree = {"files": [], "dirs": {}}
    for parts, payload, expanded in entries:
        rel = len(body) - base
        body.extend(payload)
        node = tree
        for part in parts[:-1]:
            node = node["dirs"].setdefault(part, {"files": [], "dirs": {}})
        filename = parts[-1]
        stem, dot, ext = filename.rpartition(".")
        if not dot:
            stem, ext = filename, ""
        else:
            ext = dot + ext
        node["files"].append((stem, ext, rel, len(payload), expanded))
    directory = len(body)
    struct.pack_into("<I", body, 9, directory - 9)

    def render(node, name="", root=False):
        n = _name_modern if modern else _name_legacy
        out = bytearray(n(name) if modern else n(name, root=root))
        width = 4 if modern else 2
        out.extend(len(node["files"]).to_bytes(width, "little"))
        for stem, ext, offset, size, expanded in node["files"]:
            out.extend(n(stem))
            out.extend(n(ext))
            numwidth = 8 if modern else 4
            for number in (offset, size, expanded):
                out.extend(number.to_bytes(numwidth, "little"))
            if modern:
                out.extend(bytes(16))
        out.extend(len(node["dirs"]).to_bytes(width, "little"))
        for dirname, child in node["dirs"].items():
            out.extend(render(child, dirname))
        return out

    encoded = bytes(render(tree, root_name, root=True))
    if directory_codec == "zstd":
        import zstandard
        compressed_directory = zstandard.ZstdCompressor().compress(encoded)
    else:
        compressed_directory = zlib.compress(encoded)
    prefix = struct.pack("<I", len(compressed_directory)) if length_prefix else b""
    body.extend(sk.FMF_MAGIC + bytes(4) + prefix + compressed_directory)
    return bytes(body)


class TemporaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class GoldHENV2Tests(TemporaryTests):
    def args(self, target, output, *extra):
        return ["--generate-patch", target, "--offset", "0x120", "--off", "89 C0", "--on", "90 90",
                "--title-id", "CUSA12345", "--version", "01.00", "--out-dir", output, *extra]

    def test_formula_uses_unaligned_min_vaddr_and_metadata(self):
        import jsonschema
        target = self.write("eboot.elf", elf64(marker=b"\x89\xc0"))
        out = self.root / "output"
        result = invoke(*self.args(target, out))
        self.assertEqual(result.returncode, 0, result.stderr)
        cheat = json.loads((out / "CUSA12345_01.00.json").read_text())
        jsonschema.validate(cheat, SCHEMA)
        self.assertEqual(cheat["mods"][0]["memory"][0]["offset"], "20")
        metadata = json.loads((out / "patch_metadata.json").read_text())
        self.assertEqual(metadata["target_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        deriv = metadata["derivation"]
        self.assertEqual(deriv["load_segments"][0]["p_vaddr"], 0x1100)
        self.assertEqual((deriv["base_vaddr"], deriv["virtual_address"], deriv["candidate_offset"]), (0x1100, 0x1120, 0x20))
        self.assertEqual(deriv["segment"]["p_offset"], 0x100)
        self.assertFalse(deriv["runtime_verified"])
        self.assertIn("0x1100+(0x120-0x100)=0x1120", result.stdout)
        self.assertIn("0x1120-0x1100=0x20", result.stdout)
        self.assertIn("All PT_LOAD p_vaddr values: #0=0x1100", result.stdout)
        self.assertIn("NOT verified", result.stdout)

    def test_lowest_other_load_and_unique_aob_delta(self):
        target = self.write("game.elf", two_load_elf())
        out = self.root / "auto"
        args = self.args(target, out)
        i = args.index("--offset")
        args[i:i + 2] = ["--aob", "48 8B 41 10 C3", "--match-delta", "-2"]
        res = invoke(*args)
        self.assertEqual(res.returncode, 0, res.stderr)
        deriv = json.loads((out / "patch_metadata.json").read_text())["derivation"]
        self.assertEqual((deriv["base_vaddr"], deriv["candidate_offset"]), (0x900, 0x820))
        self.assertEqual([p["p_vaddr"] for p in deriv["load_segments"]], [0x1100, 0x900])
        self.assertEqual(deriv["file_offset"], 0x120)

    def test_range_mapping_rejects_overlap_or_straddle_but_manual_override_works(self):
        for name, data, offset, size in [
            ("overlap", two_load_elf(0x121, 0x2121, 0x20), 0x120, 2),
            ("straddle", elf64(), 0x2ff, 2),
            ("unmapped", elf64(), 0x80, 2),
        ]:
            with self.subTest(name=name), self.assertRaises(sk.ToolError):
                sk.derive_goldhen_candidate(data, offset, size)
        target = self.write("overlap.elf", two_load_elf(0x121, 0x2121, 0x20))
        failed = invoke(*self.args(target, self.root / "failed"))
        self.assertEqual(failed.returncode, 2)
        self.assertIn("ambiguous", failed.stderr)
        self.assertFalse((self.root / "failed").exists())
        manual = invoke(*self.args(target, self.root / "manual", "--goldhen-offset", "0xBEEF"))
        self.assertEqual(manual.returncode, 0, manual.stderr)
        self.assertFalse((self.root / "manual" / "patch_metadata.json").exists())

    def test_invalid_loads_and_raw_require_manual_offset(self):
        bad = bytearray(elf64(marker=b"\x89\xc0"))
        struct.pack_into("<Q", bad, 0x40 + 32, 0x400)  # filesz > memsz
        with self.assertRaisesRegex(sk.ToolError, "p_filesz"):
            sk.derive_goldhen_candidate(bad, 0x120, 2)
        data = b"\x89\xc0" * 200
        target = self.write("raw.bin", data)
        args = self.args(target, self.root / "raw", "--arch", "x86_64")
        i = args.index("--offset")
        args[i + 1] = "0"
        result = invoke(*args)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--goldhen-offset", result.stderr)
        self.assertFalse((self.root / "raw").exists())


class BinaryUnpackV2Tests(TemporaryTests):
    def unpack(self, raw, name="binary.bin", *extra):
        src = self.write(name, raw)
        out = self.root / (name + ".elf")
        return invoke("--unpack-binary", src, "--output", out, *extra), out

    def test_self_plain_and_zlib_reconstructed_with_alias(self):
        for compressed in (False, True):
            raw, payload = fake_self(compressed=compressed)
            result, out = self.unpack(raw, f"{compressed}.self")
            self.assertEqual(result.returncode, 0, result.stderr)
            elf = out.read_bytes()
            self.assertEqual(elf[0x200:0x200 + len(payload)], payload)
            header, ph = sk._elf64_headers(elf, backing_size=len(elf))
            self.assertEqual(header["shoff"], 0)
            self.assertEqual(header["shnum"], 0)
            self.assertEqual(ph[0]["vaddr"], 0x400200)
            self.assertIn("no decryption", result.stdout)

    def test_self_encrypted_corrupt_index_and_zlib_are_refused_no_output(self):
        raw, _ = fake_self(encrypted=True)
        result, out = self.unpack(raw, "encrypted.self")
        self.assertEqual(result.returncode, 2)
        self.assertIn("encrypted", result.stderr)
        self.assertFalse(out.exists())
        raw, _ = fake_self(bad_index=True)
        result, out = self.unpack(raw, "bad-index.self")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())
        raw, _ = fake_self(compressed=True)
        corrupt = bytearray(raw)
        corrupt[-1] ^= 0xff
        result, out = self.unpack(bytes(corrupt), "bad-zlib.self")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())

    def test_self_missing_data_and_output_limit_refused(self):
        raw, _ = fake_self()
        data = bytearray(raw)
        elf_at = 96
        # Alias now points to an unbacked region outside the stored LOAD.
        struct.pack_into("<Q", data, elf_at + 120 + 8, 0x400)
        result, out = self.unpack(bytes(data), "missing.self")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no reconstructible", result.stderr)
        self.assertFalse(out.exists())
        data = bytearray(raw)
        struct.pack_into("<Q", data, elf_at + 64 + 8, 0x200200)
        struct.pack_into("<Q", data, elf_at + 120 + 8, 0x200210)
        result, out = self.unpack(bytes(data), "huge.self", "--max-output-mb", "1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--max-output-mb", result.stderr)
        self.assertFalse(out.exists())

    def test_nso_raw_lz4_elf_headers_hashes_bss_and_no_dependencies(self):
        raw, segments = fake_nso()
        src = self.write("main.nso", raw)
        out = self.root / "main.elf"
        res = subprocess.run([sys.executable, "-S", str(TOOL_PATH), "--unpack-binary", str(src),
                              "--output", str(out)], text=True, capture_output=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("assumption", res.stdout)
        data = out.read_bytes()
        header, ph = sk._elf64_headers(data, backing_size=len(data))
        self.assertEqual((header["machine"], header["type"], header["entry"]), (183, 3, 0))
        self.assertEqual([p["flags"] for p in ph], [5, 4, 6])
        self.assertEqual([p["vaddr"] for p in ph], [0, 0x1000, 0x2000])
        self.assertEqual(ph[2]["memsz"], len(segments[2]) + 0x80)
        for p, expected in zip(ph, segments):
            self.assertEqual(data[p["offset"]:p["offset"] + p["filesz"]], expected)
            self.assertEqual(p["offset"] % p["align"], p["vaddr"] % p["align"])

    def test_lz4_overlapping_match_and_invalid_cases(self):
        raw = b"\x24AB\x02\x00\x50CDEFG"  # AB + 8-byte match + 5 final literals
        self.assertEqual(sk.lz4_raw_decode(raw, 15), b"ABABABABABC DEFG".replace(b" ", b""))
        for malformed, expected in ((b"\x00\x00\x00", 4), (b"\xf0\xff", 10),
                                    (b"\x40ab", 4), (b"\x10A\x02\x00", 5)):
            with self.subTest(malformed=malformed), self.assertRaises(sk.ToolError):
                sk.lz4_raw_decode(malformed, expected)

    def test_nso_hash_zbic_and_truncation_refused(self):
        for name, raw, message in (
            ("hash", fake_nso(bad_hash=True)[0], "SHA-256"),
            ("zbic", fake_nso(flags=0x80)[0], "ZBIC"),
            ("short", fake_nso()[0][:-1], "outside"),
        ):
            result, out = self.unpack(raw, name + ".nso")
            self.assertEqual(result.returncode, 2, (name, result.stdout, result.stderr))
            self.assertIn(message, result.stderr)
            self.assertFalse(out.exists())

    def test_no_overwrite_or_input_clobber(self):
        raw, _ = fake_nso()
        src = self.write("source.nso", raw)
        self.assertEqual(invoke("--unpack-binary", src, "--output", src).returncode, 2)
        self.assertEqual(src.read_bytes(), raw)
        out = self.write("existing.elf", b"existing")
        self.assertEqual(invoke("--unpack-binary", src, "--output", out).returncode, 2)
        self.assertEqual(out.read_bytes(), b"existing")


class FMFV2Tests(TemporaryTests):
    def test_modern_directory_names_zlib_raw_and_info_json(self):
        xml = b'<?xml version="1.0"?><record from="Skin/Foo"/>'
        skin = b"plain panel"
        archive = fake_fmf([(("config.xml",), zlib.compress(xml), len(xml)),
                            (("Panels", "Main.xml"), skin, 0)])
        src = self.write("pack.fmf", archive)
        info = invoke("--fmf-info", src, "--json")
        self.assertEqual(info.returncode, 0, info.stderr)
        report = json.loads(info.stdout)
        self.assertEqual(report["index"]["format"], "FMF 2020-style")
        self.assertEqual({e["path"] for e in report["index"]["entries"]}, {"config.xml", "Panels/Main.xml"})
        out = self.root / "out"
        result = invoke("--fmf-unpack", src, "--output", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / "config.xml").read_bytes(), xml)
        self.assertEqual((out / "Panels/Main.xml").read_bytes(), skin)

    def test_legacy_utf16_directory(self):
        archive = fake_fmf([(("skïn", "logo.png"), b"PNGbytes", 0)], modern=False)
        src = self.write("old.fmf", archive)
        out = self.root / "old-out"
        res = invoke("--fmf-unpack", src, "--output", out)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("legacy UTF-16", res.stdout)
        self.assertEqual((out / "skïn/logo.png").read_bytes(), b"PNGbytes")

    def test_zstd_directory_and_payload(self):
        import zstandard
        xml = b'<?xml version="1.0"?><root>zstd</root>' * 3
        payload = zstandard.ZstdCompressor().compress(xml)
        src = self.write("zstd.fmf", fake_fmf([(("config.xml",), payload, len(xml))], directory_codec="zstd"))
        out = self.root / "zstd-out"
        result = invoke("--fmf-unpack", src, "--output", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / "config.xml").read_bytes(), xml)
        no_site = subprocess.run([sys.executable, "-S", str(TOOL_PATH), "--fmf-info", str(src)], text=True, capture_output=True)
        self.assertEqual(no_site.returncode, 2)
        self.assertIn("pip install zstandard", no_site.stderr)

    def test_prefixed_zstd_and_zlib_directory_with_named_root(self):
        for codec in ("zstd", "zlib"):
            with self.subTest(codec=codec):
                raw = fake_fmf([(("config.xml",), b"<x/>", 0)], directory_codec=codec,
                               length_prefix=True, root_name="fonts")
                src = self.write(codec + "-prefixed.fmf", raw)
                output = self.root / (codec + "-prefixed")
                result = invoke("--fmf-unpack", src, "--output", output)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((output / "fonts/config.xml").read_bytes(), b"<x/>")
                report = json.loads(invoke("--fmf-info", src, "--json").stdout)
                self.assertGreater(report["index"]["directory_length_prefix"], 0)

    def test_carve_unnamed_zlib_and_zstd_streams(self):
        import zstandard
        xml = b'<?xml version="1.0"?><root/> '
        table = b"table contents" * 10
        raw = sk.FMF_MAGIC + bytes(10) + zlib.compress(xml) + b"garbage" + zstandard.ZstdCompressor().compress(table)
        src = self.write("no-index.fmf", raw)
        out = self.root / "carved"
        res = invoke("--fmf-unpack", src, "--output", out)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("approximate", res.stdout)
        self.assertEqual({p.read_bytes() for p in out.iterdir()}, {xml, table})
        self.assertFalse((out / "config.xml").exists())

    def test_declared_zstd_rejects_unrecognized_payload(self):
        raw = bytearray(fake_fmf([(("config.xml",), b"opaque-or-encrypted", 0)]))
        raw[25] = 3  # modern header declares zstd, but the payload is not a frame
        src = self.write("opaque.fmf", bytes(raw))
        out = self.root / "opaque-out"
        result = invoke("--fmf-unpack", src, "--output", out)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported or encrypted", result.stderr)
        self.assertFalse(out.exists())

    def test_reject_traversal_collision_corruption_and_bomb(self):
        for name, entries in (
            ("traversal", [(("../evil.txt",), b"data", 0)]),
            ("collision", [(("A.txt",), b"a", 0), (("a.TXT",), b"b", 0)]),
        ):
            src = self.write(name + ".fmf", fake_fmf(entries))
            out = self.root / (name + "-out")
            res = invoke("--fmf-unpack", src, "--output", out)
            self.assertEqual(res.returncode, 2, (res.stdout, res.stderr))
            self.assertFalse(out.exists())
            self.assertFalse((self.root / "evil.txt").exists())
        src = self.write("bomb.fmf", fake_fmf([(("large.bin",), zlib.compress(b"A" * (2 * 1024 * 1024)), 2 * 1024 * 1024)]))
        out = self.root / "bomb-out"
        res = invoke("--fmf-unpack", src, "--output", out, "--max-output-mb", "1")
        self.assertEqual(res.returncode, 2)
        self.assertIn("--max-output-mb", res.stderr)
        self.assertFalse(out.exists())
        broken = self.write("broken.fmf", fake_fmf([(("file",), b"not a zlib stream", 200)]))
        out = self.root / "broken-out"
        self.assertEqual(invoke("--fmf-unpack", broken, "--output", out).returncode, 2)
        self.assertFalse(out.exists())


class CaseFixV2Tests(TemporaryTests):
    def test_normalized_copy_and_xml_specific_values_only(self):
        source = self.root / "Skin"
        config = b'''<?xml version="1.0" encoding="utf-8"?>
<list>
<!-- <record from="COMMENT/NO"/> -->
<record from="Graphics\\Logos\\Foo.PNG" to="Graphics/Pictures/Club/Logo" note="from='NoTouch'"/>
<record from="VirtualFontID" to="Graphics/Logos/Foo"/>
<string id="path" value="Panels\\Folder\\Thing.XML"/>
<record from="https://Domain/Path"/><record from="&amp;KEEP"/>
<other arbitrary="DoNotLower"/>
</list>'''
        self.write("Skin/Config.XML", config)
        self.write("Skin/Graphics/Logos/Foo.PNG", b"image")
        res = invoke("--fix-mod-case", source)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = self.root / "Skin_lowercase"
        self.assertEqual((out / "graphics/logos/foo.png").read_bytes(), b"image")
        result = (out / "config.xml").read_text()
        self.assertIn('from="graphics/logos/foo.png"', result)
        self.assertIn('to="Graphics/Pictures/Club/Logo"', result)
        self.assertIn('from="VirtualFontID" to="graphics/logos/foo"', result)
        self.assertIn('value="panels/folder/thing.xml"', result)
        self.assertIn('<!-- <record from="COMMENT/NO"/> -->', result)
        self.assertIn("from='NoTouch'", result)
        self.assertIn('arbitrary="DoNotLower"', result)
        self.assertIn('from="https://Domain/Path"', result)
        self.assertIn('from="&amp;KEEP"', result)
        self.assertEqual((source / "Config.XML").read_bytes(), config)

    def test_dry_run_collision_symlink_dtd_and_existing_destination(self):
        source = self.root / "Mod"
        self.write("Mod/Hello.txt", b"a")
        out = self.root / "custom"
        res = invoke("--fix-mod-case", source, "--output", out, "--dry-run")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(out.exists())
        other = source / "hello.TXT"
        if not other.exists():
            other.write_bytes(b"b")
            failed = invoke("--fix-mod-case", source, "--output", out)
            self.assertEqual(failed.returncode, 2)
            self.assertIn("collision", failed.stderr)
            self.assertFalse(out.exists())
            other.unlink()
        config = self.write("Mod/config.xml", b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')
        failed = invoke("--fix-mod-case", source, "--output", out)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("DTD", failed.stderr)
        self.assertFalse(out.exists())
        config.unlink()
        out.mkdir()
        self.assertEqual(invoke("--fix-mod-case", source, "--output", out).returncode, 2)
        out.rmdir()
        link = source / "link"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            return
        failed = invoke("--fix-mod-case", source, "--output", out)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("Symlinks", failed.stderr)
        self.assertFalse(out.exists())


class AndroidAndPackagingV2Tests(TemporaryTests):
    def test_jump_encoder_cross_page_and_optional_macros_host(self):
        compiler = shutil.which("g++")
        if os.name == "nt" or not compiler:
            self.skipTest("Host POSIX C++ compiler unavailable")
        lib = self.root / "lib.so"
        result = subprocess.run([compiler, "-std=c++17", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
                                 "-DOFFLINE_PATCH_ALLOW_RWX", "-DOFFLINE_PATCH_ENABLE_CONSTRUCTOR",
                                 str(ROOT / "templates/android_arm64_hook.cpp"), "-o", str(lib)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        dll = ctypes.CDLL(str(lib))
        encoder = dll.encode_arm64_absolute_jump
        encoder.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64]
        encoder.restype = ctypes.c_int
        jump = ctypes.create_string_buffer(16)
        dest = 0x1122334455667788
        self.assertEqual(encoder(jump, 16, dest), 0)
        self.assertEqual(jump.raw, bytes.fromhex("51 00 00 58 20 02 1F D6 88 77 66 55 44 33 22 11"))
        self.assertEqual(encoder(jump, 15, dest), -1)
        hook = dll.apply_offline_arm64_jump
        hook.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int]
        hook.restype = ctypes.c_int
        region = mmap.mmap(-1, mmap.PAGESIZE * 2, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        try:
            offset = mmap.PAGESIZE - 8
            region[offset:offset + 16] = b"A" * 16
            address = ctypes.addressof(ctypes.c_char.from_buffer(region)) + offset
            expected = ctypes.create_string_buffer(b"A" * 16)
            self.assertEqual(hook(address, expected, dest, mmap.PROT_READ | mmap.PROT_WRITE), 0)
            self.assertEqual(region[offset:offset + 16], jump.raw)
            self.assertEqual(hook(address, expected, dest, mmap.PROT_READ | mmap.PROT_WRITE), -2)
            self.assertEqual(hook(address + 1, expected, dest, mmap.PROT_READ | mmap.PROT_WRITE), -1)
        finally:
            region.close()

    def test_packager_includes_only_verified_elf64_aarch64(self):
        pack = import_file("pack_v2_under_test", ROOT / "tools" / "package_suite.py")
        # Structurally plausible fixture, not a real Android build; packaging
        # can verify ABI/headers but cannot prove build provenance.
        fake = bytearray(elf64(machine=183))
        struct.pack_into("<H", fake, 56, 2)
        struct.pack_into("<IIQQQQQQ", fake, 0x78, 2, 4, 0x180, 0x1180, 0, 16, 16, 8)
        lib = self.write("fixture.so", fake)
        out1, out2 = self.root / "one.zip", self.root / "two.zip"
        pack.build(out1, android_so=lib)
        pack.build(out2, android_so=lib)
        self.assertEqual(out1.read_bytes(), out2.read_bytes())
        with zipfile.ZipFile(out1) as archive:
            self.assertEqual(archive.read(pack.ANDROID_MEMBER), bytes(fake))
            self.assertIsNone(archive.testzip())
        fake[18] = 62  # EM_X86_64
        lib.write_bytes(fake)
        with self.assertRaisesRegex(ValueError, "EM_AARCH64"):
            pack.build(self.root / "bad.zip", android_so=lib)
        self.assertFalse((self.root / "bad.zip").exists())


if __name__ == "__main__":
    unittest.main()
