from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

# Standalone tool; all fixtures below are invented and contain no game assets.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import granny_apk_recon as recon


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name, content in entries:
                archive.writestr(name, content)
    return stream.getvalue()


def text_manifest(package=recon.PACKAGE, code=92, name="1.8.12", split=None, extra=""):
    split_attr = f' split="{split}"' if split is not None else ""
    return (f'<manifest xmlns:android="{recon.ANDROID_NS}" package="{package}" '
            f'android:versionCode="{code}" android:versionName="{name}"{split_attr} {extra}>'
            '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />'
            '</manifest>').encode()


def elf(machine=183, bits=64, endian="<"):
    data = bytearray(64)
    data[:7] = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if endian == "<" else 2, 1))
    struct.pack_into(endian + "H", data, 18, machine)
    return bytes(data)


def metadata(strings=b""):
    return struct.pack("<II", 0xFAB11BAF, 31) + strings


def serialized_file(version="2022.3.9f1", format_version=17):
    at = 48 if format_version >= 22 else 20
    data = bytearray(256)
    if format_version >= 22:
        struct.pack_into(">IIII", data, 0, 0, 0, format_version, 0)
        struct.pack_into(">IQQQ", data, 20, 64, len(data), 128, 0)
    else:
        struct.pack_into(">IIII", data, 0, 64, len(data), format_version, 128)
    encoded = version.encode() + b"\0"
    data[at:at + len(encoded)] = encoded
    return bytes(data)


def bundle_header(version="2021.3.7f1"):
    return b"UnityFS\0" + struct.pack(">I", 6) + b"5.x.x\0" + version.encode() + b"\0" + bytes(48)


def _length8(size):
    return bytes(((size >> 8) | 0x80, size & 0xff)) if size > 0x7f else bytes((size,))


def binary_manifest(utf8=True, split=None, version_name="1.8.12", version_code=92,
                    package=recon.PACKAGE, resource_name=False, include_end=True):
    strings = ["manifest", "package", package, recon.ANDROID_NS, "versionCode", "versionName",
               version_name, "split", split or "", "uses-sdk", "minSdkVersion", "targetSdkVersion"]
    offsets, body = [], bytearray()
    for value in strings:
        offsets.append(len(body))
        if utf8:
            raw = value.encode("utf-8")
            units = len(value.encode("utf-16le")) // 2
            body += _length8(units) + _length8(len(raw)) + raw + b"\0"
        else:
            raw = value.encode("utf-16le")
            units = len(raw) // 2
            assert units < 0x8000
            body += struct.pack("<H", units) + raw + b"\0\0"
    while len(body) % 4:
        body += b"\0"
    strings_start = 28 + len(strings) * 4
    pool_size = strings_start + len(body)
    pool = (struct.pack("<HHIIIIII", 1, 28, pool_size, len(strings), 0,
                        0x100 if utf8 else 0, strings_start, 0)
            + struct.pack("<" + "I" * len(offsets), *offsets) + body)

    def attribute(ns, key, raw, kind, value):
        return struct.pack("<IIIHBBI", ns, key, raw, 8, 0, kind, value)

    def start(element, attrs):
        size = 16 + 20 + len(attrs) * 20
        return (struct.pack("<HHIII", 0x102, 16, size, 1, recon.UNKNOWN)
                + struct.pack("<IIHHHHHH", recon.UNKNOWN, element, 20, 20, len(attrs), 0, 0, 0)
                + b"".join(attrs))

    def end(element):
        return struct.pack("<HHIIIII", 0x103, 16, 24, 1, recon.UNKNOWN, recon.UNKNOWN, element)

    attrs = [attribute(recon.UNKNOWN, 1, 2, 3, 2),
             attribute(3, 4, recon.UNKNOWN, 0x10, version_code),
             attribute(3, 5, recon.UNKNOWN if resource_name else 6,
                       1 if resource_name else 3, 0x7f010001 if resource_name else 6)]
    if split is not None:
        attrs.append(attribute(recon.UNKNOWN, 7, 8, 3, 8))
    sdk = [attribute(3, 10, recon.UNKNOWN, 0x10, 24),
           attribute(3, 11, recon.UNKNOWN, 0x10, 36)]
    chunks = pool + start(0, attrs) + start(9, sdk) + end(9) + (end(0) if include_end else b"")
    return struct.pack("<HHI", 3, 8, 8 + len(chunks)) + chunks


def base_apk(manifest=None, extra=()):
    return zip_bytes([("AndroidManifest.xml", manifest or text_manifest()), *extra])


class GrannyReconTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_text_manifest_fields_and_unresolved_references(self):
        data = text_manifest(name="@string/app_version", split="config.arm64_v8a",
                             extra='android:isSplitRequired="true" android:requiredSplitTypes="base__abi"')
        result = recon.parse_manifest(data)
        self.assertEqual(result["format"], "text-xml")
        self.assertEqual((result["package"], result["version_code"], result["split"]),
                         (recon.PACKAGE, 92, "config.arm64_v8a"))
        self.assertEqual((result["min_sdk"], result["target_sdk"]), (24, 36))
        self.assertTrue(result["is_split_required"])
        self.assertEqual(result["unresolved"]["version_name"], "@string/app_version")
        self.assertIsNone(result["version_name"])
        self.assertEqual(recon.parse_manifest(b"\xef\xbb\xbf" + text_manifest())["package"], recon.PACKAGE)

    def test_binary_utf8_and_utf16_manifest(self):
        for utf8 in (True, False):
            with self.subTest(utf8=utf8):
                result = recon.parse_manifest(binary_manifest(utf8=utf8, split="config.arm64_v8a"))
                self.assertEqual(result["format"], "binary-axml")
                self.assertEqual(result["package"], recon.PACKAGE)
                self.assertEqual((result["version_code"], result["version_name"]), (92, "1.8.12"))
                self.assertEqual((result["min_sdk"], result["target_sdk"]), (24, 36))
                self.assertEqual(result["split"], "config.arm64_v8a")

    def test_binary_long_utf8_length_and_unicode(self):
        value = "π" * 80 + "v"
        self.assertEqual(recon.parse_manifest(binary_manifest(version_name=value))["version_name"], value)

    def test_binary_resource_reference_is_not_fabricated(self):
        result = recon.parse_manifest(binary_manifest(resource_name=True))
        self.assertIsNone(result["version_name"])
        self.assertEqual(result["unresolved"]["version_name"], "@0x7f010001")

    def test_malformed_manifest_rejected_and_xml_entities_disallowed(self):
        cases = [b"", b"\x03\x00\x08\x00\xff\xff\xff\xff", binary_manifest()[:-4],
                 binary_manifest(include_end=False), b"<foo><manifest/></foo>",
                 b'<!DOCTYPE x [<!ENTITY a "abc">]><manifest package="&a;"/>']
        for value in cases:
            with self.subTest(value=value[:20]), self.assertRaises(recon.ReconError):
                recon.parse_manifest(value)

    def test_corrupt_string_pool_offsets_are_bounded(self):
        data = bytearray(binary_manifest())
        struct.pack_into("<I", data, 8 + 28, 0x7fffffff)
        with self.assertRaises(recon.ReconError):
            recon.parse_manifest(bytes(data))

    def test_binary_manifest_root_namespace_must_be_unqualified(self):
        data = bytearray(binary_manifest())
        pos = 8
        while pos < len(data):
            kind, header, size = struct.unpack_from("<HHI", data, pos)
            if kind == 0x0102:
                struct.pack_into("<I", data, pos + header, 3)  # Android namespace index
                break
            pos += size
        with self.assertRaisesRegex(recon.ReconError, "root element"):
            recon.parse_manifest(bytes(data))

    def test_mutated_axml_has_no_unexpected_parser_exception(self):
        rng = random.Random(20261105)
        for index in range(1000):
            data = bytearray(binary_manifest(utf8=bool(index % 2)))
            for _ in range(rng.randrange(1, 5)):
                if rng.randrange(10) == 0:
                    del data[rng.randrange(len(data)):]
                    if not data:
                        break
                else:
                    data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                recon.parse_manifest(bytes(data))
            except recon.ReconError:
                pass

    def test_one_apk_unity_il2cpp_and_marker_evidence(self):
        m = metadata(b"\0HutongGames.PlayMaker\0PlayMakerFSM\0AstarPath\0FPSControllerNEW\0")
        original = base_apk(binary_manifest(), [
            ("assets/bin/Data/Managed/Metadata/global-metadata.dat", m),
            ("assets/bin/Data/globalgamemanagers", serialized_file()),
            ("lib/arm64-v8a/libil2cpp.so", elf()),
            ("lib/arm64-v8a/libunity.so", elf()),
        ])
        path = self.write("game.apk", original)
        result = recon.inspect_input(path)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(result["apks"][0]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(result["summary"]["identity"], "matches-granny")
        self.assertEqual(result["summary"]["backend"], "il2cpp-indicated")
        self.assertEqual(result["summary"]["abis"], ["arm64-v8a"])
        self.assertEqual(result["apks"][0]["metadata_headers"][0]["version"], 31)
        self.assertTrue(result["apks"][0]["native_libraries"][0]["matches_abi"])
        self.assertEqual(result["summary"]["unity_versions"][0]["version"], "2022.3.9f1")
        for group in ("playmaker", "astar", "input_and_gameplay"):
            self.assertEqual(result["summary"]["indicators"][group]["status"], "raw-string-indicator")
            self.assertGreaterEqual(result["summary"]["indicators"][group]["evidence"][0]["offset"], 8)

    def test_unity_format_22_and_bundle_header(self):
        for payload, method in ((serialized_file("2021.3.7f1", 22), "serialized-file-header"),
                                (bundle_header(), "bundle-header")):
            with self.subTest(method=method):
                self.assertEqual(recon._unity_header(payload, len(payload)), ("2021.3.7f1", method))
        corrupt = bytearray(serialized_file())
        struct.pack_into(">I", corrupt, 4, len(corrupt) + 1)
        self.assertIsNone(recon._unity_header(bytes(corrupt), len(corrupt)))

    def test_unity_raw_fallback_is_explicitly_heuristic(self):
        path = self.write("game.apk", base_apk(extra=[("assets/bin/Data/globalgamemanagers", b"abc2020.3.8f1\0")]))
        version = recon.inspect_input(path)["summary"]["unity_versions"][0]
        self.assertEqual((version["version"], version["confidence"]), ("2020.3.8f1", "heuristic"))

    def test_compatible_split_directory_crosses_metadata_and_libraries(self):
        folder = self.root / "splits"
        folder.mkdir()
        base = base_apk(binary_manifest(), [("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata())])
        split = base_apk(binary_manifest(split="config.arm64_v8a"), [("lib/arm64-v8a/libil2cpp.so", elf())])
        (folder / "base.apk").write_bytes(base)
        (folder / "split_config.arm64_v8a.apk").write_bytes(split)
        (folder / "ignored.txt").write_text("untouched")
        before = {p.name: p.read_bytes() for p in folder.iterdir()}
        r = recon.inspect_input(folder)
        self.assertEqual(r["summary"]["grouping"], "manifest-consistent-not-signature-verified")
        self.assertEqual(r["summary"]["backend"], "il2cpp-indicated")
        self.assertEqual(r["apks"][0]["backend"], "partial-or-ambiguous")
        self.assertEqual({p.name: p.read_bytes() for p in folder.iterdir()}, before)

    def test_xapk_bundle_spools_without_extracting_named_paths(self):
        base = base_apk(binary_manifest(), [("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata())])
        split = base_apk(binary_manifest(split="config.arm64_v8a"), [("lib/arm64-v8a/libil2cpp.so", elf())])
        bundle = zip_bytes([("base.apk", base), ("splits/arm64.apk", split),
                            ("../escape.apk", base), ("main.obb", b"not examined")])
        path = self.write("game.xapk", bundle)
        tempdir = self.root / "scratch"
        tempdir.mkdir()
        with mock.patch.object(recon, "SPOOL_MEMORY", 1), mock.patch.object(tempfile, "tempdir", str(tempdir)):
            r = recon.inspect_input(path)
        self.assertEqual(r["input"]["kind"], "split-bundle")
        self.assertEqual(r["summary"]["backend"], "il2cpp-indicated")
        self.assertTrue(any("Unsafe ZIP member" in w for w in r["summary"]["warnings"]))
        self.assertTrue(any("OBB" in w for w in r["summary"]["warnings"]))
        self.assertEqual(list(tempdir.iterdir()), [])
        self.assertFalse((self.root / "escape.apk").exists())
        self.assertEqual(path.read_bytes(), bundle)

    def test_apks_multiple_bases_and_toc_are_not_combined(self):
        base1 = base_apk(binary_manifest(), [("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata())])
        base2 = base_apk(binary_manifest(), [("lib/x86_64/libil2cpp.so", elf(62))])
        path = self.write("variants.apks", zip_bytes([("toc.pb", b"not parsed"), ("one/base.apk", base1), ("two/base.apk", base2)]))
        r = recon.inspect_input(path)
        self.assertEqual(r["summary"]["grouping"], "ambiguous-do-not-combine")
        self.assertEqual(r["summary"]["backend"], "unresolved-see-individual-apks")
        self.assertEqual(r["summary"]["abis"], [])
        self.assertEqual(r["summary"]["indicators"]["playmaker"]["status"], "unresolved-see-individual-apks")
        self.assertTrue(any("toc.pb" in w for w in r["summary"]["warnings"]))

    def test_conflicting_packages_and_versions_never_cross_combine(self):
        for split_manifest in (binary_manifest(split="config.arm64_v8a", version_code=93),
                               binary_manifest(split="config.arm64_v8a", version_name="1.8.13"),
                               binary_manifest(split="config.arm64_v8a", package="another.app")):
            base = base_apk(binary_manifest(), [("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata())])
            split = base_apk(split_manifest, [("lib/arm64-v8a/libil2cpp.so", elf())])
            path = self.write("conflict.xapk", zip_bytes([("base.apk", base), ("split.apk", split)]))
            r = recon.inspect_input(path)
            self.assertEqual(r["summary"]["grouping"], "conflicting-identities")
            self.assertEqual(r["summary"]["backend"], "unresolved-see-individual-apks")

    def test_missing_split_version_is_ambiguous(self):
        split = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.dvloper.granny" split="config.arm64_v8a"/>'
        path = self.write("missing.zip", zip_bytes([("base.apk", base_apk()), ("split.apk", base_apk(split))]))
        self.assertEqual(recon.inspect_input(path)["summary"]["grouping"], "ambiguous-do-not-combine")

    def test_version_code_major_conflict_is_not_combined(self):
        base = base_apk(text_manifest(extra='android:versionCodeMajor="0"'))
        split = base_apk(text_manifest(split="config.arm64_v8a", extra='android:versionCodeMajor="1"'))
        path = self.write("major.xapk", zip_bytes([("base.apk", base), ("split.apk", split)]))
        r = recon.inspect_input(path)
        self.assertEqual(r["summary"]["grouping"], "conflicting-identities")
        self.assertEqual(r["summary"]["backend"], "unresolved-see-individual-apks")

    def test_single_split_and_required_split_warnings(self):
        path = self.write("split.apk", base_apk(binary_manifest(split="config.arm64_v8a")))
        r = recon.inspect_input(path)
        self.assertTrue(any("base APK is missing" in w for w in r["summary"]["warnings"]))
        path.write_bytes(base_apk(text_manifest(extra='android:isSplitRequired="true"')))
        r = recon.inspect_input(path)
        self.assertTrue(any("split requirements" in w for w in r["summary"]["warnings"]))

    def test_mono_assembly_playmaker_filename_and_mixed_backend(self):
        managed = [("assets/bin/Data/Managed/Assembly-CSharp.dll", b"MZ synthetic"),
                   ("assets/bin/Data/Managed/PlayMaker.dll", b"MZ synthetic")]
        path = self.write("mono.apk", base_apk(extra=managed))
        r = recon.inspect_input(path)
        self.assertEqual(r["summary"]["backend"], "mono-indicated")
        self.assertEqual(r["summary"]["indicators"]["playmaker"]["status"], "file-indicator")
        path.write_bytes(base_apk(extra=managed + [("lib/arm64-v8a/libil2cpp.so", elf()),
                         ("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata())]))
        self.assertEqual(recon.inspect_input(path)["summary"]["backend"], "mixed-or-ambiguous")

    def test_abi_mismatch_and_invalid_metadata_are_warnings_not_guarantees(self):
        path = self.write("bad_headers.apk", base_apk(extra=[("lib/arm64-v8a/libil2cpp.so", elf(62)),
                          ("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"not metadata")]))
        apk = recon.inspect_input(path)["apks"][0]
        self.assertFalse(apk["native_libraries"][0]["matches_abi"])
        self.assertFalse(recon._native_header(elf(machine=183, bits=32), "arm64-v8a")["matches_abi"])
        self.assertFalse(recon._native_header(elf(machine=183, endian=">"), "arm64-v8a")["matches_abi"])
        self.assertFalse(apk["metadata_headers"][0]["magic_valid"])
        self.assertGreaterEqual(len(apk["warnings"]), 2)
        # Backend is explicitly a file-layout indicator, not a validity/boot claim.
        self.assertEqual(apk["backend"], "il2cpp-indicated")

    def test_raw_utf16_marker_across_chunk_boundary(self):
        marker = "PlayMakerFSM".encode("utf-16le")
        contents = metadata(b"x" * (recon.CHUNK - 10) + marker)
        path = self.write("cross.apk", base_apk(extra=[("assets/bin/Data/Managed/Metadata/global-metadata.dat", contents)]))
        evidence = recon.inspect_input(path)["apks"][0]["markers"]["playmaker"]
        hit = next(x for x in evidence if x["marker"] == "PlayMakerFSM" and x["encoding"] == "utf-16le")
        self.assertEqual(hit["offset"], recon.CHUNK - 2)

    def test_budget_truncation_never_means_not_present(self):
        contents = metadata(b"x" * recon.MIB + b"PlayMakerFSM")
        path = self.write("large.apk", base_apk(extra=[("assets/bin/Data/Managed/Metadata/global-metadata.dat", contents)]))
        r = recon.inspect_input(path, scan_limit_mib=1, per_file_mib=1)
        self.assertEqual(r["summary"]["indicators"]["playmaker"]["status"], "unknown")
        self.assertTrue(r["apks"][0]["inspection_incomplete"])
        self.assertEqual(r["limits"]["marker_bytes_read"], recon.MIB)
        self.assertFalse(r["apks"][0]["scanned_members"][0]["complete"])

    def test_absent_or_corrupt_manifest_reports_unknown(self):
        path = self.write("no_manifest.apk", zip_bytes([("assets/bin/Data/globalgamemanagers", b"data")]))
        r = recon.inspect_input(path)
        self.assertEqual(r["summary"]["identity"], "unknown")
        self.assertTrue(r["apks"][0]["inspection_incomplete"])
        path.write_bytes(base_apk(b"\x03\0broken"))
        r = recon.inspect_input(path)
        self.assertTrue(any("Manifest unreadable" in w for w in r["apks"][0]["warnings"]))

    def test_duplicate_zip_members_refused(self):
        path = self.write("duplicate.apk", zip_bytes([("AndroidManifest.xml", text_manifest()),
                                                     ("AndroidManifest.xml", text_manifest())]))
        with self.assertRaisesRegex(recon.ReconError, "duplicate"):
            recon.inspect_input(path)

    def test_path_traversal_within_apk_is_skipped(self):
        outside = self.root.parent / (self.root.name + "-escaped")
        path = self.write("unsafe.apk", base_apk(extra=[(f"../{outside.name}/PlayMaker.dll", b"x")]))
        r = recon.inspect_input(path)
        self.assertEqual(r["summary"]["indicators"]["playmaker"]["status"], "unknown")
        self.assertTrue(r["apks"][0]["inspection_incomplete"])
        self.assertFalse(outside.exists())

    def test_encrypted_manifest_is_not_read_or_decrypted(self):
        data = bytearray(zip_bytes([("AndroidManifest.xml", text_manifest())], zipfile.ZIP_STORED))
        local, central = data.find(b"PK\x03\x04"), data.find(b"PK\x01\x02")
        struct.pack_into("<H", data, local + 6, 1)
        struct.pack_into("<H", data, central + 8, 1)
        r = recon.inspect_input(self.write("encrypted.apk", data))
        self.assertEqual(r["summary"]["identity"], "unknown")
        self.assertTrue(any("encrypted" in w for w in r["apks"][0]["warnings"]))

    def test_malformed_crc_is_reported(self):
        data = bytearray(zip_bytes([("AndroidManifest.xml", text_manifest())], zipfile.ZIP_STORED))
        local = data.find(b"PK\x03\x04")
        name_length, extra_length = struct.unpack_from("<HH", data, local + 26)
        data[local + 30 + name_length + extra_length + 5] ^= 1
        r = recon.inspect_input(self.write("corrupt.apk", data))
        self.assertEqual(r["summary"]["identity"], "unknown")
        self.assertTrue(any("Manifest unreadable" in w for w in r["apks"][0]["warnings"]))

    def test_entry_and_nested_count_limits(self):
        path = self.write("many.apk", base_apk(extra=[("a", b"1"), ("b", b"2")]))
        with mock.patch.object(recon, "MAX_ENTRIES", 2), self.assertRaisesRegex(recon.ReconError, "ZIP entries"):
            recon.inspect_input(path)
        bundle = self.write("many.apks", zip_bytes([("a.apk", base_apk()), ("b.apk", base_apk())]))
        with mock.patch.object(recon, "MAX_APKS", 1), self.assertRaisesRegex(recon.ReconError, "1..1"):
            recon.inspect_input(bundle)

    def test_compressed_nested_apk_bomb_refused(self):
        nested = b"\0" * (recon.MIB + 1)
        path = self.write("bomb.xapk", zip_bytes([("huge.apk", nested)]))
        with self.assertRaisesRegex(recon.ReconError, "compression ratio"):
            recon.inspect_input(path)

    def test_aggregate_and_per_apk_size_limits(self):
        path = self.write("tiny.apk", base_apk())
        with mock.patch.object(recon, "MAX_APK_SIZE", 8), self.assertRaisesRegex(recon.ReconError, "APK exceeds"):
            recon.inspect_input(path)
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "a.apk").write_bytes(base_apk())
        (folder / "b.apk").write_bytes(base_apk())
        with mock.patch.object(recon, "MAX_NESTED_TOTAL", len(base_apk()) + 1):
            with self.assertRaisesRegex(recon.ReconError, "aggregate"):
                recon.inspect_input(folder)

    def test_symlinks_are_not_followed_if_supported(self):
        path = self.write("real.apk", base_apk())
        link = self.root / "link.apk"
        try:
            link.symlink_to(path)
        except (OSError, NotImplementedError):
            self.skipTest("host does not permit symlinks")
        with self.assertRaisesRegex(recon.ReconError, "symlinks"):
            recon.inspect_input(link)

    def test_cli_json_stdlib_only_and_strict_package(self):
        path = self.write("game.apk", base_apk(binary_manifest()))
        cmd = [sys.executable, "-I", str(ROOT / "tools/granny_apk_recon.py"), str(path), "--json", "--require-granny"]
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["summary"]["package"], recon.PACKAGE)
        path.write_bytes(base_apk(binary_manifest(package="different.package")))
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 3)
        self.assertEqual(json.loads(run.stdout)["summary"]["identity"], "different-package")

    def test_cli_invalid_input_and_budget(self):
        path = self.write("game.apk", base_apk())
        cmd = [sys.executable, str(ROOT / "tools/granny_apk_recon.py"), str(path), "--scan-limit-mib", "0"]
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 2)
        self.assertIn("scan limit", run.stderr)
        run = subprocess.run([sys.executable, str(ROOT / "tools/granny_apk_recon.py"), str(self.root / "missing.apk")],
                             capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 2)

    def test_package_allowlist_contains_recon_deliverables(self):
        from tools.package_suite import FILES
        for name in ("tools/granny_apk_recon.py", "docs/GRANNY_PS4_RECON_RU.md", "tests/test_granny_apk_recon.py"):
            self.assertIn(name, FILES)


if __name__ == "__main__":
    unittest.main()
