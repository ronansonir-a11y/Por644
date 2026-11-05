from __future__ import annotations

import asyncio
import base64
import ctypes
import importlib.util
import json
import mmap
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "re_swiss_knife.py"
SERVER_PATH = ROOT / "templates" / "local_ps4_server_emulator.py"


def import_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sk = import_file("re_swiss_knife_under_test", TOOL_PATH)
server = import_file("local_emulator_under_test", SERVER_PATH)
SCHEMA = json.loads((ROOT / "tests" / "goldhen_generated_subset.schema.json").read_text())


def elf64(machine=62, marker=b"") -> bytes:
    """Small, synthetic ELF with one PT_LOAD mapping 0x100->VA 0x1100."""
    result = bytearray(0x300)
    result[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", result, 16, 3, machine, 1, 0, 0x40, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", result, 0x40, 1, 5, 0x100, 0x1100, 0, 0x200, 0x300, 0x1000)
    result[0x120:0x120 + len(marker)] = marker
    return bytes(result)


def elf32(machine=40, endian="<") -> bytes:
    result = bytearray(0x300)
    result[:16] = b"\x7fELF\x01" + (b"\x01" if endian == "<" else b"\x02") + b"\x01" + b"\0" * 9
    struct.pack_into(endian + "HHIIIIIHHHHHH", result, 16, 3, machine, 1, 0, 0x34, 0, 0, 52, 32, 1, 40, 0, 0)
    struct.pack_into(endian + "IIIIIIII", result, 0x34, 1, 0x100, 0x1100, 0, 0x200, 0x300, 5, 0x1000)
    return bytes(result)


def pe64(section=b".UPX0") -> bytes:
    result = bytearray(0x600)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, 0x84, 0x8664, 1, 0, 0x500, 3, 0xF0, 0)
    opt = 0x98
    struct.pack_into("<H", result, opt, 0x20B)
    struct.pack_into("<Q", result, opt + 24, 0x140000000)
    struct.pack_into("<I", result, opt + 60, 0x400)
    section_off = opt + 0xF0
    result[section_off:section_off + len(section)] = section
    struct.pack_into("<IIII", result, section_off + 8, 0x180, 0x1000, 0x200, 0x400)
    return bytes(result)


def macho64(cryptid=1) -> bytes:
    data = bytearray(32 + 24)
    data[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, 0x0100000C)  # arm64
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<IIIIII", data, 32, 0x2C, 24, 0x1000, 0x1000, cryptid, 0)
    return bytes(data)


def invoke(*args: str, python: str = sys.executable) -> subprocess.CompletedProcess:
    return subprocess.run([python, str(TOOL_PATH), *map(str, args)], text=True, capture_output=True, timeout=20)


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, data=b""):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def engine_names(self):
        return [e["name"] for e in sk.analyze_path(self.root)["engines"]]

    def test_unity_il2cpp_and_arm64(self):
        self.write("Game_Data/il2cpp_data/Metadata/global-metadata.dat", b"metadata")
        self.write("lib/arm64-v8a/libil2cpp.so", elf64(183))
        report = sk.analyze_path(self.root)
        self.assertIn("Unity (IL2CPP)", self.engine_names())
        self.assertEqual(report["binaries"][0]["architecture"], "ARM64")

    def test_unity_mono(self):
        self.write("Game_Data/Managed/Assembly-CSharp.dll")
        self.write("UnityPlayer.dll")
        self.assertIn("Unity (Mono)", self.engine_names())

    def test_unity_backend_unknown(self):
        self.write("UnityPlayer.dll")
        self.assertIn("Unity (backend unknown)", self.engine_names())

    def test_unreal_ue5_iostore(self):
        self.write("UE5Game/Content/Paks/global.utoc")
        self.write("UE5Game/Content/Paks/global.ucas")
        self.assertIn("Unreal Engine 5 (IoStore)", self.engine_names())

    def test_iostore_alone_does_not_prove_ue5(self):
        self.write("Content/Paks/global.utoc")
        self.write("Content/Paks/global.ucas")
        result = self.engine_names()[0]
        self.assertIn("UE4.25+ or UE5", result)
        self.assertNotEqual(result, "Unreal Engine 5 (IoStore)")

    def test_unreal_ue4(self):
        self.write("UE4Game/Content/Paks/game.pak")
        self.assertIn("Unreal Engine 4", self.engine_names())

    def test_other_engines_and_fallback(self):
        cases = [("gameinfo.txt", "Source"), ("Data/test.toc", None), ("Data/a.cas", "Frostbite"),
                 ("project.godot", "Godot"), ("renpy/common/stdlib.rpy", "Ren'Py")]
        self.assertIn("Custom C++", self.engine_names()[0])
        for filename, expected in cases:
            self.write(filename)
            if expected:
                self.assertTrue(any(expected in e for e in self.engine_names()), self.engine_names())

    def test_self_and_elf_eboot(self):
        self.write("eboot.bin", b"\x4f\x15\x3d\x1d" + bytes(64))
        b = sk.analyze_path(self.root)["binaries"][0]
        self.assertEqual(b["format"], "PS4 SELF/FSELF container")
        self.assertEqual(b["architecture"], "unknown")
        self.assertIn("cannot be determined", b["protection"][0])
        self.write("eboot.bin", elf64())
        b = sk.analyze_path(self.root)["binaries"][0]
        self.assertEqual(b["format"], "ELF64")
        self.assertEqual(b["architecture"], "x86_64")
        self.assertEqual(sk.map_file_offset(sk.parse_binary(elf64()), 0x120),
                         {"image_va": 0x1120, "rva": 0x120, "image_base": 0x1000})
        self.assertIsNone(sk.map_file_offset(sk.parse_binary(elf64()), 0x40))
        self.assertIsNone(sk.map_file_offset(sk.parse_binary(elf64()), 0x310))  # BSS is not file-backed

    def test_invalid_elf_segment_is_not_mapped(self):
        bad = bytearray(elf64())
        struct.pack_into("<Q", bad, 0x40 + 32, 0x500)  # filesz exceeds memsz
        report = sk.parse_binary(bytes(bad))
        self.assertIsNone(sk.map_file_offset(report, 0x120))
        self.assertTrue(any("Invalid PT_LOAD" in note for note in report.notes))
        truncated = sk.parse_binary(elf64()[:0x130])
        self.assertIsNone(sk.map_file_offset(truncated, 0x120))
        # Header prefix alone must still map a valid larger file when its full size is known.
        prefix = sk.parse_binary(elf64()[:0x130], file_size=0x300)
        self.assertEqual(sk.map_file_offset(prefix, 0x120)["rva"], 0x120)

    def test_switch_nso_does_not_claim_arch_from_magic(self):
        f = self.write("main.nso", b"NSO0" + bytes(128))
        info = sk.analyze_path(f)["binaries"][0]
        self.assertIn("NSO0", info["format"])
        self.assertEqual(info["architecture"], "unknown")
        self.assertTrue(any("ARM64" in n and "not proven" in n for n in info["notes"]))

    def test_elf_symbol_and_debug_section_names(self):
        data = bytearray(elf64()) + bytearray(0x300)
        struct.pack_into("<Q", data, 40, 0x300)  # section table
        struct.pack_into("<HHH", data, 58, 64, 4, 1)
        names = b"\0.shstrtab\0.symtab\0.debug_info\0"
        data[0x500:0x500 + len(names)] = names
        struct.pack_into("<IIQQQQIIQQ", data, 0x340, 1, 3, 0, 0, 0x500, len(names), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", data, 0x380, 11, 2, 0, 0, 0, 0, 0, 0, 8, 24)
        struct.pack_into("<IIQQQQIIQQ", data, 0x3C0, 19, 1, 0, 0, 0, 0, 0, 0, 1, 0)
        report = sk.parse_binary(bytes(data))
        self.assertTrue(any(".symtab" in item for item in report.symbols))
        self.assertTrue(any("DWARF" in item for item in report.symbols))

    def test_pe_rva_compiler_and_packer(self):
        data = bytearray(pe64())
        data[0x410:0x410 + len(b"denuvo GCC: (GNU)")] = b"denuvo GCC: (GNU)"
        info = sk.parse_binary(bytes(data))
        self.assertEqual(info.architecture, "x86_64")
        self.assertEqual(sk.map_file_offset(info, 0x410)["rva"], 0x1010)
        self.assertEqual(sk.map_file_offset(info, 0x410)["image_va"], 0x140001010)
        self.assertIsNone(sk.map_file_offset(info, 0x590))  # raw padding, beyond VirtualSize
        self.assertTrue(any("UPX-like" in s for s in info.protection))
        self.assertTrue(any("not proof" in s for s in info.protection))
        self.assertTrue(any("GCC" in s for s in info.symbols))

    def test_macho_cryptid_and_universal(self):
        for cryptid in (0, 1):
            report = sk.parse_binary(macho64(cryptid))
            self.assertEqual(report.architecture, "ARM64")
            self.assertTrue(any(f"cryptid={cryptid}" in x for x in report.protection))
        fat = bytearray(0x100) + bytearray(macho64(1))
        fat[:4] = b"\xca\xfe\xba\xbe"
        struct.pack_into(">I", fat, 4, 1)
        struct.pack_into(">IIIII", fat, 8, 0x0100000C, 0, 0x100, len(macho64(1)), 0)
        report = sk.parse_binary(bytes(fat))
        self.assertEqual(report.architecture, "ARM64")
        self.assertTrue(any("cryptid=1" in p for p in report.protection))
        self.assertIsNone(sk.map_file_offset(report, 0x120))

    def test_fat_self_referential_slice_is_not_recursed(self):
        fat = bytearray(64)
        fat[:4] = b"\xca\xfe\xba\xbe"
        struct.pack_into(">I", fat, 4, 1)
        struct.pack_into(">IIIII", fat, 8, 0x0100000C, 0, 0, 64, 0)
        report = sk.parse_binary(bytes(fat))
        self.assertTrue(any("invalid" in n for n in report.notes))

    def test_powerpc_arm32_and_arch_mismatch(self):
        self.assertEqual(sk.parse_binary(elf64(21)).architecture, "PowerPC64")
        ppc = sk.parse_binary(elf32(20, ">"))
        self.assertEqual((ppc.architecture, ppc.endian), ("PowerPC", "big"))
        self.assertEqual(sk.map_file_offset(ppc, 0x120)["rva"], 0x120)
        arm = sk.parse_binary(elf32(40))
        self.assertEqual(arm.architecture, "ARM32")
        self.assertTrue(any("ARMv7" in n and "does not" in n for n in arm.notes))
        with self.assertRaises(sk.ToolError):
            sk.choose_arch(arm, "x86_64")

    def test_apk_armv7_abi_hint_is_explicitly_heuristic(self):
        apk = self.root / "armv7.apk"
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("lib/armeabi-v7a/libtest.so", elf32(40))
        binary = sk.analyze_path(apk)["binaries"][0]
        self.assertEqual(binary["architecture"], "ARM32")
        self.assertTrue(any("ARMv7-A" in note and "only a hint" in note for note in binary["notes"]))

    def test_apk_ipa_without_extracting(self):
        apk = self.root / "game.apk"
        with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"mock")
            z.writestr("lib/arm64-v8a/libil2cpp.so", elf64(183))
            z.writestr("../../escape.txt", b"do not extract")
        report = sk.analyze_path(apk)
        self.assertEqual(report["engines"][0]["name"], "Unity (IL2CPP)")
        self.assertEqual(report["binaries"][0]["architecture"], "ARM64")
        self.assertFalse((self.root.parent / "escape.txt").exists())
        ipa = self.root / "game.ipa"
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/Foo.app/Foo", macho64(1))
        report = sk.analyze_path(ipa)
        self.assertTrue(any("cryptid=1" in p for p in report["binaries"][0]["protection"]))

    def test_truncated_headers_are_not_crashes(self):
        for data in (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"NSO0"):
            report = sk.parse_binary(data)
            self.assertIsInstance(report.format, str)
        badzip = self.write("bad.apk", b"not zip")
        self.assertEqual(invoke("--analyze", badzip).returncode, 2)

    def test_cli_json_and_nonexistent_path(self):
        target = self.write("eboot.bin", elf64())
        result = invoke("--analyze", target, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["binaries"][0]["architecture"], "x86_64")
        result = invoke("--analyze", self.root / "missing")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


class AOBTests(unittest.TestCase):
    def test_parse_and_overlapping_matches(self):
        pattern = sk.parse_pattern("AA ? AA")
        self.assertEqual(list(sk.iter_aob_matches(bytes.fromhex("AA AB AA AB AA"), pattern)), [0, 2])
        self.assertEqual(list(sk.iter_aob_matches(b"abc", sk.parse_pattern("FF"))), [])
        for invalid in ("", "?? ?", "A?", "123", "foo", "0x90"):
            with self.subTest(invalid=invalid), self.assertRaises(sk.ToolError):
                sk.parse_pattern(invalid)

    def test_randomized_matcher_agrees_with_naive_scan(self):
        rng = random.Random(20261104)
        for _ in range(500):
            data = bytes(rng.randrange(4) for _ in range(rng.randrange(0, 100)))
            size = rng.randrange(1, 12)
            pattern = [None if rng.randrange(3) == 0 else rng.randrange(4) for _ in range(size)]
            if all(v is None for v in pattern):
                pattern[rng.randrange(size)] = rng.randrange(4)
            expected = [pos for pos in range(max(0, len(data) - size + 1))
                        if all(v is None or data[pos + i] == v for i, v in enumerate(pattern))]
            self.assertEqual(list(sk.iter_aob_matches(data, pattern)), expected)

    def test_x86_signature_masks_branch_and_displacements(self):
        data = bytes.fromhex("48 89 5C 24 08 48 8B 05 78 56 34 12 E8 11 22 33 44 90")
        pattern, lines = sk.make_aob(data, "x86_64", 17)
        self.assertEqual(pattern, "48 89 5C 24 ?? 48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ??")
        mutated = bytes.fromhex("48 89 5C 24 20 48 8B 05 01 02 03 04 E8 AA BB CC DD 90")
        self.assertEqual(list(sk.iter_aob_matches(mutated, sk.parse_pattern(pattern))), [0])
        self.assertTrue(any("relative branch" in line for line in lines))
        self.assertEqual(list(sk.iter_aob_matches(b"\x49" + mutated[1:], sk.parse_pattern(pattern))), [])

    def test_arm64_masks_full_instruction_for_split_fields(self):
        data = bytes.fromhex("FD 7B BF A9 FD 03 00 91 00 00 00 94 1F 20 03 D5")
        pattern, lines = sk.make_aob(data, "arm64", 16)
        self.assertEqual(pattern, "?? ?? ?? ?? FD 03 00 91 ?? ?? ?? ?? 1F 20 03 D5")
        # Top byte of BL also contains two displacement bits; 0x97 is legal.
        mutated = bytes.fromhex("FD 7B BE A9 FD 03 00 91 12 34 56 97 1F 20 03 D5")
        self.assertEqual(list(sk.iter_aob_matches(mutated, sk.parse_pattern(pattern))), [0])
        self.assertTrue(any("relative branch" in line for line in lines))

    def test_arm64_post_index_immediate_is_masked(self):
        # ldp x29,x30,[sp],#16: Capstone exposes the offset as a separate operand.
        pattern, lines = sk.make_aob(bytes.fromhex("FD 7B C1 A8 1F 20 03 D5"), "arm64", 8)
        self.assertEqual(pattern, "?? ?? ?? ?? 1F 20 03 D5")
        self.assertTrue(any("memory displacement" in line for line in lines))

    def test_arm64_adrp_and_literal_masks(self):
        data = bytes.fromhex("01 00 00 90 40 00 00 58 1F 20 03 D5")
        pattern, lines = sk.make_aob(data, "arm64", 12)
        self.assertEqual(pattern, "?? ?? ?? ?? ?? ?? ?? ?? 1F 20 03 D5")
        self.assertTrue(any("PC-relative address" in line for line in lines))
        self.assertTrue(any("PC-relative literal" in line for line in lines))

    def test_bad_alignment_undecodable_and_all_masked(self):
        for data, arch, length, address in [(b"\x90", "x86_64", 2, 0),
                                            (bytes.fromhex("00 00 00 94"), "arm64", 4, 0),
                                            (bytes(8), "arm64", 4, 1),
                                            (bytes(8), "arm64", 3, 0)]:
            with self.subTest(data=data), self.assertRaises(sk.ToolError):
                sk.make_aob(data, arch, length, address)

    def test_cli_scan_and_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "eboot.bin"
            f.write_bytes(elf64(marker=bytes.fromhex("48 89 C0 90 C3")))
            result = invoke("--scan-aob", f, "--pattern", "48 89 ?? 90 C3", "--context", "4")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("file offset 0x120; RVA 0x120", result.stdout)
            self.assertIn("mov", result.stdout)
            self.assertIn("not the live process", result.stdout)

    def test_signature_rounding_and_uniqueness(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "raw.bin"
            code = bytes.fromhex("48 89 C0 E8 11 22 33 44 90")
            f.write_bytes(code + code)
            result = invoke("--make-aob", f, "--arch", "x86_64", "--offset", "0", "--length", "4")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("48 89 C0 E8 ?? ?? ?? ??", result.stdout)
            self.assertIn("not unique", result.stdout)

    def test_optional_capstone_and_invalid_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "raw.bin"
            f.write_bytes(bytes.fromhex("48 89 C0 90"))
            # -S ignores site-packages regardless of the test runner's venv.
            scan = subprocess.run([sys.executable, "-S", str(TOOL_PATH), "--scan-aob", str(f),
                                   "--arch", "x86_64", "--pattern", "48 89 ??"], capture_output=True, text=True)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            self.assertIn("disassembly unavailable", scan.stdout)
            make = subprocess.run([sys.executable, "-S", str(TOOL_PATH), "--make-aob", str(f),
                                   "--arch", "x86_64", "--offset", "0", "--length", "3"], capture_output=True, text=True)
            self.assertEqual(make.returncode, 2)
            self.assertIn("Capstone is required", make.stderr)
            bad = invoke("--scan-aob", f, "--pattern", "?? ??")
            self.assertEqual(bad.returncode, 2)
            self.assertNotIn("Traceback", bad.stderr)


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "eboot.bin"
        self.target.write_bytes(elf64(marker=bytes.fromhex("89 C0 48 8B 41 10 C3")))
        self.out = self.root / "out"

    def tearDown(self):
        self.temp.cleanup()

    def args(self, extra=(), output=None):
        return ["--generate-patch", self.target, "--offset", "0x120", "--off", "89 C0", "--on", "90 90",
                "--title-id", "CUSA12345", "--version", "01.00", "--goldhen-offset", "0xBEEF",
                "--out-dir", output or self.out, *extra]

    def test_generated_json_schema_and_values(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        result = invoke(*self.args())
        self.assertEqual(result.returncode, 0, result.stderr)
        cheat = json.loads((self.out / "CUSA12345_01.00.json").read_text())
        jsonschema.validate(cheat, SCHEMA)
        self.assertEqual(cheat["mods"][0]["memory"][0], {"offset": "BEEF", "on": "9090", "off": "89C0"})
        self.assertEqual(cheat["process"], "eboot.bin")
        self.assertIn("NOT been verified", result.stdout)
        self.assertEqual((self.out / "android_patch_template.cpp").read_text(), sk.ANDROID_TEMPLATE)
        self.assertEqual(sk.ANDROID_TEMPLATE, (ROOT / "templates/android_arm64_hook.cpp").read_text())
        sample = json.loads((ROOT / "templates/goldhen_cheat_sample.json").read_text())
        jsonschema.validate(sample, SCHEMA)
        for key, value in (("id", "CUSA1234"), ("version", "1.00"), ("process", "../eboot.bin")):
            bad = dict(cheat)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(bad, SCHEMA)

    def test_patcher_copy_undo_refusal_and_hash(self):
        self.assertEqual(invoke(*self.args()).returncode, 0)
        script = self.out / "offline_file_patcher.py"
        original = self.target.read_bytes()
        patched, restored = self.root / "patched.bin", self.root / "restored.bin"
        result = subprocess.run([sys.executable, script, self.target, "--output", patched], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(patched.read_bytes()[0x120:0x122], b"\x90\x90")
        self.assertEqual(self.target.read_bytes(), original)
        result = subprocess.run([sys.executable, script, patched, "--output", restored, "--undo"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored.read_bytes(), original)
        for src, dst in ((self.target, self.target), (self.target, patched)):
            result = subprocess.run([sys.executable, script, src, "--output", dst], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        altered = self.root / "altered.bin"
        altered.write_bytes(original[:-1] + b"!")
        badout = self.root / "badout.bin"
        result = subprocess.run([sys.executable, script, altered, "--output", badout], capture_output=True, text=True)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertFalse(badout.exists())

    def test_original_mismatch_lengths_title_version_and_no_clobber(self):
        bad_args = [("--off", "00 00"), ("--on", "90"), ("--title-id", "CUSAXXXXX"),
                    ("--version", "1.0"), ("--goldhen-offset", "-1")]
        for option, value in bad_args:
            result = invoke(*self.args((option, value)))
            self.assertEqual(result.returncode, 2, (option, result.stdout, result.stderr))
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(self.out.exists())
        self.assertEqual(invoke(*self.args()).returncode, 0)
        before = (self.out / "CUSA12345_01.00.json").read_bytes()
        again = invoke(*self.args())
        self.assertEqual(again.returncode, 2)
        self.assertEqual((self.out / "CUSA12345_01.00.json").read_bytes(), before)

    def test_aob_unique_delta_and_ambiguous(self):
        args = self.args()
        i = args.index("--offset")
        args[i:i + 2] = ["--aob", "89 C0 48 8B ?? 10"]
        result = invoke(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        twice = bytearray(self.target.read_bytes())
        twice[0x150:0x156] = bytes.fromhex("89 C0 48 8B 41 10")
        self.target.write_bytes(twice)
        ambiguous = invoke(*self.args(("--aob", "89 C0 48 8B ?? 10"), self.root / "ambig"))
        self.assertEqual(ambiguous.returncode, 2)  # offset + aob rejected
        args = self.args(output=self.root / "ambig")
        i = args.index("--offset")
        args[i:i + 2] = ["--aob", "89 C0 48 8B ?? 10"]
        ambiguous = invoke(*args)
        self.assertEqual(ambiguous.returncode, 2)
        self.assertIn("more than once", ambiguous.stderr)
        self.assertFalse((self.root / "ambig").exists())
        missing = args.copy()
        missing[missing.index("89 C0 48 8B ?? 10")] = "FF EE DD CC"
        self.assertIn("did not match", invoke(*missing).stderr)

    def test_reject_wrong_arch_container_and_raw_without_explicit_arch(self):
        for data in (elf64(183), pe64(), b"\x4f\x15\x3d\x1d" + b"\0" * 64, b"NSO0" + b"\0" * 64):
            self.target.write_bytes(data)
            result = invoke(*self.args())
            self.assertEqual(result.returncode, 2)
            self.assertFalse(self.out.exists())
        self.target.write_bytes(b"\x89\xc0" * 200)
        self.assertIn("explicitly pass --arch x86_64", invoke(*self.args()).stderr)
        self.assertEqual(invoke(*self.args(("--arch", "x86_64"))).returncode, 0)

    def test_file_only_generates_for_pc_without_cheat_metadata(self):
        self.target.write_bytes(pe64())
        args = ["--generate-patch", self.target, "--file-only", "--offset", "0x400", "--off", "00 00", "--on", "90 90", "--out-dir", self.out]
        result = invoke(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["offline_file_patcher.py"])
        dest = self.root / "pc-patched.exe"
        patch = subprocess.run([sys.executable, self.out / "offline_file_patcher.py", self.target, "--output", dest], text=True, capture_output=True)
        self.assertEqual(patch.returncode, 0, patch.stderr)
        self.assertEqual(dest.read_bytes()[0x400:0x402], b"\x90\x90")

    def test_tool_is_standalone_without_repository_templates(self):
        single = self.root / "standalone.py"
        shutil.copyfile(TOOL_PATH, single)
        result = subprocess.run([sys.executable, single, *map(str, self.args())], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.out / "android_patch_template.cpp").read_text(), sk.ANDROID_TEMPLATE)

    def test_aob_match_delta_targets_following_instruction(self):
        args = self.args()
        i = args.index("--offset")
        args[i:i + 2] = ["--aob", "89 C0 48 8B 41 10", "--match-delta", "2"]
        args[args.index("89 C0")] = "48 8B"
        args[args.index("90 90")] = "90 90"
        result = invoke(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("file offset 0x122", result.stdout)

    def test_android_template_compiles_and_checks_expected_bytes(self):
        compiler = shutil.which("g++")
        if os.name == "nt" or not compiler:
            self.skipTest("POSIX host C++ compiler unavailable (NDK compile still recommended)")
        library = self.root / "patch.so"
        compile_result = subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                                         str(ROOT / "templates/android_arm64_hook.cpp"), "-o", str(library)],
                                        text=True, capture_output=True)
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        dll = ctypes.CDLL(str(library))
        fn = dll.apply_offline_patch
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        fn.restype = ctypes.c_int
        region = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        try:
            region[:4] = b"abcd"
            address = ctypes.addressof(ctypes.c_char.from_buffer(region))
            expected, replacement = ctypes.create_string_buffer(b"abcd"), ctypes.create_string_buffer(b"wxyz")
            self.assertEqual(fn(address, expected, replacement, 4, mmap.PROT_READ | mmap.PROT_WRITE), 0)
            self.assertEqual(region[:4], b"wxyz")
            self.assertEqual(fn(address, expected, replacement, 4, mmap.PROT_READ | mmap.PROT_WRITE), -2)
            self.assertEqual(region[:4], b"wxyz")
        finally:
            region.close()


class PackagingTests(unittest.TestCase):
    def test_complete_reproducible_archive_and_no_overwrite(self):
        pack = import_file("pack_suite_under_test", ROOT / "tools" / "package_suite.py")
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / "one.zip", Path(tmp) / "two.zip"
            pack.build(one)
            pack.build(two)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with zipfile.ZipFile(one) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(set(archive.namelist()), set(pack.FILES))
                self.assertNotIn("Ultimate_Game_RE_&_Modding_Suite.zip", archive.namelist())
            with self.assertRaises(ValueError):
                pack.build(one)
            pack.build(one, force=True)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with self.assertRaises(ValueError):
                pack.build(ROOT / "README.md", force=True)


class LocalServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tcp, self.udp, self.state = await server.start_services("127.0.0.1", 0, 0)
        self.port = self.tcp.sockets[0].getsockname()[1]
        self.udp_port = self.udp.get_extra_info("sockname")[1]

    async def asyncTearDown(self):
        self.tcp.close()
        await self.tcp.wait_closed()
        self.udp.close()

    async def request(self, raw: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(raw)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 3)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_http_health_state_input_and_replay(self):
        health = await self.request(b"GET /health HTTP/1.1\r\nHost: local\r\n\r\n")
        self.assertTrue(health.startswith(b"HTTP/1.1 200"))
        self.assertEqual(json.loads(health.split(b"\r\n\r\n", 1)[1])["service"], "synthetic-offline-demo")
        body = b'{"type":"move","seq":1,"dx":1,"dy":-1}'
        req = (b"POST /input HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
        first = await self.request(req)
        self.assertTrue(first.startswith(b"HTTP/1.1 200"))
        self.assertEqual(json.loads(first.split(b"\r\n\r\n", 1)[1])["state"]["x"], 1)
        replay = await self.request(req)
        self.assertTrue(replay.startswith(b"HTTP/1.1 400"))
        self.assertEqual(self.state.tick, 1)
        state = await self.request(b"GET /state HTTP/1.1\r\nHost: local\r\n\r\n")
        self.assertEqual(json.loads(state.split(b"\r\n\r\n", 1)[1])["state"]["y"], -1)

    async def test_bind_restrictions_and_bad_http(self):
        for address, lan in (("0.0.0.0", True), ("8.8.8.8", True), ("192.168.1.2", False), ("::1", True)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                server.check_bind(address, lan)
        server.check_bind("192.168.1.2", True)
        for extra in (b"Origin: https://example.invalid\r\n", b"Transfer-Encoding: chunked\r\n"):
            resp = await self.request(b"GET /state HTTP/1.1\r\nHost: local\r\n" + extra + b"\r\n")
            self.assertTrue(resp.startswith(b"HTTP/1.1 403"))
        duplicate = await self.request(b"GET /health HTTP/1.1\r\nHost: local\r\nHost: local\r\n\r\n")
        self.assertTrue(duplicate.startswith(b"HTTP/1.1 400"))
        invalid = server.State().apply({"type": "move", "seq": True, "dx": 999, "dy": 0})
        self.assertFalse(invalid["ok"])

    async def test_deep_json_is_rejected_without_crashing(self):
        body = b"[" * 1500 + b"0" + b"]" * 1500
        req = (b"POST /input HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
        response = await self.request(req)
        self.assertTrue(response.startswith(b"HTTP/1.1 400"), response)
        self.assertEqual(self.state.tick, 0)

    async def test_udp_state_validation(self):
        future = asyncio.get_running_loop().create_future()

        class Client(asyncio.DatagramProtocol):
            def connection_made(inner, transport):
                inner.transport = transport
                transport.sendto(b'{"type":"move","seq":2,"dx":1,"dy":0}')

            def datagram_received(inner, data, addr):
                if not future.done():
                    future.set_result(json.loads(data))

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            Client, remote_addr=("127.0.0.1", self.udp_port))
        try:
            response = await asyncio.wait_for(future, 3)
            self.assertTrue(response["ok"])
            self.assertEqual(response["state"]["x"], 1)
            self.assertEqual(self.state.last_seq, 2)
        finally:
            transport.close()

    async def test_websocket_handshake_and_masked_frame(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        key = base64.b64encode(b"1234567890123456")
        writer.write(b"GET /ws HTTP/1.1\r\nHost: local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n\r\n")
        await writer.drain()
        handshake = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        self.assertIn(b"101 Switching Protocols", handshake)
        payload = b'{"type":"move","seq":3,"dx":0,"dy":1}'
        mask = b"abcd"
        encrypted = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        writer.write(bytes((0x81, 0x80 | len(payload))) + mask + encrypted)
        await writer.drain()
        first, length = await asyncio.wait_for(reader.readexactly(2), 3)
        self.assertEqual(first, 0x81)
        self.assertLess(length, 126)
        result = json.loads(await reader.readexactly(length))
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"]["y"], 1)
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
