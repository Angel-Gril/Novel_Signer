"""Verify JNI registration and Java tag-to-entry provenance boundaries.

This is a read-only provenance check.  It combines pinned ELF instruction
facts with the decompiled Java call sites and a bounded historical unidbg
capture.  The capture is used only for registration/class/signature/offset
markers; request URLs, headers, identifiers and returned values are never
copied into the evidence record.

The result closes ownership of the JNI entry function and static Java provenance
for the public signing and frameSign tags. It does not claim a live Android JVM,
a complete request differential, or a fresh signer result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile


EXPECTED_LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
JNI_ONLOAD = 0x27B41C
JNI_ENTRY = 0x26E684
REGISTER_CALLSITE = 0x26E514
REGISTER_METHOD_SLOT = 0xB8
REGISTER_COUNT = 1
TAG_SIGN = 0x3000001
TAG_FRAME_SIGN = 0x200000A
SIGNATURE = "a(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_instructions(library: Path, addresses: tuple[int, ...]) -> dict[str, dict[str, str]]:
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        if text is None:
            raise AssertionError("ELF has no .text section")
        data = text.data()
        text_base = int(text["sh_addr"])
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        result: dict[str, dict[str, str]] = {}
        for address in addresses:
            offset = address - text_base
            rows = list(decoder.disasm(data[offset : offset + 4], address, count=1))
            if len(rows) != 1:
                raise AssertionError(f"cannot decode {address:#x}")
            row = rows[0]
            result[hex(address)] = {
                "mnemonic": row.mnemonic,
                "operands": row.op_str,
            }
        return result


def verify_elf(library: Path) -> dict:
    digest = sha256_file(library)
    if digest != EXPECTED_LIBRARY_SHA256:
        raise AssertionError(f"unexpected native sample {digest}")
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            raise AssertionError("ELF has no .dynsym")
        jni_symbols = [
            {"name": symbol.name, "value": hex(int(symbol["st_value"]))}
            for symbol in dynsym.iter_symbols()
            if symbol.name == "JNI_OnLoad"
        ]
        if jni_symbols != [{"name": "JNI_OnLoad", "value": hex(JNI_ONLOAD)}]:
            raise AssertionError(f"unexpected JNI_OnLoad export: {jni_symbols}")

    addresses = (
        0x26E684, 0x26E688, 0x26E68C, 0x26E690, 0x26E694, 0x26E698,
        0x26E4F8, 0x26E500, 0x26E504, 0x26E508, 0x26E50C,
        0x26E514, 0x26E518, 0x26E51C, 0x26E520, 0x26E524,
    )
    instructions = decode_instructions(library, addresses)
    expected = {
        "0x26e684": ("mov", "x1, x0"),
        "0x26e688": ("mov", "w0, w2"),
        "0x26e68c": ("mov", "w2, w3"),
        "0x26e690": ("mov", "x3, x4"),
        "0x26e694": ("mov", "x4, x5"),
        "0x26e698": ("mov", "x5, x6"),
        "0x26e4f8": ("mov", "w3, #1"),
        "0x26e500": ("ldr", "x8, [x9, #0x6b8]"),
        "0x26e504": ("adrp", "x9, #0x26e000"),
        "0x26e508": ("add", "x9, x9, #0x684"),
        "0x26e50c": ("str", "x9, [x21, #0x10]"),
        "0x26e514": ("ldr", "x8, [x19]"),
        "0x26e518": ("mov", "x0, x19"),
        "0x26e51c": ("mov", "x1, x24"),
        "0x26e520": ("ldr", "x8, [x8, #0xb8]"),
        "0x26e524": ("blr", "x8"),
    }
    actual = {
        address: (row["mnemonic"], row["operands"])
        for address, row in instructions.items()
    }
    if any(actual[address] != pair for address, pair in expected.items()):
        mismatches = {
            address: {"expected": expected[address], "actual": actual[address]}
            for address in expected
            if actual[address] != expected[address]
        }
        raise AssertionError(f"JNI registration instructions changed: {mismatches}")
    return {
        "sha256": digest,
        "jni_onload_export": {"offset": hex(JNI_ONLOAD), "count": len(jni_symbols)},
        "entry_offset": hex(JNI_ENTRY),
        "register_callsite": hex(REGISTER_CALLSITE),
        "register_method_table_slot": hex(REGISTER_METHOD_SLOT),
        "register_count": REGISTER_COUNT,
        "instruction_facts": instructions,
    }


def verify_sources(r4: Path, y2: Path, core: Path) -> dict:
    r4_text = r4.read_text(encoding="utf-8")
    y2_text = y2.read_text(encoding="utf-8")
    core_text = core.read_text(encoding="utf-8")
    required_r4 = (
        "onCallToAddSecurityFactor",
        "y2.a(50331649, 0, this.a.a, str",
        "(String[]) arrayList.toArray(new String[0])",
    )
    required_y2 = (
        "public static native Object a(int i, int i2, long j, String str, Object obj);",
    )
    required_core = (
        "public final java.util.Map frameSign(java.lang.String str, int i)",
        "java.lang.String[] strArr = (java.lang.String[]) ms.bd.c.y2.a(33554442, i, this.a, str, (java.lang.Object) null);",
        "if ((strArr instanceof java.lang.String[]) && strArr.length % 2 == 0)",
    )
    if any(fragment not in r4_text for fragment in required_r4):
        raise AssertionError("r4 signing callsite changed")
    if any(fragment not in y2_text for fragment in required_y2):
        raise AssertionError("y2 native declaration changed")
    if any(fragment not in core_text for fragment in required_core):
        raise AssertionError("core frameSign callsite changed")
    return {
        "r4": {"basename": r4.name, "sha256": sha256_file(r4)},
        "y2": {"basename": y2.name, "sha256": sha256_file(y2)},
        "core": {"basename": core.name, "sha256": sha256_file(core)},
        "signing_tag": hex(TAG_SIGN),
        "tag_callsite_verified": True,
        "frame_sign_tag": hex(TAG_FRAME_SIGN),
        "frame_sign_callsite_verified": True,
        "native_declaration_verified": True,
        "input_roles": {
            "tag": "int i",
            "type": "int i2",
            "handle": "long j",
            "url": "String str",
            "extra": "Object obj (String[] header pairs at signing callsite)",
            "frame_sign": {
                "tag": "0x200000a",
                "type": "int i",
                "handle": "long this.a",
                "url": "String str",
                "extra": "null Object",
                "return": "String[] key/value pairs converted to Map",
            },
        },
    }


def verify_capture(capture: Path) -> dict:
    text = capture.read_text(encoding="utf-8", errors="replace")
    markers = {
        "jni_onload_started": "[HookMain] calling JNI_OnLoad ..." in text,
        "jni_onload_completed": "[HookMain] JNI_OnLoad done" in text,
        "register_natives": bool(re.search(
            r"JNIEnv->RegisterNatives\(ms/bd/c/m, .*?, 1\).*0x26e514", text
        )),
        "registered_signature": f"RegisterNative(ms/bd/c/m, {SIGNATURE}," in text,
        "native_entry_lookup": bool(re.search(
            r"Find native function Java_ms_bd_c_m_a => .*0x26e684", text
        )),
        "signing_tag_observed": "[HookMain] MS.a tag=0x3000001" in text,
    }
    if not all(markers.values()):
        raise AssertionError(f"capture markers incomplete: {markers}")
    return {
        "basename": capture.name,
        "sha256": sha256_file(capture),
        "markers": markers,
        "capture_scope": "bounded unidbg registration/signing markers; payloads omitted",
    }


def verify(library: Path, r4: Path, y2: Path, core: Path, capture: Path) -> dict:
    elf = verify_elf(library)
    sources = verify_sources(r4, y2, core)
    dynamic = verify_capture(capture)
    return {
        "schema": "vm9-jni-registration-provenance-20261028-v2",
        "evidence_date": "2026-10-28",
        "evidence_label": "JNI_OnLoad RegisterNatives entry and Java tag provenance",
        "elf": elf,
        "java_sources": sources,
        "bounded_capture": dynamic,
        "provenance_conclusion": {
            "jni_onload_export_verified": True,
            "register_natives_site_verified": True,
            "registered_class_verified": True,
            "registered_signature_verified": True,
            "entry_offset_verified": True,
            "signing_tag_to_entry_verified": True,
            "frame_sign_tag_to_entry_verified": True,
            "frame_sign_dynamic_capture_verified": False,
            "actual_jni_provider_verified": False,
            "live_android_jvm_verified": False,
            "whole_request_native_python_differential_verified": False,
            "fresh_standalone_signer_verified": False,
            "online_header_acceptance_verified": False,
        },
        "interpretation": (
            "The pinned ELF exports JNI_OnLoad at +0x27b41c. Its registration path "
            "constructs one JNINativeMethod whose function pointer is image+0x26e684 "
            "and calls the JNIEnv function-table slot +0xb8 (RegisterNatives). The "
            "Java r4 callsite supplies tag 0x3000001 and the same URL/header-pair "
            "argument shape; core.c.frameSign supplies tag 0x200000a to the same "
            "native declaration and converts a String[] key/value result to a Map. "
            "The bounded unidbg capture independently reports class "
            "ms/bd/c/m, the exact native signature and the +0x26e684 entry. This closes "
            "JNI entry ownership and Java-to-entry tag provenance only; the frameSign "
            "tag has no dynamic marker in this capture. Providers, live JVM behavior, "
            "whole-request equivalence and signer acceptance remain open."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--r4-source", type=Path, required=True)
    parser.add_argument("--y2-source", type=Path, required=True)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--capture-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.library, args.r4_source, args.y2_source, args.core_source, args.capture_log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "entry_offset": report["elf"]["entry_offset"],
        "jni_onload": report["elf"]["jni_onload_export"]["offset"],
        "signing_tag": report["java_sources"]["signing_tag"],
        "frame_sign_tag": report["java_sources"]["frame_sign_tag"],
        "capture_markers": sum(report["bounded_capture"]["markers"].values()),
        "output": str(args.output),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
