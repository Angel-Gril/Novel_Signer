"""Verify the redacted Cronet native JNI-boundary evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_SCHEMA = "vm9-cronet-native-jni-boundary-20261031-v1"
EXPECTED_SHA256 = "ab0547460f1c06e5111b69826d2277f145aad4f79c7d2b7aea0356dcf25e49ac"
EXPECTED_SIZE = 6192768
EXPECTED_CHAINS = {
    "CronetUrlRequestContext.addSecurityFactor": {
        "class_string": "CronetUrlRequestContext",
        "class_resolver_call": 0x1F343C,
        "class_resolver_stub": 0x1F7160,
        "method_name": "addSecurityFactor",
        "method_signature": "(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;",
        "method_lookup_call": 0x1F346C,
        "method_lookup_stub": 0x1EFFFC,
        "method_invoke_call": 0x1F3484,
        "method_invoke_stub": 0x1F46AC,
    },
    "CronetUrlRequest.addSecurityFactor": {
        "class_string": "CronetUrlRequest",
        "class_resolver_call": 0x20272C,
        "class_resolver_stub": 0x202870,
        "method_name": "addSecurityFactor",
        "method_signature": "(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;",
        "method_lookup_call": 0x20275C,
        "method_lookup_stub": 0x1EFFFC,
        "method_invoke_call": 0x202774,
        "method_invoke_stub": 0x1F46AC,
    },
}


def verify(record_path: Path, elf_path: Path | None = None) -> dict[str, object]:
    data = json.loads(record_path.read_text(encoding="utf-8"))
    if data.get("schema") != EXPECTED_SCHEMA:
        raise AssertionError("unexpected schema")
    if data.get("package") != "com.dragon.read" or data.get("version") != "7.2.5.32/72532":
        raise AssertionError("unexpected target identity")
    artifact = data.get("artifact", {})
    if artifact.get("member") != "lib/arm64-v8a/libsscronet.so":
        raise AssertionError("unexpected ELF member")
    if artifact.get("sha256") != EXPECTED_SHA256 or artifact.get("size") != EXPECTED_SIZE:
        raise AssertionError("unexpected ELF identity")
    if artifact.get("elf_class") != 64 or artifact.get("machine") != "AArch64" or artifact.get("type") != "ET_DYN":
        raise AssertionError("unexpected ELF type")
    sections = data.get("sections", {})
    if sections.get(".text") != {"address": 0x1EC118, "file_offset": 0x1EC118, "size": 0x3D5220}:
        raise AssertionError("unexpected .text")
    if sections.get(".rodata") != {"address": 0x6EB50, "file_offset": 0x6EB50, "size": 0x7B3C0}:
        raise AssertionError("unexpected .rodata")
    strings = data.get("strings", {})
    expected_strings = {
        "addSecurityFactor": {"file_offset": 0x76D13, "virtual_address": 0x76D13, "length_without_nul": 17},
        "CronetUrlRequestContext": {"file_offset": 0xA61E8, "virtual_address": 0xA61E8, "length_without_nul": 55},
        "CronetUrlRequest": {"file_offset": 0xA628C, "virtual_address": 0xA628C, "length_without_nul": 48},
        "addSecurityFactor_signature": {"file_offset": 0x970F2, "virtual_address": 0x970F2, "length_without_nul": 58},
    }
    if strings != expected_strings:
        raise AssertionError(("unexpected strings", strings))
    expected_refs = {
        "addSecurityFactor": [
            {"adrp": 0x1F3444, "add": 0x1F3448},
            {"adrp": 0x202734, "add": 0x202738},
        ],
        "CronetUrlRequestContext": [{"adrp": 0x1F7164, "add": 0x1F7168}],
        "CronetUrlRequest": [{"adrp": 0x202874, "add": 0x202878}],
        "addSecurityFactor_signature": [
            {"adrp": 0x1F344C, "add": 0x1F3450},
            {"adrp": 0x20273C, "add": 0x202740},
        ],
    }
    if data.get("string_refs") != expected_refs:
        raise AssertionError("unexpected string references")
    if data.get("native_call_chains") != EXPECTED_CHAINS:
        raise AssertionError("native call chains changed")
    jni = data.get("jni_functions", {})
    expected_jni = {
        "JNI_OnLoad": {"address": 0x1EE624, "dynamic_symbol": True},
        "JavaVM_GetEnv": {"helper": 0x323310, "table_offset": 0x30, "table_load": 0x323358},
        "JNI_GetMethodID": {"helper": 0x323134, "table_offset": 0x108, "table_load": 0x32316C},
        "JNI_CallObjectMethodV": {"helper": 0x1F46AC, "table_offset": 0x118, "table_load": 0x1F4708},
    }
    if jni != expected_jni:
        raise AssertionError(("unexpected JNI boundaries", jni))
    if data.get("dynamic_symbols") != {
        "jni_names": ["JNI_OnLoad"],
        "static_java_native_symbol_count": 0,
        "register_natives_symbol_count": 0,
    }:
        raise AssertionError("unexpected dynamic symbols")
    if data.get("raw_native_bytes_retained") is not False or data.get("raw_instruction_text_retained") is not False:
        raise AssertionError("raw native material must not be retained")
    if elf_path is not None:
        actual = elf_path.read_bytes()
        if len(actual) != EXPECTED_SIZE or hashlib.sha256(actual).hexdigest() != EXPECTED_SHA256:
            raise AssertionError("ELF digest mismatch")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    args = parser.parse_args()
    data = verify(args.record, args.elf)
    print(json.dumps({
        "schema": data["schema"],
        "sha256": data["artifact"]["sha256"],
        "native_call_chains": sorted(data["native_call_chains"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
