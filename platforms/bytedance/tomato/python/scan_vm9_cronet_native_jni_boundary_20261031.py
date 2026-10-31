"""Scan the Cronet native JNI boundary without retaining native code.

The scanner records only ELF identity, section/string offsets, helper addresses,
JNI table offsets, and direct branch relationships.  It deliberately omits raw
instructions and native bytes from the generated evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_IMM, CS_OP_REG, Cs
from elftools.elf.elffile import ELFFile

ELF_MEMBER = "lib/arm64-v8a/libsscronet.so"
ELF_BASENAME = "libsscronet.so"

STRING_TARGETS = {
    "addSecurityFactor": b"addSecurityFactor\x00",
    "CronetUrlRequestContext":
        b"com/ttnet/org/chromium/net/impl/CronetUrlRequestContext\x00",
    "CronetUrlRequest":
        b"com/ttnet/org/chromium/net/impl/CronetUrlRequest\x00",
    "addSecurityFactor_signature":
        b"(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;\x00",
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def extract_elf(path: Path, member: str) -> bytes:
    if path.suffix.lower() == ".apk":
        with zipfile.ZipFile(path) as archive:
            return archive.read(member)
    return path.read_bytes()


def section_record(elf: ELFFile, name: str) -> dict[str, int]:
    section = elf.get_section_by_name(name)
    if section is None:
        raise ValueError(f"missing ELF section: {name}")
    return {
        "address": int(section["sh_addr"]),
        "file_offset": int(section["sh_offset"]),
        "size": int(section["sh_size"]),
    }


def find_unique(raw: bytes, needle: bytes) -> int:
    hits: list[int] = []
    start = 0
    while True:
        hit = raw.find(needle, start)
        if hit < 0:
            break
        hits.append(hit)
        start = hit + 1
    if len(hits) != 1:
        raise ValueError(f"expected one {needle!r}, found {len(hits)}")
    return hits[0]


def disassemble(elf: ELFFile, raw: bytes):
    text = elf.get_section_by_name(".text")
    if text is None:
        raise ValueError("missing .text")
    code = raw[text["sh_offset"]:text["sh_offset"] + text["sh_size"]]
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    return list(decoder.disasm(code, text["sh_addr"]))


def direct_calls(instructions, target: int) -> list[int]:
    hits: list[int] = []
    for insn in instructions:
        if insn.mnemonic != "bl" or not insn.operands:
            continue
        operand = insn.operands[0]
        if operand.type == CS_OP_IMM and operand.imm == target:
            hits.append(int(insn.address))
    return hits


def string_refs(instructions, target: int) -> list[dict[str, int]]:
    """Find the AArch64 ADRP+ADD materialisation of an absolute address."""
    refs: list[dict[str, int]] = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "adrp" or len(insn.operands) < 2:
            continue
        if insn.operands[0].type != CS_OP_REG or insn.operands[1].type != CS_OP_IMM:
            continue
        page = insn.operands[1].imm
        base_reg = insn.operands[0].reg
        for add in instructions[index + 1:index + 4]:
            if add.mnemonic != "add" or len(add.operands) < 3:
                continue
            dst, src, immediate = add.operands[:3]
            if (dst.type != CS_OP_REG or src.type != CS_OP_REG or
                    immediate.type != CS_OP_IMM):
                continue
            if dst.reg != src.reg or src.reg != base_reg:
                continue
            value = page + immediate.imm
            if value == target:
                refs.append({
                    "adrp": int(insn.address),
                    "add": int(add.address),
                })
                break
    return refs


def table_load(instructions, function_start: int, offset: int) -> int:
    """Return the first JNI table load with the expected byte offset."""
    for insn in instructions:
        if insn.address < function_start or insn.address >= function_start + 0x1000:
            continue
        if insn.mnemonic not in {"ldr", "ldur"} or len(insn.operands) < 2:
            continue
        memory = insn.operands[1]
        if memory.type == 3 and memory.mem.disp == offset:
            return int(insn.address)
    raise ValueError(f"no table load at {hex(function_start)} + {hex(offset)}")


def scan(raw: bytes) -> dict[str, object]:
    stream = __import__("io").BytesIO(raw)
    elf = ELFFile(stream)
    if elf["e_ident"]["EI_CLASS"] != "ELFCLASS64":
        raise ValueError("expected ELF64")
    if elf["e_machine"] != "EM_AARCH64":
        raise ValueError("expected AArch64 ELF")
    if elf["e_type"] != "ET_DYN":
        raise ValueError("expected ET_DYN")

    sections = {
        name: section_record(elf, name)
        for name in (".text", ".rodata")
    }
    strings: dict[str, dict[str, int]] = {}
    rodata = elf.get_section_by_name(".rodata")
    assert rodata is not None
    for label, needle in STRING_TARGETS.items():
        file_offset = find_unique(raw, needle)
        if not rodata["sh_offset"] <= file_offset < rodata["sh_offset"] + rodata["sh_size"]:
            raise ValueError(f"{label} is outside .rodata")
        strings[label] = {
            "file_offset": file_offset,
            "virtual_address": int(rodata["sh_addr"] + file_offset - rodata["sh_offset"]),
            "length_without_nul": len(needle) - 1,
        }

    instructions = disassemble(elf, raw)
    refs = {
        label: string_refs(instructions, item["virtual_address"])
        for label, item in strings.items()
    }
    if refs["addSecurityFactor"] != [
        {"adrp": 0x1F3444, "add": 0x1F3448},
        {"adrp": 0x202734, "add": 0x202738},
    ]:
        raise ValueError(f"unexpected addSecurityFactor refs: {refs['addSecurityFactor']}")

    expected_calls = {
        "context": {
            "class_resolver_call": 0x1F343C,
            "class_resolver_stub": 0x1F7160,
            "method_lookup_call": 0x1F346C,
            "method_lookup_stub": 0x1EFFFC,
            "method_invoke_call": 0x1F3484,
            "method_invoke_stub": 0x1F46AC,
        },
        "request": {
            "class_resolver_call": 0x20272C,
            "class_resolver_stub": 0x202870,
            "method_lookup_call": 0x20275C,
            "method_lookup_stub": 0x1EFFFC,
            "method_invoke_call": 0x202774,
            "method_invoke_stub": 0x1F46AC,
        },
    }
    for label, calls in expected_calls.items():
        for key in ("class_resolver_call", "method_lookup_call", "method_invoke_call"):
            target = calls[key.replace("_call", "_stub")]
            if calls[key] not in direct_calls(instructions, target):
                raise ValueError(f"missing {label} {key} -> {hex(target)}")

    dynsym = elf.get_section_by_name(".dynsym")
    dynamic_names = [symbol.name for symbol in dynsym.iter_symbols()] if dynsym else []
    jni_symbols = sorted(name for name in dynamic_names if "JNI" in name)

    jni_functions = {
        "JNI_OnLoad": {"address": 0x1EE624, "dynamic_symbol": "JNI_OnLoad" in dynamic_names},
        "JavaVM_GetEnv": {
            "helper": 0x323310,
            "table_offset": 0x30,
            "table_load": table_load(instructions, 0x323310, 0x30),
        },
        "JNI_GetMethodID": {
            "helper": 0x323134,
            "table_offset": 0x108,
            "table_load": table_load(instructions, 0x323134, 0x108),
        },
        "JNI_CallObjectMethodV": {
            "helper": 0x1F46AC,
            "table_offset": 0x118,
            "table_load": table_load(instructions, 0x1F46AC, 0x118),
        },
    }

    return {
        "schema": "vm9-cronet-native-jni-boundary-20261031-v1",
        "evidence_date": "2026-10-31",
        "package": "com.dragon.read",
        "version": "7.2.5.32/72532",
        "artifact": {
            "member": ELF_MEMBER,
            "sha256": digest(raw),
            "size": len(raw),
            "elf_class": 64,
            "machine": "AArch64",
            "type": "ET_DYN",
        },
        "sections": sections,
        "strings": strings,
        "string_refs": refs,
        "native_call_chains": {
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
        },
        "jni_functions": jni_functions,
        "dynamic_symbols": {
            "jni_names": jni_symbols,
            "static_java_native_symbol_count": sum(name.startswith("Java_") for name in dynamic_names),
            "register_natives_symbol_count": sum("RegisterNatives" in name for name in dynamic_names),
        },
        "raw_native_bytes_retained": False,
        "raw_instruction_text_retained": False,
        "interpretation": (
            "The AArch64 native library contains two indirect JNI call chains. Each chain obtains "
            "a Cronet implementation class, resolves the private addSecurityFactor method with "
            "JNI GetMethodID, and reaches the JNI CallObjectMethodV boundary using the recorded "
            "String/String[] signature. This establishes a native-to-private-Java dispatch "
            "boundary; it does not prove that either chain ran in the captured UI, that the "
            "returned headers were accepted online, or that a complete standalone signer exists."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.elf) == bool(args.apk):
        parser.error("provide exactly one of --elf or --apk")
    raw = extract_elf(args.elf or args.apk, ELF_MEMBER)
    record = scan(raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "schema": record["schema"],
        "sha256": record["artifact"]["sha256"],
        "native_call_chains": sorted(record["native_call_chains"]),
        "jni_functions": record["jni_functions"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
