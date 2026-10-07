"""Export sanitized observations from a private offline bridge run.

JNI array return sites are not signer entries. VM_ENTRY prints only the first
hit of each bytecode; the footer counts repetitions but carries no caller data.
This exporter does not execute Java, sign a request, or contact a server.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

LIBRARY_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
SYNTHETIC_URL = "https://example.invalid/api/novel/search?aid=1967&query=synthetic&offset=0"


def export_reference(*, log_text, headers, status, library_hash, bridge_hash):
    if library_hash != LIBRARY_SHA256:
        raise ValueError("reference library does not match the analyzed sample")
    input_hash = hashlib.sha256(SYNTHETIC_URL.encode()).hexdigest()
    if headers.get("url") != SYNTHETIC_URL or status.get("input_sha256") != input_hash:
        raise ValueError("only the designated synthetic input may be exported")
    if status.get("exit_code") != 0 or status.get("failure") is not None:
        raise ValueError("bridge run did not finish successfully")
    medusa = headers["X-Medusa"]
    raw = base64.b64decode(medusa, validate=True)
    vm_observations, builder_observations = [], []
    hit_counts = {}
    round_number = None
    footer = False
    for line in log_text.splitlines():
        match = re.search(r"=== SIGN ROUND (\d+) ===", line)
        if match:
            round_number = int(match[1])
        match = re.search(r"VM_ENTRY bytecode=\+0x([0-9a-f]+).*callerLR=\+0x([0-9a-f]+)", line)
        if match:
            vm_observations.append(dict(
                bytecode_offset=hex(int(match[1], 16)),
                caller_return_offset=hex(int(match[2], 16)),
                sign_round=round_number,
                phase="initialization" if round_number is None else "sign_round"))
        match = re.search(r"\b(ARRBUILD2?) @\+0x([0-9a-f]+).*lr=\+0x([0-9a-f]+)", line)
        if match:
            site = int(match[2], 16)
            if site not in (0x27152C, 0x271548):
                raise ValueError("unexpected current JNI array return site")
            observation = dict(marker=match[1], observation_offset=hex(site),
                link_register_offset=hex(int(match[3], 16)), sign_round=round_number,
                classification="return_after_SetObjectArrayElement")
            w2 = re.search(r"\bw2=(\d+)\b", line)
            if w2:
                observation["observed_w2"] = int(w2[1])
            builder_observations.append(observation)
        if line == "=== VM bytecode hit summary ===":
            footer = True
            continue
        if footer:
            match = re.fullmatch(r"\s+\+0x([0-9a-f]+) : (\d+)", line)
            if match:
                hit_counts[hex(int(match[1], 16))] = int(match[2])
            else:
                footer = False
    if len(vm_observations) != len({row["bytecode_offset"] for row in vm_observations}):
        raise ValueError("VM_ENTRY records do not follow first-hit logging semantics")
    if set(hit_counts) != {row["bytecode_offset"] for row in vm_observations}:
        raise ValueError("VM footer and first-hit observations disagree")
    if not builder_observations or not vm_observations:
        raise ValueError("reference contains no usable observations")
    sign_entries = [row for row in vm_observations if row["phase"] == "sign_round"]
    if not sign_entries or sign_entries[0]["bytecode_offset"] != "0xf7720":
        raise ValueError("unexpected first newly observed request VM")
    return dict(schema="current-request-entry-reference-v2", evidence_date="2026-10-07",
        sample_sha256=library_hash, bridge_class_sha256=bridge_hash,
        input_profile="synthetic example.invalid URL; aid1967/query synthetic/offset0",
        input_sha256=input_hash, bridge_used=True, jvm_used=True,
        server_request_performed=False, medusa_base64_characters=len(medusa),
        medusa_raw_bytes=len(raw), medusa_value_sha256=hashlib.sha256(medusa.encode()).hexdigest(),
        jni_array_observations=builder_observations,
        jni_array_observation_counts=dict(Counter(row["observation_offset"] for row in builder_observations)),
        vm_first_hit_observations=vm_observations, vm_hit_counts=hit_counts,
        observed_total_vm_hits=sum(hit_counts.values()),
        vm_logging_semantics="first hit per distinct bytecode; footer counts all instrumented hits",
        first_new_vm_in_sign_round=dict(bytecode_offset="0xf7720", caller_entry_offset="0x2830c4",
            caller_vm_call_offset="0x283130", caller_return_offset="0x283134"),
        independent_python_signature_verified=False, current_online_header_matrix_verified=False,
        limitations=[
            "This is an offline JVM-backed bridge reference, not a standalone Python signer.",
            "VM_ENTRY does not print repeated hits; absence in a round does not prove non-execution.",
            "The first newly observed request VM is not proven to be the only request entry.",
            "ARRBUILD hooks observe post-call JNI array returns, not signature generation entries.",
            "Only offsets/counts/hashes/lengths are exported; raw memory, logs and header values remain private."])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--bridge-class", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = export_reference(
        log_text=args.stdout.read_text(encoding="utf-8", errors="replace"),
        headers=json.loads(args.headers.read_text(encoding="utf-8")),
        status=json.loads(args.status.read_text(encoding="utf-8")),
        library_hash=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        bridge_hash=hashlib.sha256(args.bridge_class.read_bytes()).hexdigest())
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("offline reference", len(report["jni_array_observations"]), "JNI array returns;",
          len(report["vm_first_hit_observations"]), "distinct VMs;",
          report["observed_total_vm_hits"], "instrumented hits; standalone signing remains open")


if __name__ == "__main__":
    main()
