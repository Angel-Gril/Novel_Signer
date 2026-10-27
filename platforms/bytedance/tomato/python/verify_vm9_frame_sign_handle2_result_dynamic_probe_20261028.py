"""Verify the fresh frameSign capture with the 0x4000002 handle.

The capture is an isolated unidbg Unicorn2 run with explicit Java/OS
callbacks.  This verifier keeps the returned String[] structural and
cryptographic observations only; it never publishes the URL or raw values and
does not patch or rerun the native target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import verify_vm9_signer_objects as oracle


EXPECTED_HEADERS = (
    "X-Argus",
    "X-Gorgon",
    "X-Helios",
    "X-Khronos",
    "X-Ladon",
    "X-Medusa",
)
EXPECTED_RESULT = (
    "frametype",
    "0",
    "lid",
    "1394812046",
    "signinfo",
    None,
    "signvalue",
    None,
    "signversion",
    "1.0",
)
HANDLE2 = "0x128a3000"
C_SOURCE_SHA256 = "fb143c74d7b82731af3b5833c93b06d5884e4aba20163dd54b330e09ee48c46a"
G_SOURCE_SHA256 = "0d7aca0a0646097813d804afffe7ca4df1feb30b71e8774063e817df2b40a4e1"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def digest(value: str) -> dict:
    return {"length": len(value), "sha256": sha256_bytes(value.encode("utf-8"))}


def require(text: str, marker: str) -> None:
    if marker not in text:
        raise AssertionError(f"missing marker: {marker}")


def _result_values(trace: str) -> list[str]:
    rows = re.findall(r"^\[HookMain\] FRAME_SIGN_RESULT\[(\d+)\]= (.*)$", trace, re.MULTILINE)
    if not rows:
        raise AssertionError("frameSign result entries are missing")
    indexed = {int(index): value for index, value in rows}
    if sorted(indexed) != list(range(10)):
        raise AssertionError(("frameSign result indices", sorted(indexed)))
    return [indexed[index] for index in range(10)]


def _check_java_source(path: Path, expected_hash: str, markers: tuple[str, ...], label: str) -> str:
    actual = sha256(path)
    if actual != expected_hash:
        raise AssertionError((f"{label} SHA-256", actual, expected_hash))
    source = path.read_text(encoding="utf-8")
    for marker in markers:
        require(source, marker)
    return actual


def verify(
    *,
    library: Path,
    hook_source: Path,
    run_log: Path,
    rounds: Path,
    c_source: Path,
    g_source: Path,
    output: Path,
) -> dict:
    library_hash = sha256(library)
    if library_hash != oracle.LIBRARY_SHA256:
        raise AssertionError(("pinned ELF hash", library_hash, oracle.LIBRARY_SHA256))

    c_hash = _check_java_source(
        c_source,
        C_SOURCE_SHA256,
        (
            "this.a = j;",
            "ms.bd.c.y2.a(33554442, i, this.a, str, (java.lang.Object) null)",
            "if ((strArr instanceof java.lang.String[]) && strArr.length % 2 == 0)",
            "hashMap.put(str2, str3);",
        ),
        "core.c.java",
    )
    g_hash = _check_java_source(
        g_source,
        G_SOURCE_SHA256,
        (
            "ms.bd.c.y2.a(67108866, 0, 0L, (java.lang.String) null, (java.lang.Object) null)",
            "return new com.bytedance.mobsec.metasec.core.c(bVar, ms.bd.c.m2.b.a, ((java.lang.Long) a2).longValue());",
        ),
        "core.g.java",
    )

    trace = run_log.read_text(encoding="utf-8", errors="replace")
    for marker in (
        "[HookMain] MS.a tag=0x4000002 handle=0x0 s=1967",
        "[HookMain] handle from 0x4000002 = 0x128a3000",
        "[HookMain] handle final = 0x1296a4a0",
        "[HookMain] FRAME_SIGN_PROBE_HANDLE=0x128a3000 source=handle2",
        "[HookMain] MS.a tag=0x200000a handle=0x128a3000",
        "[HookMain] FRAME_SIGN_RETURN_STATE pc=metasec+0x178cb4",
        "[HookMain] FRAME_SIGN_RESULT_LENGTH=10",
        "=== DONE ===",
    ):
        require(trace, marker)
    if "UC_ERR_WRITE_PROT" in trace or "write-protected memory" in trace:
        raise AssertionError("handle2 capture still contains a write-protected-memory failure")
    if "FRAME_SIGN_RESULT_TYPE=null" in trace:
        raise AssertionError("handle2 capture reported a null frameSign result")

    result = _result_values(trace)
    if (
        result[0:5] != list(EXPECTED_RESULT[0:5])
        or result[6] != "signvalue"
        or result[8:10] != ["signversion", "1.0"]
    ):
        raise AssertionError(("frameSign result shape", result))
    if len(result[5]) != 224 or not re.fullmatch(r"[0-9a-f]+", result[5]):
        raise AssertionError("signinfo shape")
    if len(result[7]) != 64 or not re.fullmatch(r"[0-9a-f]+", result[7]):
        raise AssertionError("signvalue shape")

    raw_rounds = json.loads(rounds.read_text(encoding="utf-8"))
    if not isinstance(raw_rounds, dict) or "0" not in raw_rounds:
        raise AssertionError("rounds JSON is empty")
    row = raw_rounds["0"]
    if not isinstance(row, dict):
        raise AssertionError("round 0 is not an object")
    required_round_keys = {"url", *EXPECTED_HEADERS}
    if not required_round_keys.issubset(row):
        raise AssertionError(("six-header setup keys", sorted(row)))
    for name in EXPECTED_HEADERS:
        if not isinstance(row[name], str) or not row[name]:
            raise AssertionError(("empty setup header", name))
    if not isinstance(row["url"], str) or not row["url"]:
        raise AssertionError("missing setup URL")
    if not isinstance(row["X-Khronos"], str) or not row["X-Khronos"].isdigit():
        raise AssertionError("invalid X-Khronos")

    source_hashes = {
        "library": library_hash,
        "hook_source": sha256(hook_source),
        "run_log": sha256(run_log),
        "rounds": sha256(rounds),
        "core_c_java": c_hash,
        "core_g_java": g_hash,
    }
    report = {
        "schema": "vm9-frame-sign-handle2-result-dynamic-probe-20261028-v1",
        "evidence_date": "2026-10-28",
        "sample_sha256": library_hash,
        "jni_entry": "+0x26e684",
        "signing_setup_tag": "0x3000001",
        "handle2_source_tag": "0x4000002",
        "frame_sign_tag": "0x200000a",
        "frame_sign_handle": HANDLE2,
        "callback1_signer_handle": "0x1296a4a0",
        "handle2_selected_for_frame_sign": True,
        "frame_sign_dynamic_capture_verified": True,
        "frame_sign_result_verified": True,
        "frame_sign_result_length": 10,
        "frame_sign_result_keys": ["frametype", "lid", "signinfo", "signvalue", "signversion"],
        "frame_sign_result_observations": {
            "frametype": {"length": 1, "sha256": sha256_bytes(result[1].encode("utf-8"))},
            "lid": {"length": len(result[3]), "sha256": sha256_bytes(result[3].encode("utf-8"))},
            "signinfo": digest(result[5]),
            "signvalue": digest(result[7]),
            "signversion": digest(result[9]),
        },
        "signing_setup_six_header_shape_verified": True,
        "signing_setup_header_names": list(EXPECTED_HEADERS),
        "signing_setup_header_observations": {
            name: digest(row[name]) for name in EXPECTED_HEADERS
        },
        "signing_setup_khronos_seconds": int(row["X-Khronos"]),
        "static_java_contract_verified": {
            "core_c_frame_sign_stores_handle_in_this_a": True,
            "core_c_frame_sign_tag": "0x200000a",
            "core_g_handle_source_tag": "0x4000002",
            "core_g_passes_handle_to_core_c": True,
        },
        "synthetic_jni_provider_used": True,
        "actual_jni_provider_verified": False,
        "live_android_jvm_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "source_hashes": source_hashes,
        "interpretation": (
            "The fresh isolated unidbg capture obtains handle2 from tag 0x4000002 and "
            "selects that handle for the 0x200000A frameSign call. Static core.g.java "
            "passes the same 0x4000002 result into core.c, and core.c stores it as "
            "this.a before calling the frameSign tag. With handle2, the native entry "
            "returns a non-null String[] of length 10 containing frametype/lid/signinfo/"
            "signvalue/signversion; only lengths and SHA-256 digests are published. "
            "The callback-1 signer handle is therefore the wrong frameSign input. "
            "Explicit Java/OS callbacks remain in the harness, so live Android-JVM, "
            "actual JNI provider, whole-request differential, standalone signer and "
            "online acceptance remain unverified."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("library", "hook-source", "run-log", "rounds", "c-source", "g-source", "output"):
        parser.add_argument(f"--{name}", dest=name.replace("-", "_"), type=Path, required=True)
    args = parser.parse_args()
    report = verify(**vars(args))
    print(json.dumps({
        "handle2_selected_for_frame_sign": report["handle2_selected_for_frame_sign"],
        "frame_sign_result_length": report["frame_sign_result_length"],
        "frame_sign_result_keys": report["frame_sign_result_keys"],
        "signinfo": report["frame_sign_result_observations"]["signinfo"],
        "signvalue": report["frame_sign_result_observations"]["signvalue"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
