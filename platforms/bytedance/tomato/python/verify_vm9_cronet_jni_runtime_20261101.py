"""Verify a redacted live Cronet JNI-table capture.

This verifier treats a capture with no ``jni_call_object_method_v`` event as a
bounded negative observation.  It does not upgrade that result to an
unreachable or disabled Cronet branch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


EXPECTED_SIGNATURE = "(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;"
ALLOWED_EVENTS = {
    "get_env_handler",
    "get_env_handler_missing",
    "art_missing",
    "jni_created_vms_missing",
    "jni_vm_error",
    "jni_vm_attached",
    "jni_table",
    "jni_table_error",
    "jni_hooks_installed",
    "jni_get_method_id",
    "jni_call_object_method_v",
    "probe_ready",
    "script_loaded",
    "session_detached",
    "frida_message",
}
POINTER = re.compile(r"^0x[0-9a-fA-F]+$")


def load(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise AssertionError("capture row must be an object")
        rows.append(row)
    if not rows:
        raise AssertionError("empty capture")
    raw = json.dumps(rows, ensure_ascii=False)
    for forbidden in ("http://", "https://", "X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"):
        if forbidden in raw:
            raise AssertionError(f"raw request material retained: {forbidden}")
    return rows


def verify(path: Path) -> dict[str, object]:
    rows = load(path)
    events = [row.get("event") for row in rows]
    if any(event not in ALLOWED_EVENTS for event in events):
        raise AssertionError(f"unexpected event: {sorted(set(events) - ALLOWED_EVENTS)}")
    if "probe_ready" not in events or "script_loaded" not in events:
        raise AssertionError("probe did not load")

    tables = [row for row in rows if row.get("event") == "jni_table"]
    if not tables:
        raise AssertionError("JNIEnv table was not observed")
    for table in tables:
        if table.get("table_offsets") != {"GetMethodID": 0x108, "CallObjectMethodV": 0x118}:
            raise AssertionError("unexpected JNI table offsets")
        for key in ("table", "get_method_id", "call_object_method_v"):
            if not isinstance(table.get(key), str) or not POINTER.fullmatch(table[key]):
                raise AssertionError(f"invalid pointer field: {key}")

    gets = [row for row in rows if row.get("event") == "jni_get_method_id"]
    calls = [row for row in rows if row.get("event") == "jni_call_object_method_v"]
    for row in gets + calls:
        if row.get("name") != "addSecurityFactor" or row.get("sig") != EXPECTED_SIGNATURE:
            raise AssertionError("unexpected Cronet JNI method")
        if not isinstance(row.get("method_id"), str) or not POINTER.fullmatch(row["method_id"]):
            raise AssertionError("invalid method id")
        if row.get("event") == "jni_call_object_method_v" and not isinstance(row.get("thread_id"), int):
            raise AssertionError("missing call thread id")

    counts = Counter(event for event in events if isinstance(event, str))
    return {
        "schema": "vm9-cronet-jni-runtime-20261101-v1",
        "event_counts": dict(sorted(counts.items())),
        "jni_table_observed": True,
        "cronet_runtime_branch_observed": bool(calls),
        "bounded_negative_if_zero": not bool(calls),
        "terminal_event": next((row for row in reversed(rows) if row.get("event") == "session_detached"), None),
    }


def verify_record(capture: Path, record_path: Path) -> dict[str, object]:
    summary = verify(capture)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("schema") != "vm9-cronet-jni-runtime-evidence-20261101-v1":
        raise AssertionError("unexpected evidence schema")
    if record.get("package") != "com.dragon.read" or record.get("version") != "7.2.5.32/72532":
        raise AssertionError("unexpected target identity")
    capture_meta = record.get("capture")
    if not isinstance(capture_meta, dict):
        raise AssertionError("missing capture metadata")
    if capture_meta.get("capture_sha256") != hashlib.sha256(capture.read_bytes()).hexdigest():
        raise AssertionError("capture digest mismatch")
    if capture_meta.get("event_counts") != summary["event_counts"]:
        raise AssertionError("event count mismatch")
    if record.get("jni_table_offsets") != {"GetMethodID": 264, "CallObjectMethodV": 280}:
        raise AssertionError("unexpected table offsets")
    if record.get("cronet_runtime_branch_observed") != summary["cronet_runtime_branch_observed"]:
        raise AssertionError("runtime verdict mismatch")
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    summary = verify(args.capture)
    if args.record is not None:
        verify_record(args.capture, args.record)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
