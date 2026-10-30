"""Reduce a redacted Gadget JSONL capture to certificate/runtime evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"empty capture: {path}")
    if re.search(r"https?://", json.dumps(rows)):
        raise ValueError(f"raw URL in capture: {path}")
    return rows


def digest_summary(value: dict) -> dict:
    assert set(value) == {"length", "sha256"}
    assert isinstance(value["length"], int) and value["length"] >= 0
    assert re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
    return value


def stack_summary(context: dict) -> dict:
    assert isinstance(context, dict) and isinstance(context.get("thread_id"), int)
    stack = context.get("stack")
    assert isinstance(stack, list) and 1 <= len(stack) <= 24
    result = []
    for row in stack:
        assert set(row) == {"class", "method"}
        result.append(row)
    return {"thread_id": context["thread_id"], "stack": result}


def summarize_capture(path: Path, source_sha256: str) -> dict:
    rows = load(path)
    events = [row for row in rows if isinstance(row.get("event"), str)]
    hooked = sorted(row["target"] for row in events if row.get("event") == "hooked")
    cert_returns = []
    cert_enters = []
    for row in events:
        if row.get("event") == "certificate_read_enter":
            assert row["target"] in {"ms.bd.c.s2.k", "ms.bd.c.s2.j.certificate"}
            cert_enters.append({"target": row["target"], "input": row.get("input"),
                                "context": stack_summary(row["context"])})
        elif row.get("event") == "certificate_read_return":
            assert row["target"] in {"ms.bd.c.s2.k", "ms.bd.c.s2.j.certificate"}
            cert_returns.append({"target": row["target"], "input": row.get("input"),
                                 "context": stack_summary(row["context"]),
                                 "result": row["result"]})
    factors = []
    for row in events:
        if row.get("event") != "securityFactor":
            continue
        result = row.get("result")
        assert isinstance(result, dict) and result.get("count") == 6
        assert len(result.get("rows", [])) == 6
        for header in result["rows"]:
            assert set(header) == {"key", "value"} and isinstance(header["key"], str)
            digest_summary(header["value"])
        factors.append({"url": row["url"], "route": row["route"], "result": result,
                        "context": stack_summary(row["context"])})
    return {
        "capture_sha256": sha256(path), "capture_bytes": path.stat().st_size,
        "source_sha256": source_sha256, "event_counts": dict(Counter(row.get("event") for row in events)),
        "hooked_targets": hooked, "certificate_reads": {"enter": cert_enters, "return": cert_returns},
        "six_header_calls": factors,
        "terminal_event": events[-1] if events and events[-1].get("event") == "session_detached" else None,
        "raw_capture_retained_in_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="append", nargs=2, metavar=("JSONL", "SOURCE_SHA256"), required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--bridge-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    if not re.fullmatch(r"[0-9a-f]{64}", args.apk_sha256) or not re.fullmatch(r"[0-9a-f]{64}", args.bridge_sha256):
        parser.error("artifact hashes must be lowercase SHA-256")
    captures = [summarize_capture(Path(path), source) for path, source in args.capture]
    record = {
        "schema": "vm9-certificate-runtime-evidence-20261031-v1",
        "artifact": {"package": "com.dragon.read", "version_code": 72532,
                      "gadget_apk_sha256": args.apk_sha256, "bridge_sha256": args.bridge_sha256},
        "capture_count": len(captures), "captures": captures,
        "certificate_callback_observed": any(c["certificate_reads"]["return"] for c in captures),
        "six_header_callback_observed": any(c["six_header_calls"] for c in captures),
        "certificate_and_six_headers_same_call_correlated": False,
        "certificate_value_is_unique_cause_verified": False,
        "whole_request_native_python_differential_verified": False,
        "cronet_runtime_branch_observed": False,
        "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "target_app_modified": False,
        "interpretation": "The Gadget runtime entered ms.bd.c.s2.j and s2.k and returned byte arrays while a separate capture observed the six-header NetworkParams callback. Certificate reads and six-header calls are not correlated to one call/thread here; returned certificate lengths can vary across application state, so no unique-cause or online-acceptance claim is made.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "summarized", "capture_count": len(captures),
                      "certificate_callback_observed": record["certificate_callback_observed"],
                      "six_header_callback_observed": record["six_header_callback_observed"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
