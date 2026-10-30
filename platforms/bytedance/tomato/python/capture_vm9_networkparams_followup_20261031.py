"""Reduce a redacted follow-up Gadget capture to path-separation evidence.

The input JSONL files are private runtime captures.  The output keeps only
event counts, digests, header names and lengths, thread ids, and hook names;
raw URLs, header values, tokens and response bodies are rejected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


HEADERS = {"X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"}
CRONET_EVENTS = {
    "cronetSecurityFactor",
    "cronetContextSecurityFactor",
    "cronetContextO0",
}


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_row(value: dict) -> dict:
    if set(value) != {"length", "sha256"}:
        raise ValueError("digest row has unexpected fields")
    if not isinstance(value["length"], int) or value["length"] < 0:
        raise ValueError("invalid digest length")
    if not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise ValueError("invalid digest")
    return {"length": value["length"], "sha256": value["sha256"]}


def context_summary(value: object) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("thread_id"), int):
        raise ValueError("invalid context")
    return {"thread_id": value["thread_id"]}


def load(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"empty capture: {path}")
    raw = json.dumps(rows, ensure_ascii=False)
    if re.search(r"https?://", raw):
        raise ValueError(f"raw URL in capture: {path}")
    return rows


def factor_summary(row: dict) -> dict:
    result = row.get("result")
    if not isinstance(result, dict) or result.get("count") != 6:
        raise ValueError("six-header result missing")
    headers = []
    for header in result.get("rows", []):
        if set(header) != {"key", "value"} or header["key"] not in HEADERS:
            raise ValueError("unexpected result header")
        headers.append({"key": header["key"], "value": digest_row(header["value"])})
    if {header["key"] for header in headers} != HEADERS:
        raise ValueError("incomplete result headers")
    inputs = []
    for header in row.get("input", {}).get("rows", []):
        if set(header) != {"key", "value"} or not isinstance(header["key"], str):
            raise ValueError("unexpected input header")
        inputs.append({"key": header["key"], "value": digest_row(header["value"])})
    return {
        "url": digest_row(row["url"]),
        "route": {
            "length": row["route"]["length"],
            "sha256": row["route"]["sha256"],
            "path": digest_row(row["route"]["path"]),
        },
        "input": {"count": len(inputs), "rows": inputs},
        "result": {"count": 6, "rows": sorted(headers, key=lambda item: item["key"])},
        "context": context_summary(row.get("context")),
    }


def summarize(path: Path, label: str, source_sha256: str) -> dict:
    rows = load(path)
    events = [row for row in rows if isinstance(row.get("event"), str)]
    factors = [factor_summary(row) for row in events if row.get("event") == "securityFactor"]
    cronet = [row for row in events if row.get("event") in CRONET_EVENTS]
    cert_returns = []
    for row in events:
        if row.get("event") != "certificate_read_return":
            continue
        result = row.get("result")
        if not isinstance(result, dict) or result.get("is_null") is not False:
            raise ValueError("invalid certificate return")
        cert_returns.append({
            "target": row.get("target"),
            "input": row.get("input"),
            "context": context_summary(row.get("context")),
            "result": {
                "is_null": False,
                **digest_row({"length": result["length"], "sha256": result["sha256"]}),
            },
        })
    return {
        "label": label,
        "capture_sha256": digest_file(path),
        "capture_bytes": path.stat().st_size,
        "source_sha256": source_sha256,
        "event_counts": dict(Counter(row.get("event") for row in events)),
        "hooked_targets": sorted(row["target"] for row in events if row.get("event") == "hooked"),
        "security_factor_calls": factors,
        "certificate_returns": cert_returns,
        "cronet_event_count": len(cronet),
        "terminal_event": events[-1] if events and events[-1].get("event") == "session_detached" else None,
        "raw_capture_retained_in_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="append", nargs=3, metavar=("LABEL", "JSONL", "SOURCE_SHA256"), required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--bridge-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    if not re.fullmatch(r"[0-9a-f]{64}", args.apk_sha256) or not re.fullmatch(r"[0-9a-f]{64}", args.bridge_sha256):
        parser.error("artifact hashes must be lowercase SHA-256")
    captures = [summarize(Path(path), label, source) for label, path, source in args.capture]
    record = {
        "schema": "vm9-networkparams-followup-20261031-v1",
        "artifact": {
            "package": "com.dragon.read",
            "version_code": 72532,
            "gadget_apk_sha256": args.apk_sha256,
            "bridge_sha256": args.bridge_sha256,
        },
        "capture_count": len(captures),
        "captures": captures,
        "security_factor_callback_observed": any(c["security_factor_calls"] for c in captures),
        "six_header_call_count": sum(len(c["security_factor_calls"]) for c in captures),
        "cronet_runtime_branch_observed": any(c["cronet_event_count"] for c in captures),
        "certificate_callback_observed": any(c["certificate_returns"] for c in captures),
        "same_request_certificate_correlation_verified": False,
        "whole_request_native_python_differential_verified": False,
        "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "target_app_modified": False,
        "interpretation": (
            "The static-overlay UI follow-up produced three ordinary NetworkParams/r4 six-header "
            "callbacks while Cronet addSecurityFactor/o0 remained uncalled in the exercised page. "
            "This confirms path separation for this observation window; it does not prove that the "
            "Cronet branch is absent from other features or that the headers were accepted online."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "summarized", "capture_count": len(captures),
                      "six_header_call_count": record["six_header_call_count"],
                      "cronet_runtime_branch_observed": record["cronet_runtime_branch_observed"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
