"""Verify retained passive business evidence without promoting online acceptance."""
from __future__ import annotations

import collections
import copy
import json
import re
from pathlib import Path


EVIDENCE = Path(__file__).parents[1] / "evidence/vm9_networkparams_runtime_20261031.json"
HEADERS = {"X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"}


def check_digest(value: dict) -> None:
    assert isinstance(value["length"], int) and value["length"] > 0
    assert re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
    assert set(value) <= {"length", "sha256", "path"}


def verify(record: dict) -> dict:
    assert record["schema"] == "vm9-networkparams-runtime-20261031-v1"
    assert record["evidence_label"] == "re_signed_gadget_passive_business_request"
    assert record["device"]["mem_total_kb"] >= 3 * 1024 * 1024
    assert record["official_control"]["actual_chapter_body_visually_observed"] is True
    assert record["business_security_factor_observed"] is True
    assert record["six_header_result_observed"] is True
    assert record["server_business_rejection_observed"] is True
    for name in (
        "exact_reason_for_business_code_110_identified", "cronet_runtime_branch_observed",
        "manual_frame_sign_invocation", "whole_request_native_python_differential_verified",
        "fresh_standalone_signer_verified", "online_header_acceptance_verified",
        "raw_urls_or_header_values_retained",
    ):
        assert record[name] is False, name
    events = record["events"]
    counts = collections.Counter(row.get("event") for row in events)
    assert not any(counts[name] for name in (
        "frameSign", "cronetSecurityFactor", "cronetContextO0", "cronetContextSecurityFactor",
        "hook_error", "install_error", "diagnostic_install_error", "frida_message",
    ))
    hooked = collections.Counter(row["target"] for row in events if row.get("event") == "hooked")
    assert len(hooked) == 9 and set(hooked.values()) == {1}
    signatures = [row for row in events if row.get("event") == "securityFactor"]
    assert signatures
    correlated = []
    for signature in signatures:
        check_digest(signature["url"])
        check_digest(signature["route"])
        check_digest(signature["route"]["path"])
        result = signature["result"]
        assert result["count"] == len(result["rows"]) == 6
        assert {row["key"] for row in result["rows"]} == HEADERS
        for summary in (signature["input"], result):
            assert summary["count"] == len(summary["rows"])
            for row in summary["rows"]:
                assert set(row) == {"key", "value"}
                check_digest(row["value"])
        stack = signature["context"]["stack"]
        assert len(stack) <= 24
        assert [row["class"] for row in stack[:3]] == [
            "ms.bd.c.r4",
            "com.bytedance.frameworks.baselib.network.http.NetworkParams",
            "com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor",
        ]
        matches = [row for row in events if row.get("event") == "response_deserialized"
                   and row["thread_id"] == signature["context"]["thread_id"]
                   and row["route"]["path"] == signature["route"]["path"]]
        for response in matches:
            assert events.index(response) > events.index(signature)
            assert response["http_status"] == record["observed_http_status"] == 200
            assert response["business_code"] == record["observed_business_code"] == 110
            assert response["transport_error_class"] is None
            assert response["response_class"] == "com.dragon.read.pbrpc.BookstoreTabResponse"
            assert response["route"]["sha256"] != signature["route"]["sha256"]
            correlated.append(response)
    assert correlated, "no response with matching path digest and thread id"
    errors = [row for row in events if row.get("event") == "error_code_exception_created"]
    assert errors
    for error in errors:
        assert error["code"] == 110 and error["error_kind"] == "ILLEGAL_ACCESS"
        assert error["stack"][0] == {
            "class": "com.dragon.read.util.NetReqUtil", "method": "assertRspDataOk"}
    assert any(row.get("event") == "version_warning_resource" and row["resource_id"] == 2131104020
               for row in events)
    for row in events:
        assert not re.search(r"https?://", json.dumps(row)), "raw URL in retained event"
    return {"status": "verified_boundary", "six_header_calls": len(signatures),
            "correlated_http_200_business_110": len(correlated),
            "cronet_observed": False, "online_acceptance_verified": False}


def main() -> int:
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = verify(record)
    for kind in ("missing_header", "mismatched_thread", "false_acceptance"):
        invalid = copy.deepcopy(record)
        if kind == "missing_header":
            next(row for row in invalid["events"] if row.get("event") == "securityFactor")[
                "result"]["rows"].pop()
        elif kind == "mismatched_thread":
            for row in invalid["events"]:
                if row.get("event") == "response_deserialized":
                    row["thread_id"] = -1
        else:
            invalid["online_header_acceptance_verified"] = True
        try:
            verify(invalid)
        except AssertionError:
            continue
        raise AssertionError(f"invalid evidence accepted: {kind}")
    result["negative_controls"] = 3
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
