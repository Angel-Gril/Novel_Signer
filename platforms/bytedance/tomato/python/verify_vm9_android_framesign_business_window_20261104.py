"""Validate the bounded frameSign business-window ledger."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_record(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    require(report["schema"] ==
            "vm9-android-framesign-business-window-20261104-v1",
            "evidence schema")
    frame = report["frame_sign"]
    require(frame["hook_ready"] is True and frame["enter_events"] == 1 and
            frame["leave_ok_events"] == 1 and frame["result_present"] is True,
            "frameSign result")
    methods = report["jni_method_identity"]
    require(methods["get_method_id_events"] == 35 and
            methods["call_object_method_v_events"] == 70 and
            methods["getbytes_observed"] is True,
            "JNI method identity")
    fields = report["field_string_identity"]
    require(fields["get_object_field_events"] == 87 and
            fields["field_object_to_getstringutfchars_joins"] == 12 and
            fields["joined_field_ids"] == {"0x6f3dbfb8": 12},
            "field/string identity")
    formatter = report["formatter"]
    require(formatter["vsnprintf_calls_observed"] == 385 and
            formatter["match_events"] == 19 and
            formatter["matched_hits"] == 20 and
            formatter["business_sequence_1_match_events"] == 16 and
            formatter["field_join_getter_ids_also_matched_by_formatter"] == 0,
            "formatter ledger")
    claims = report["claims"]
    require(claims["business_window_formatter_matches_observed"] is True and
            claims["business_window_field_to_jni_string_joins_observed"] is True,
            "business window observations")
    require(claims["field_string_to_formatter_direct_dataflow_verified"] is False,
            "dataflow overclaim guard")
    require(claims["provider_field_identity_joined"] is False,
            "provider field guard")
    return {
        "schema": report["schema"],
        "frame_sign_triggered": claims["frame_sign_triggered"],
        "business_window_formatter_matches_observed":
            claims["business_window_formatter_matches_observed"],
        "business_window_field_to_jni_string_joins_observed":
            claims["business_window_field_to_jni_string_joins_observed"],
        "field_string_to_formatter_direct_dataflow_verified":
            claims["field_string_to_formatter_direct_dataflow_verified"],
        "provider_field_identity_joined": claims["provider_field_identity_joined"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence" /
                        "vm9_android_framesign_business_window_20261104.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
