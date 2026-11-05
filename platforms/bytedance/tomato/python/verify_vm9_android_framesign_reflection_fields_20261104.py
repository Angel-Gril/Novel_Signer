"""Validate reflected Java field identities from an Android frameSign window."""
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
            "vm9-android-framesign-reflection-fields-20261104-v1",
            "evidence schema")
    frame = report["frame_sign"]
    require(frame["hook_ready"] is True and frame["enter_events"] == 1 and
            frame["leave_ok_events"] == 1 and frame["result_present"] is True,
            "frameSign result")
    jni = report["jni"]
    require(jni["get_method_id_events"] == 42 and
            jni["call_object_method_v_events"] == 53 and
            jni["get_object_field_events"] == 74 and
            jni["field_object_to_getstringutfchars_joins"] == 49,
            "JNI counts")
    require(jni["joined_field_ids"] == {
        "0x6f3dbfb8": 32,
        "0x6f3df358": 17,
    }, "field join distribution")
    require(jni["resolved_fields"] == [{
        "field_id": "0x6f3dbfb8",
        "name": "path",
        "declaring_class": "java.io.File",
        "named_get_object_field_events": 33,
    }], "resolved field")
    require(jni["observed_methods"] == [
        "checkPermission(Ljava/lang/String;Ljava/lang/String;)I",
        "getBytes(Ljava/lang/String;)[B",
    ], "observed method set")
    formatter = report["formatter"]
    require(formatter["vsnprintf_calls_observed"] == 109 and
            formatter["match_events"] == 18 and
            formatter["matched_getter_hits"] == 19 and
            formatter["business_sequence_1_match_events"] == 11 and
            formatter["field_join_getter_ids_also_matched_by_formatter"] == 0,
            "formatter counts")
    claims = report["claims"]
    require(claims["java_io_file_path_field_identity_verified"] is True and
            claims["file_path_field_to_jni_string_join_verified"] is True and
            claims["check_permission_method_observed"] is True,
            "reflection claims")
    require(claims["file_path_field_to_formatter_direct_dataflow_verified"] is False,
            "formatter overclaim guard")
    require(claims["provider_field_identity_joined"] is False,
            "provider identity guard")
    return {
        "schema": report["schema"],
        "java_io_file_path_field_identity_verified":
            claims["java_io_file_path_field_identity_verified"],
        "file_path_field_to_jni_string_join_verified":
            claims["file_path_field_to_jni_string_join_verified"],
        "file_path_field_to_formatter_direct_dataflow_verified":
            claims["file_path_field_to_formatter_direct_dataflow_verified"],
        "provider_field_identity_joined": claims["provider_field_identity_joined"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence" /
                        "vm9_android_framesign_reflection_fields_20261104.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
