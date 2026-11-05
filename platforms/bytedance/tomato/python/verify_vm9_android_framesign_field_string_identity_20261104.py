"""Validate anonymous Android field-object to JNI string handle joins."""
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
            "vm9-android-framesign-field-string-identity-20261104-v1",
            "evidence schema")
    require(report["frame_sign_hook_ready"] is True and
            report["frame_sign_enter_events"] == 1 and
            report["frame_sign_leave_ok_events"] == 1 and
            report["frame_sign_result_present"] is True,
            "frameSign invocation")
    require(report["get_object_field_events"] == 180,
            "GetObjectField count")
    require(report["field_object_to_getstringutfchars_joins"] == 18,
            "field/string handle joins")
    require(report["joined_field_ids"] == {
        "0x6fe15bb4": 17,
        "0x6f3dbfb8": 1,
    }, "joined field ID distribution")
    claims = report["claims"]
    require(claims["get_object_field_return_handle_equals_getstringutfchars_jstring"]
            is True, "field handle identity")
    require(claims["field_id_to_java_field_name_resolved"] is False,
            "field name guard")
    require(claims["provider_field_identity_joined"] is False,
            "provider field guard")
    require(claims["formatter_consumption_joined_in_this_capture"] is False,
            "formatter join guard")
    return {
        "schema": report["schema"],
        "get_object_field_events": report["get_object_field_events"],
        "field_object_to_getstringutfchars_joins":
            report["field_object_to_getstringutfchars_joins"],
        "get_object_field_return_handle_equals_getstringutfchars_jstring":
            claims["get_object_field_return_handle_equals_getstringutfchars_jstring"],
        "provider_field_identity_joined": claims["provider_field_identity_joined"],
        "formatter_consumption_joined_in_this_capture":
            claims["formatter_consumption_joined_in_this_capture"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence" /
                        "vm9_android_framesign_field_string_identity_20261104.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
