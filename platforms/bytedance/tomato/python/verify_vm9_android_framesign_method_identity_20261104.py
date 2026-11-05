"""Validate the actual Android frameSign JNI method identity ledger."""
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
            "vm9-android-framesign-method-identity-20261104-v1",
            "evidence schema")
    require(report["frame_sign_hook_ready"] is True and
            report["frame_sign_enter_events"] == 1 and
            report["frame_sign_leave_ok_events"] == 1 and
            report["frame_sign_result_present"] is True,
            "frameSign invocation")
    require(report["jni_get_method_id_events_in_trigger_window"] == 15,
            "GetMethodID count")
    require(report["jni_call_object_method_v_events_in_trigger_window"] == 20,
            "CallObjectMethodV count")
    require(report["observed_java_methods"] == [{
        "name": "getBytes", "signature": "(Ljava/lang/String;)[B"
    }], "observed method identity")
    claims = report["claims"]
    require(claims["string_to_utf8_byte_array_method_identity_verified"] is True,
            "UTF-8 conversion identity")
    require(claims["provider_getter_method_identity_joined"] is False,
            "provider identity guard")
    require(claims["provider_return_bytes_joined_to_android_capture"] is False,
            "return byte guard")
    return {
        "schema": report["schema"],
        "frame_sign_triggered": True,
        "jni_get_method_id_events_in_trigger_window":
            report["jni_get_method_id_events_in_trigger_window"],
        "jni_call_object_method_v_events_in_trigger_window":
            report["jni_call_object_method_v_events_in_trigger_window"],
        "string_to_utf8_byte_array_method_identity_verified":
            claims["string_to_utf8_byte_array_method_identity_verified"],
        "provider_getter_method_identity_joined":
            claims["provider_getter_method_identity_joined"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence" /
                        "vm9_android_framesign_method_identity_20261104.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
