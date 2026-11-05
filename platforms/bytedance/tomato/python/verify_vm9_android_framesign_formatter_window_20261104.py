"""Validate the bounded Android frameSign-to-formatter capture ledger."""
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
            "vm9-android-framesign-formatter-window-20261104-v1",
            "evidence schema")
    require(report["jni_getstringutfchars_hooked"] is True,
            "JNI getter hook")
    require(report["jni_release_string_utf_chars_hooked"] is True,
            "JNI release hook")
    require(report["formatter_hook"] == "libc.so!vsnprintf",
            "formatter hook")
    require(report["formatter_calls_observed"] == 83,
            "formatter call count")
    trigger = report["frame_sign_trigger"]
    require(report["frame_sign_hook_ready"] is True and
            report["frame_sign_overloads"] == 1,
            "frameSign hook")
    require(trigger["enter_business_seq"] == 1 and
            trigger["leave_ok"] is True and
            trigger["result_present"] is True,
            "frameSign trigger result")
    matches = report["formatter_matches"]
    require(matches["match_events"] == 12 and
            matches["matched_hits"] == 12,
            "formatter match count")
    require(matches["direct_pointer_matches"] == 9 and
            matches["released_fingerprint_matches"] == 3,
            "pointer/fingerprint split")
    require(matches["post_trigger_business_seq_1"] == 6 and
            matches["matches_while_java_method_active"] == 0,
            "temporal business window")
    claims = report["claims"]
    require(claims["android_getter_return_pointer_reached_vsnprintf_va_list"]
            is True, "Android va_list pointer relation")
    require(claims["frame_sign_synchronous_formatter_consumption_verified"]
            is False, "synchronous overclaim guard")
    require(claims["callback_url_or_map_identity_joined"] is False,
            "callback identity guard")
    require(claims["ordinary_cronet_six_head_chain_verified"] is False,
            "Cronet chain guard")
    return {
        "schema": report["schema"],
        "formatter_calls_observed": report["formatter_calls_observed"],
        "frame_sign_triggered": True,
        "formatter_match_events": matches["match_events"],
        "direct_pointer_matches": matches["direct_pointer_matches"],
        "released_fingerprint_matches": matches["released_fingerprint_matches"],
        "android_getter_return_pointer_reached_vsnprintf_va_list":
            claims["android_getter_return_pointer_reached_vsnprintf_va_list"],
        "frame_sign_synchronous_formatter_consumption_verified":
            claims["frame_sign_synchronous_formatter_consumption_verified"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence" /
                        "vm9_android_framesign_formatter_window_20261104.json")
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence), sort_keys=True))


if __name__ == "__main__":
    main()
