"""Validate the redacted Frida Gadget Java-bridge evidence boundary."""

from __future__ import annotations

import json
from pathlib import Path


EVIDENCE = Path(__file__).parents[1] / "evidence" / "vm9_gadget_java_bridge_20261030.json"


def main() -> int:
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert record["evidence_label"] == "patched_signed_gadget_runtime_capture"
    assert record["gadget"]["version"] == "17.24.3"
    assert record["gadget"]["on_load"] == "resume"
    assert record["host_bridge"]["java_available"] is True
    required = {
        "connected",
        "attached",
        "script_loaded",
        "bridge_initialized",
        "hooked MSManager.frameSign",
        "hooked r4.onCallToAddSecurityFactor",
        "hooked CronetUrlRequest.addSecurityFactor",
        "hooked CronetUrlRequestContext.addSecurityFactor",
        "hooked CronetUrlRequestContext.o0",
    }
    assert required <= set(record["observed_events"])
    assert record["manual_frame_sign_invocation"]["observed"] is True
    assert record["business_request_runtime_call_observed"] is False
    assert record["whole_request_native_python_differential_verified"] is False
    assert record["online_header_acceptance_verified"] is False
    print({"evidence": str(EVIDENCE), "status": "verified_boundary"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
