"""Verify the redacted static business-request/frameSign separation record."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED = {
    "r4.java": "b3334993de362c69f3d27e116f300121261732fa166c9c34c7a03739ab451b00",
    "s4.java": "805137ef6255765914ceff189bf859ab75c169efc5442b873dcf1bea9770152a",
    "CronetUrlRequest.java": "7f4cb81b3e8a6c470bca8c33192670ec2c57da0a33f93cb0ee9cdeb492e7e2b2",
    "CronetUrlRequestContext.java": "dee10f74172f56e60eabbd58cd5d92abd4f78c396f9605447a9fc4799697e553",
    "core.c.java": "fb143c74d7b82731af3b5833c93b06d5884e4aba20163dd54b330e09ee48c46a",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(record: Path, source_dir: Path, core_dir: Path) -> dict:
    data = json.loads(record.read_text(encoding="utf-8"))
    if data.get("schema") != "vm9-business-framesign-chain-20261028-v1":
        raise AssertionError("unexpected schema")
    chain = data.get("static_chain", {})
    if chain.get("request_native_tag") != "0x3000001":
        raise AssertionError("ordinary request tag is not 0x3000001")
    if chain.get("frame_sign_api", "").find("0x200000A") < 0:
        raise AssertionError("frameSign tag is not 0x200000A")
    if not data.get("separation_verified"):
        raise AssertionError("request/frameSign separation not marked verified")
    if data.get("business_frame_sign_call_observed"):
        raise AssertionError("record unexpectedly claims a business frameSign call")
    if data.get("runtime_probe", {}).get("raw_urls_or_headers_retained"):
        raise AssertionError("raw request material must not be retained")
    paths = {
        "r4.java": source_dir / "ms" / "bd" / "c" / "r4.java",
        "s4.java": source_dir / "ms" / "bd" / "c" / "s4.java",
        "CronetUrlRequest.java": source_dir / "com" / "ttnet" / "org" / "chromium" / "net" / "impl" / "CronetUrlRequest.java",
        "CronetUrlRequestContext.java": source_dir / "com" / "ttnet" / "org" / "chromium" / "net" / "impl" / "CronetUrlRequestContext.java",
        "core.c.java": core_dir / "com" / "bytedance" / "mobsec" / "metasec" / "core" / "c.java",
    }
    for name, expected in EXPECTED.items():
        actual = sha256(paths[name])
        if actual != expected:
            raise AssertionError((name, actual, expected))
        if data.get("source_hashes", {}).get(name) != expected:
            raise AssertionError(("record_hash", name))
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--core-dir", type=Path, required=True)
    args = parser.parse_args()
    data = verify(args.record, args.source_dir, args.core_dir)
    print(json.dumps({
        "schema": data["schema"],
        "separation_verified": data["separation_verified"],
        "business_frame_sign_call_observed": data["business_frame_sign_call_observed"],
        "request_native_tag": data["static_chain"]["request_native_tag"],
        "frame_sign_tag": "0x200000A",
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
