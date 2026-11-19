"""Small conservative scan for accidental private trial material."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_RULES = {
    "device identifier": re.compile(r"device[_-]?id\s*[:=]\s*['\"][0-9]{10,}", re.I),
    "credential assignment": re.compile(r"(?:x-)?(?:ss-req-ticket|rticket|token|authorization)\s*[:=]", re.I),
    "private key marker": re.compile(r"BEGIN (?:(?:[A-Z0-9]+ )*PRIVATE|RSA|EC|OPENSSH) KEY", re.I),
}
JSON_CREDENTIAL_FIELDS = {
    "authorization", "token", "access-token", "refresh-token", "cookie", "set-cookie",
    "sessionid", "session-id", "rticket", "ss-req-ticket", "x-ss-req-ticket",
}


def scan_text(text: str, findings: set[str]) -> None:
    for rule, pattern in TEXT_RULES.items():
        if rule not in findings and pattern.search(text):
            findings.add(rule)


def scan_json(text: str, findings: set[str]) -> None:
    def check_fields(pairs):
        # Inspect every member, including duplicate keys that a dict would discard.
        strings_and_children = []
        for key, value in pairs:
            field = key.casefold().replace("_", "-")
            if field in JSON_CREDENTIAL_FIELDS and (
                (isinstance(value, str) and value.strip()) or type(value) is int
            ):
                findings.add("credential field")
            if field in {"device-id", "deviceid"} and type(value) in (int, str):
                if re.fullmatch(r"[0-9]{10,}", str(value)):
                    findings.add("device identifier")
            strings_and_children.extend((key, value))
        return strings_and_children

    try:
        pending = [json.loads(text, object_pairs_hook=check_fields)]
    except (ValueError, RecursionError):
        findings.add("invalid JSON")
        return

    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            scan_text(value, findings)


def main() -> int:
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
    )
    bad = []
    for name in sorted(set(files.split(b"\0")) - {b""}):
        path = Path(os.fsdecode(name))
        suffix = path.suffix.lower()
        if path.parts[0] != "platforms" and suffix not in {".json", ".md"}:
            continue
        source = ROOT / path
        if source.is_symlink() or not source.is_file():
            continue

        findings = set()
        try:
            contents = source.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            if suffix in {".json", ".md"}:
                findings.add("invalid UTF-8")
        except OSError:
            findings.add("unreadable file")
        else:
            scan_text(contents, findings)
            if suffix == ".json":
                scan_json(contents, findings)

        if findings:
            bad.append(f"{path.as_posix()}: {', '.join(sorted(findings))}")

    if bad:
        print("public scan failed")
        print("\n".join(bad))
        return 1
    print("public scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
