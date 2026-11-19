"""Small conservative scan for accidental private trial material."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_RULES = {
    "device identifier": re.compile(r"device[_-]?id\s*[:=]\s*['\"]?[0-9]{10,}", re.I),
    "credential assignment": re.compile(r"(?:x-)?(?:ss-req-ticket|rticket|token|authorization)\s*[:=]", re.I),
    "session cookie assignment": re.compile(
        r"(?:session[_-]?id|sid[_-]?guard|uid[_-]?tt|passport[_-]?csrf[_-]?token)\s*[:=]",
        re.I,
    ),
    "bearer credential": re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}", re.I),
    "cookie header": re.compile(
        r"^\s*(?:set-cookie|cookie)\s*:\s*[^\r\n]*\b[A-Za-z][A-Za-z0-9_-]{1,}\s*=", re.I | re.M,
    ),
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


def in_scope(path: Path) -> bool:
    return path.parts[0] == "platforms" or path.suffix.lower() in {".json", ".md"}


def worktree_files() -> Iterator[tuple[Path, bytes | None]]:
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
    )
    for name in sorted(set(files.split(b"\0")) - {b""}):
        path = Path(os.fsdecode(name))
        if not in_scope(path):
            continue
        source = ROOT / path
        if source.is_symlink() or not source.is_file():
            continue
        try:
            contents = source.read_bytes()
        except OSError:
            contents = None
        yield path, contents


def staged_files() -> Iterator[tuple[Path, bytes | None]]:
    changes = subprocess.check_output([
        "git", "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
        "--no-color", "--diff-filter=AMT", "--ita-invisible-in-index", "--",
    ], cwd=ROOT)
    fields = changes.split(b"\0")[:-1]
    blobs = []
    for metadata, name in zip(fields[::2], fields[1::2], strict=True):
        _, mode, _, oid, _ = metadata.split()
        path = Path(os.fsdecode(name))
        if in_scope(path) and mode in {b"100644", b"100755"}:
            blobs.append((path, oid))
    if not blobs:
        return

    # Request objects by hash so worktree edits and filename quoting cannot affect the scan.
    with subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as git:
        assert git.stdin is not None and git.stdout is not None
        for path, oid in blobs:
            git.stdin.write(oid + b"\n")
            git.stdin.flush()
            header = git.stdout.readline().split()
            if len(header) != 3 or header[:2] != [oid, b"blob"]:
                yield path, None
                return
            size = int(header[2])
            contents = git.stdout.read(size)
            if len(contents) != size or git.stdout.read(1) != b"\n":
                yield path, None
                return
            yield path, contents


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="scan files changed in the Git index")
    args = parser.parse_args()
    files = staged_files() if args.staged else worktree_files()

    bad = []
    for path, contents in files:
        suffix = path.suffix.lower()
        findings = set()
        if contents is None:
            findings.add("unreadable file")
        else:
            try:
                text = contents.decode("utf-8-sig")
            except UnicodeDecodeError:
                if suffix in {".json", ".md"}:
                    findings.add("invalid UTF-8")
            else:
                scan_text(text, findings)
                if suffix == ".json":
                    scan_json(text, findings)

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
