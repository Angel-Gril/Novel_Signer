"""Read certificate digests from Android package manager without root or Frida."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE = Path(__file__).with_name("android") / "Vm9PackageIdentity.java"


def run(command: list[str], timeout: int = 45) -> str:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                           f"command failed with status {result.returncode}")
    return result.stdout


def capture(args: argparse.Namespace) -> dict:
    adb = [args.adb, "-s", args.serial]
    with tempfile.TemporaryDirectory(prefix="vm9-identity-") as temporary:
        work = Path(temporary)
        run(["javac", "-source", "8", "-target", "8", "-cp", str(args.android_jar),
             "-d", str(work), str(SOURCE)])
        run([str(args.d8), "--min-api", "26", "--lib", str(args.android_jar),
             "--output", str(work), str(work / "Vm9PackageIdentity.class")])
        device_file = f"/data/local/tmp/{work.name}.dex"
        try:
            run(adb + ["push", str(work / "classes.dex"), device_file])
            output = run(adb + ["shell", f"CLASSPATH={device_file}", "app_process",
                                "/system/bin", "Vm9PackageIdentity", args.package])
            rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            if len(rows) != 1 or rows[0].get("event") != "package_identity":
                raise RuntimeError("device did not return one package identity record")
            result = rows[0]
            if result["package"] != args.package:
                raise RuntimeError("device returned another package")
            result["probe_source_sha256"] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
            return result
        finally:
            run(adb + ["shell", "rm", "-f", "--", device_file])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", default="com.dragon.read")
    parser.add_argument("--android-jar", type=Path, required=True)
    parser.add_argument("--d8", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new JSON evidence file; existing files are refused")
    args = parser.parse_args()
    if not re.fullmatch(r"(?:android|[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+)", args.package):
        parser.error("--package must be one explicit Android package name")
    if args.output is not None and args.output.exists():
        parser.error("--output already exists")
    try:
        result = capture(args)
        serialized = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            with args.output.open("x", encoding="utf-8") as target:
                target.write(serialized)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"event": "package_identity_capture_error",
                          "error_class": type(error).__name__, "detail": str(error)},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
