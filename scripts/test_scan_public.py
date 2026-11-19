"""Exercise the public scan in a temporary checkout with synthetic data."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCANNER = Path(__file__).with_name("scan_public.py").resolve()
FAKE_KEY = "-----BEGIN PRIVATE KEY-----"


class PublicScanTests(unittest.TestCase):
    def run_scan(self, files, *, staged=None, args=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            scanner = root / "scripts" / SCANNER.name
            scanner.parent.mkdir()
            shutil.copyfile(SCANNER, scanner)

            def write_files(contents):
                for name, body in contents.items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body, encoding="utf-8")

            if staged is not None:
                write_files(staged)
                subprocess.run(["git", "add", "--", *staged], cwd=root, check=True)
            write_files(files)
            return subprocess.run(
                [sys.executable, str(scanner), *args], cwd=root, capture_output=True, text=True,
            )

    def test_reports_accidental_public_material_without_printing_it(self):
        for path, body, secret in (
            ("platforms/evidence.json", '{"token":"example-only-token"}', "example-only-token"),
            ("platforms/evidence.json", r'{"nested":["\u002d----BEGIN PRIVATE KEY-----"]}', FAKE_KEY),
            ("platforms/README.md", FAKE_KEY, FAKE_KEY),
            ("docs/report.md", FAKE_KEY, FAKE_KEY),
            ("platforms/control.txt", "authorization=example-only-token", "example-only-token"),
            ("platforms/control.txt", "sessionid=example-session-value", "example-session-value"),
            ("platforms/control.txt", "Cookie: sid_guard=example-session-value", "example-session-value"),
            ("platforms/control.txt", "Bearer example-token-value-1234", "example-token-value-1234"),
            ("platforms/broken.json", '{"token":"broken-fixture"', "broken-fixture"),
        ):
            with self.subTest(path=path, secret=secret):
                result = self.run_scan({path: body})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(path, result.stdout)
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_allows_redacted_metadata_and_skips_ignored_files(self):
        result = self.run_scan({
            ".gitignore": "local/\n",
            "local/private.json": '{"token":"example-only-token"}',
            "platforms/evidence.json": '{"token_sha256":"f00d", "cookie":null}',
            "README.md": "Public evidence records lengths and hashes.\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("public scan passed", result.stdout)

    def test_staged_scan_detects_content_removed_only_from_worktree(self):
        path = "docs/evidence space.json"
        result = self.run_scan(
            {path: '{"token_sha256":"f00d"}'},
            staged={path: '{"token":"example-only-staged"}'}, args=("--staged",),
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"{path}: credential field", result.stdout)
        self.assertNotIn("example-only-staged", result.stdout + result.stderr)

    def test_staged_scan_ignores_material_that_is_not_staged(self):
        path = "platforms/README.md"
        result = self.run_scan(
            {path: FAKE_KEY, "docs/untracked.md": FAKE_KEY},
            staged={path: "Public evidence.\n"}, args=("--staged",),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("public scan passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
