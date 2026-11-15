"""Offline release/installer regressions; tool doubles do not prove signatures."""
import hashlib
import io
import os
from pathlib import Path

import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseTests(unittest.TestCase):
    def test_lock_schema_describes_package_and_decision_records(self):
        import json
        schema = json.loads((ROOT / "schemas/lock.schema.json").read_text())
        self.assertNotIn("placeholder", schema["title"])
        package = schema["properties"]["package"]["items"]
        self.assertIn("package_files_sha256", package["required"])
        self.assertIn("license_files", package["required"])
        self.assertEqual(package["properties"]["file_count"]["type"], "integer")
        decision = schema["properties"]["decision"]["items"]
        self.assertEqual(set(decision["required"]), {"name", "version", "strategy", "dependents"})

    def test_release_cannot_bypass_the_ci_quality_gate(self):
        text = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("    uses: ./.github/workflows/ci.yml", text)
        self.assertIn("    needs: quality", text)
        self.assertIn("  workflow_call:", (ROOT / ".github/workflows/ci.yml").read_text())

    def test_slsa_is_a_reusable_job_not_an_action(self):
        text = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotIn("      - uses: slsa-framework/", text)
        self.assertIn("    runs-on: ${{ matrix.os }}", text)
        self.assertIn("    uses: slsa-framework/slsa-github-generator/", text)

    def test_release_archives_ignore_local_mtimes_and_permissions(self):
        with tempfile.TemporaryDirectory(prefix="own-package-test-") as tmp:
            root = Path(tmp)
            for name in ("own", "own-verify"):
                (root / name).write_bytes(b"binary fixture: " + name.encode())
            out = root / "release.tar.gz"
            command = ["python3", str(ROOT / "scripts/package-release.py"),
                       "--binary-dir", str(root), "--output", str(out), "--epoch", "100"]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            content = out.read_bytes()
            for name in ("own", "own-verify"):
                os.utime(root / name, (200, 200))
                (root / name).chmod(0o600)
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(content, out.read_bytes())
            self.assertEqual((root / "release.tar.gz.sha256").read_text(),
                             f"{hashlib.sha256(content).hexdigest()}  release.tar.gz\n")
            with tarfile.open(out) as archive:
                self.assertEqual(archive.getnames(), ["own", "own-verify"])
                for entry in archive:
                    self.assertEqual((entry.mtime, entry.uid, entry.gid, entry.mode), (100, 0, 0, 0o755))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="own-installer-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "tools"
        self.bin.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.dest = self.root / "installed"
        self.calls = self.root / "calls"
        self.asset = "own-v0.1.0-linux-amd64.tar.gz"
        self.payload = {"own": b"#!/bin/sh\necho own\n", "own-verify": b"#!/bin/sh\necho verify\n"}
        self.make_archive()
        (self.assets / (self.asset + ".bundle")).write_text("test double, not a signature")
        (self.assets / "multiple.intoto.jsonl").write_text("test double, not provenance")
        self.tool("uname", 'if [ "$1" = "-m" ]; then echo x86_64; else echo Linux; fi')
        self.tool("curl", 'for last; do :; done\nurl=""\nfor arg; do case "$arg" in https:*) url="$arg";; esac; done\ncp "$TEST_ASSETS/${url##*/}" "$last"')
        self.tool("cosign", 'printf "cosign %s\\n" "$*" >> "$TEST_CALLS"')
        self.tool("slsa-verifier", 'printf "slsa %s\\n" "$*" >> "$TEST_CALLS"\nexit "${TEST_SLSA_EXIT:-0}"')
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", OWN_VERSION="v0.1.0",
                        OWN_BIN_DIR=str(self.dest), TEST_ASSETS=str(self.assets), TEST_CALLS=str(self.calls))

    def tool(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        p.chmod(0o755)

    def make_archive(self):
        with tarfile.open(self.assets / self.asset, "w:gz") as archive:
            for name, data in self.payload.items():
                entry = tarfile.TarInfo(name)
                entry.mode = 0o755
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        digest = hashlib.sha256((self.assets / self.asset).read_bytes()).hexdigest()
        (self.assets / (self.asset + ".sha256")).write_text(f"{digest}  {self.asset}\n")

    def run_installer(self, **env):
        return subprocess.run(["bash", str(ROOT / "scripts/install-own.sh")],
                              env=dict(self.env, **env), capture_output=True, text=True, timeout=10)

    def test_provenance_binds_the_tarball_repository_and_exact_tag(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text()
        self.assertIn(f"slsa verify-artifact {self.asset}", calls)
        self.assertIn("--source-uri github.com/YourFriendPollux/own", calls)
        self.assertIn("--source-tag v0.1.0", calls)
        self.assertIn("--provenance-path multiple.intoto.jsonl", calls)
        self.assertIn("--certificate-identity https://github.com/YourFriendPollux/own/.github/workflows/release.yml@refs/tags/v0.1.0", calls)
        for name, data in self.payload.items():
            self.assertEqual((self.dest / name).read_bytes(), data)

    def test_failed_provenance_never_replaces_existing_binaries(self):
        self.dest.mkdir()
        for name in self.payload:
            (self.dest / name).write_bytes(b"original")
        result = self.run_installer(TEST_SLSA_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        for name in self.payload:
            self.assertEqual((self.dest / name).read_bytes(), b"original")

    def test_missing_second_binary_never_replaces_first(self):
        self.payload.pop("own-verify")
        self.make_archive()
        self.dest.mkdir()
        (self.dest / "own").write_bytes(b"original")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.dest / "own").read_bytes(), b"original")

    def test_checksum_mismatch_never_reaches_verifiers(self):
        (self.assets / (self.asset + ".sha256")).write_text(f"{'0' * 64}  {self.asset}\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.dest.exists())

    def test_untrusted_verifier_is_not_bootstrapped_from_same_download(self):
        (self.bin / "cosign").unlink()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted cosign", result.stderr)
        self.assertNotIn("installing pinned cosign", result.stdout)

    def test_invalid_release_identifiers_are_refused_before_download(self):
        for env in ({"OWN_VERSION": "v0.1.0/../../bad"}, {"OWN_REPO": "org/repo/extra"},
                    {"OWN_PROVENANCE_ASSET": "../outside"}):
            with self.subTest(env=env):
                result = self.run_installer(**env)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()
