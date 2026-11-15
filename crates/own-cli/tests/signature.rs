//! External verifier mocks exercise CLI arguments/errors, not cryptography.
#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NONCE: AtomicU64 = AtomicU64::new(0);
const IDENTITY: &str =
    "^https://github.com/example/own/.github/workflows/release.yml@refs/tags/v.*$";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

struct Fixture {
    root: PathBuf,
    tools: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "own-signature-{}-{} with spaces",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let tools = root.join("trusted-tools");
        fs::create_dir_all(&tools).unwrap();
        for name in [
            "release.tar.gz",
            "release.bundle",
            "multiple.intoto.jsonl",
            "trusted-root.json",
        ] {
            fs::write(
                root.join(name),
                b"mock verification input, not signed evidence",
            )
            .unwrap();
        }
        let fixture = Self { root, tools };
        for (name, variable) in [("cosign", "COSIGN"), ("slsa-verifier", "SLSA")] {
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' '{name}' >> \"$CALL_LOG\"\nprintf '%s\\0' \"$@\" >> \"${variable}_LOG\"\nprintf '\\0' >> \"${variable}_LOG\"\nif [ \"$1\" = '--version' ]; then exit 0; fi\nprintf '%s\\n' \"${{{variable}_ERROR:-}}\" >&2\nexit \"${{{variable}_EXIT:-0}}\"\n"
            );
            fs::write(fixture.tools.join(name), script).unwrap();
            fs::set_permissions(fixture.tools.join(name), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        fixture
    }

    fn args(&self, provenance: bool) -> Vec<OsString> {
        let mut args: Vec<OsString> = [
            "verify-signature",
            "release.tar.gz",
            "--bundle",
            "release.bundle",
            "--identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if provenance {
            args.extend(["--provenance", "multiple.intoto.jsonl"].map(OsString::from));
        }
        args
    }

    fn run(&self, args: &[OsString], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_own"))
            .args(args)
            .current_dir(&self.root)
            .env("PATH", &self.tools)
            .env("CALL_LOG", self.root.join("calls.log"))
            .env("COSIGN_LOG", self.root.join("cosign.log"))
            .env("SLSA_LOG", self.root.join("slsa.log"))
            .env_remove("COSIGN_EXIT")
            .env_remove("SLSA_EXIT")
            .env_remove("COSIGN_ERROR")
            .env_remove("SLSA_ERROR")
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    fn provenance_args(&self) -> Vec<OsString> {
        let mut args = self.args(true);
        args.extend(
            [
                "--source-uri",
                "github.com/example/own",
                "--source-tag",
                "v0.1.0",
                "--trusted-root",
                "trusted-root.json",
            ]
            .map(OsString::from),
        );
        args
    }

    fn calls(&self) -> Vec<String> {
        match fs::read_to_string(self.root.join("calls.log")) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("cannot read calls: {error}"),
        }
    }

    fn verifier_args(&self, name: &str) -> Vec<Vec<OsString>> {
        let bytes = fs::read(self.root.join(format!("{name}.log"))).unwrap();
        let mut invocations = Vec::new();
        let mut invocation = Vec::new();
        for arg in bytes.split(|byte| *byte == 0) {
            if arg.is_empty() {
                if !invocation.is_empty() {
                    invocations.push(std::mem::take(&mut invocation));
                }
            } else {
                invocation.push(OsString::from_vec(arg.to_vec()));
            }
        }
        invocations
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn missing_verifiers_are_refused_before_any_subprocess() {
    for name in ["slsa-verifier", "cosign"] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.tools.join(name)).unwrap();
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("IO_ERROR") && stderr.contains(name),
            "{out:?}"
        );
        assert!(
            fixture.calls().is_empty(),
            "verifier ran before discovering missing {name}"
        );
    }
}

#[test]
fn nonexecutable_verifiers_are_refused_before_any_subprocess() {
    for name in ["slsa-verifier", "cosign"] {
        let fixture = Fixture::new();
        fs::set_permissions(fixture.tools.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(name),
            "{out:?}"
        );
        assert!(
            fixture.calls().is_empty(),
            "verifier ran before discovering nonexecutable {name}"
        );
    }
}

#[test]
fn signature_rejection_stops_slsa_and_preserves_failure_detail() {
    let fixture = Fixture::new();
    let out = fixture.run(
        &fixture.provenance_args(),
        &[
            ("COSIGN_EXIT", "41"),
            ("COSIGN_ERROR", "mock: signature does not match artifact"),
        ],
    );
    assert_exit(&out, 1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PROVENANCE_INVALID: signature"), "{out:?}");
    assert!(
        stderr.contains("41") && stderr.contains("mock: signature does not match artifact"),
        "{out:?}"
    );
    assert_eq!(fixture.calls(), ["cosign"]);
    assert!(
        out.stdout.is_empty(),
        "no success after signature rejection: {out:?}"
    );
}

#[test]
fn slsa_rejections_propagate_without_any_success_claim() {
    // These are verifier error plumbing tests, not genuine cryptographic
    // subject/source/tag mismatch fixtures.
    for reason in [
        "mock: artifact subject digest mismatch",
        "mock: source repository mismatch",
        "mock: source tag mismatch",
        "mock: malformed signed DSSE provenance",
        "mock: Rekor unavailable",
    ] {
        let fixture = Fixture::new();
        let out = fixture.run(
            &fixture.provenance_args(),
            &[("SLSA_EXIT", "57"), ("SLSA_ERROR", reason)],
        );
        assert_exit(&out, 1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("PROVENANCE_INVALID: SLSA provenance"),
            "{out:?}"
        );
        assert!(stderr.contains("57") && stderr.contains(reason), "{out:?}");
        assert_eq!(fixture.calls(), ["cosign", "slsa-verifier"]);
        assert!(
            out.stdout.is_empty(),
            "no success after SLSA rejection: {out:?}"
        );
    }
}

#[test]
fn empty_release_policy_is_refused_before_any_subprocess() {
    for flag in ["--source-uri", "--source-tag"] {
        for value in ["", " \t"] {
            let fixture = Fixture::new();
            let mut args = fixture.provenance_args();
            let position = args.iter().position(|arg| arg == flag).unwrap();
            args[position + 1] = value.into();
            let out = fixture.run(&args, &[]);
            assert_exit(&out, 2);
            assert!(
                String::from_utf8_lossy(&out.stderr).contains(flag),
                "{out:?}"
            );
            assert!(
                fixture.calls().is_empty(),
                "empty policy must not reach a verifier"
            );
        }
    }
}

#[test]
fn help_does_not_promise_offline_provenance_or_shared_trust_roots() {
    let fixture = Fixture::new();
    let out = fixture.run(&["verify-signature".into(), "--help".into()], &[]);
    assert_exit(&out, 0);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(!help.lines().next().unwrap().contains("offline"), "{help}");
    assert!(
        help.contains("may use network") && help.contains("cosign only"),
        "{help}"
    );
    assert!(help.contains("does not make SLSA offline"), "{help}");
    assert!(fixture.calls().is_empty());
}

#[test]
fn signature_only_does_not_require_or_claim_slsa_verification() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.tools.join("slsa-verifier")).unwrap();
    let out = fixture.run(&fixture.args(false), &[]);
    assert_exit(&out, 0);
    assert_eq!(fixture.calls(), ["cosign"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("signature verified") && !stdout.contains("SLSA"),
        "{out:?}"
    );
    let cosign_args = fixture.verifier_args("cosign");
    assert!(!cosign_args[0].iter().any(|arg| arg == "--trusted-root"));
}

#[test]
fn source_policy_without_provenance_is_refused_before_any_subprocess() {
    for supplied in [
        vec!["--source-uri", "github.com/example/own"],
        vec!["--source-tag", "v0.1.0"],
        vec![
            "--source-uri",
            "github.com/example/own",
            "--source-tag",
            "v0.1.0",
        ],
    ] {
        let fixture = Fixture::new();
        let mut args = fixture.args(false);
        args.extend(supplied.into_iter().map(OsString::from));
        let out = fixture.run(&args, &[]);
        assert_exit(&out, 2);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--provenance"),
            "{out:?}"
        );
        assert!(fixture.calls().is_empty());
    }
}

#[test]
fn non_utf8_root_is_passed_losslessly_to_both_verifiers() {
    let mut fixture = Fixture::new();
    let previous = fixture.root.clone();
    let mut bytes = previous.clone().into_os_string().into_vec();
    bytes.push(0xff);
    fixture.root = PathBuf::from(OsString::from_vec(bytes));
    fs::rename(previous, &fixture.root).unwrap();
    fixture.tools = fixture.root.join("trusted-tools");
    let mut args = fixture.provenance_args();
    args.extend([
        OsString::from("--root"),
        fixture.root.clone().into_os_string(),
    ]);
    let out = fixture.run(&args, &[]);
    assert_exit(&out, 0);
    let cosign = fixture.verifier_args("cosign");
    let slsa = fixture.verifier_args("slsa");
    assert_eq!(
        cosign[0].last().unwrap(),
        fixture.root.join("release.tar.gz").as_os_str()
    );
    assert_eq!(slsa[0][1], fixture.root.join("release.tar.gz").as_os_str());
    assert_eq!(
        slsa[0][3],
        fixture.root.join("multiple.intoto.jsonl").as_os_str()
    );
    let position = cosign[0]
        .iter()
        .position(|arg| arg == "--trusted-root")
        .unwrap();
    assert_eq!(
        cosign[0][position + 1],
        fixture.root.join("trusted-root.json").as_os_str()
    );
    assert_eq!(fixture.calls(), ["cosign", "slsa-verifier"]);
}

#[test]
fn verifier_spawn_failures_name_the_exact_tool_path_without_success() {
    for name in ["cosign", "slsa-verifier"] {
        let fixture = Fixture::new();
        let path = fixture.tools.join(name);
        fs::write(&path, "#!/nonexistent/own-test-interpreter\n").unwrap();
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("IO_ERROR") && stderr.contains(path.to_str().unwrap()),
            "{out:?}"
        );
        assert!(out.stdout.is_empty());
        assert_eq!(
            fixture.calls(),
            if name == "cosign" {
                vec![]
            } else {
                vec!["cosign"]
            }
        );
    }
}

fn assert_exit(out: &Output, code: i32) {
    assert_eq!(out.status.code(), Some(code), "{out:?}");
}

#[test]
fn provenance_requires_explicit_repository_and_exact_tag_before_any_subprocess() {
    for supplied in [
        None,
        Some(("--source-uri", "github.com/example/own")),
        Some(("--source-tag", "v0.1.0")),
    ] {
        let fixture = Fixture::new();
        let mut args = fixture.args(true);
        if let Some((flag, value)) = supplied {
            args.extend([flag, value].map(OsString::from));
        }
        let out = fixture.run(&args, &[]);
        assert_exit(&out, 2);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for flag in ["--source-uri", "--source-tag"] {
            if supplied.map(|pair| pair.0) != Some(flag) {
                assert!(stderr.contains(flag), "{out:?}");
            }
        }
        assert!(
            fixture.calls().is_empty(),
            "no verifier may run for incomplete policy"
        );
    }
}

#[test]
fn verifiers_receive_the_published_formats_artifact_and_explicit_release_policy() {
    let fixture = Fixture::new();
    let mut args = fixture.args(true);
    args.extend(
        [
            "--source-uri",
            "github.com/other/secure-own",
            "--source-tag",
            "release/2026.01",
            "--trusted-root",
            "trusted-root.json",
        ]
        .map(OsString::from),
    );
    let out = fixture.run(&args, &[]);
    assert_exit(&out, 0);
    assert_eq!(fixture.calls(), ["cosign", "slsa-verifier"]);
    assert_eq!(
        fixture.verifier_args("cosign"),
        vec![vec![
            OsStr::new("verify-blob").to_owned(),
            "--new-bundle-format=true".into(),
            "--bundle".into(),
            fixture.root.join("release.bundle").into_os_string(),
            "--certificate-identity-regexp".into(),
            IDENTITY.into(),
            "--certificate-oidc-issuer".into(),
            ISSUER.into(),
            "--trusted-root".into(),
            fixture.root.join("trusted-root.json").into_os_string(),
            fixture.root.join("release.tar.gz").into_os_string(),
        ]]
    );
    assert_eq!(fixture.verifier_args("slsa"), vec![vec![
        "verify-artifact".into(), fixture.root.join("release.tar.gz").into_os_string(),
        "--provenance-path".into(), fixture.root.join("multiple.intoto.jsonl").into_os_string(),
        "--source-uri".into(), "github.com/other/secure-own".into(),
        "--source-tag".into(), "release/2026.01".into(),
        "--builder-id".into(),
        "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0".into(),
    ]]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("SLSA provenance verified"),
        "{out:?}"
    );
}

#[test]
fn all_missing_inputs_are_named_before_any_subprocess() {
    for name in [
        "trusted-root.json",
        "multiple.intoto.jsonl",
        "release.tar.gz",
        "release.bundle",
    ] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join(name)).unwrap();
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("IO_ERROR") && stderr.contains(name),
            "{out:?}"
        );
        assert!(
            fixture.calls().is_empty(),
            "verifier ran with absent {name}"
        );
        assert!(
            out.stdout.is_empty(),
            "no premature verification success: {out:?}"
        );
    }
}

#[test]
fn all_directory_inputs_are_refused_before_any_subprocess() {
    for name in [
        "trusted-root.json",
        "multiple.intoto.jsonl",
        "release.tar.gz",
        "release.bundle",
    ] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join(name)).unwrap();
        fs::create_dir(fixture.root.join(name)).unwrap();
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(name),
            "{out:?}"
        );
        assert!(
            fixture.calls().is_empty(),
            "verifier ran with directory {name}"
        );
    }
}

#[test]
fn unreadable_inputs_are_refused_before_any_subprocess() {
    for name in [
        "trusted-root.json",
        "multiple.intoto.jsonl",
        "release.tar.gz",
        "release.bundle",
    ] {
        let fixture = Fixture::new();
        let path = fixture.root.join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Root may bypass Unix permission bits; only exercise denied opens.
        if fs::File::open(&path).is_ok() {
            continue;
        }
        let out = fixture.run(&fixture.provenance_args(), &[]);
        assert_exit(&out, 2);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(name),
            "{out:?}"
        );
        assert!(
            fixture.calls().is_empty(),
            "verifier ran with unreadable {name}"
        );
    }
}
