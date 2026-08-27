//! The `seismic-manifest` subprocess contract, as non-Rust callers rely on
//! it: `render` puts the canonical bytes on stdout and nothing else does;
//! every failure is stderr + nonzero exit with an empty stdout.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] =
    include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");
fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seismic-manifest"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn render_emits_canonical_bytes_from_any_formatting() {
    let value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    let compact = serde_json::to_vec(&value).unwrap();
    let out = run(&["render", "-"], &compact);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, FIXTURE);
}

#[test]
fn render_reads_a_file_path() {
    let dir = std::env::temp_dir().join(format!("seismic-manifest-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("doc.json");
    std::fs::write(&path, FIXTURE).unwrap();
    let out = run(&["render", path.to_str().unwrap()], b"");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, FIXTURE);
}

#[test]
fn parse_accepts_a_valid_manifest_silently() {
    let out = run(&["parse", "-"], FIXTURE);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "parse must not write to stdout");
}

#[test]
fn failures_leave_stdout_empty() {
    let mut unknown_field: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    unknown_field["tx_io_pk"] = "0x02ab".into();
    let mut v2 = unknown_field.clone();
    v2["manifest_version"] = 2.into();

    let cases: [(&[&str], Vec<u8>, &str); 4] = [
        (
            &["render", "-"],
            serde_json::to_vec(&unknown_field).unwrap(),
            "tx_io_pk",
        ),
        (
            &["parse", "-"],
            serde_json::to_vec(&unknown_field).unwrap(),
            "tx_io_pk",
        ),
        (
            &["parse", "-"],
            serde_json::to_vec(&v2).unwrap(),
            "unsupported manifest_version 2",
        ),
        (&["parse", "-"], b"{not json".to_vec(), "schema v1"),
    ];
    for (args, stdin, expected) in cases {
        let out = run(args, &stdin);
        assert!(!out.status.success(), "{args:?} should fail");
        assert!(out.stdout.is_empty(), "{args:?} wrote to stdout");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }

    let out = run(&["parse", "/nonexistent/network-manifest.json"], b"");
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}
