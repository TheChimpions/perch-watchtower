//! Embed the git commit in the binary.
//!
//! A version number says which release; it does not say which build. Several
//! binaries can carry the same version and differ in behaviour, and the only
//! way to tell them apart from a running fleet is something the build itself
//! stamped in. Resolution order: the git checkout being built from; else a
//! `PERCH_COMMIT` variable, which is how a tarball build (no `.git`) is told
//! what it is; else "unknown", stated plainly rather than guessed.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn main() {
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).map(|c| {
        let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
            .is_some_and(|s| !s.is_empty());
        if dirty { format!("{c}-dirty") } else { c }
    });
    let commit = commit
        .or_else(|| std::env::var("PERCH_COMMIT").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PERCH_COMMIT={commit}");
    println!("cargo:rerun-if-env-changed=PERCH_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
