//! The shipped example configs must stay valid.
//!
//! These are the first thing anyone deploying this will copy. A config that has
//! quietly rotted -- a renamed field, a tightened validation rule -- turns a
//! five-minute setup into an afternoon, so they are parsed on every test run
//! rather than trusted to review.

use perch::config::{Alerting, Config};
use std::path::{Path, PathBuf};

/// Placeholders a reader is expected to replace. Substituted here so the file
/// can stay readable while still being machine-checked.
fn realize(raw: &str) -> String {
    raw.replace("https://...", "https://api.mainnet-beta.solana.com")
        .replace(
            "YOUR_IDENTITY_PUBKEY",
            "Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk",
        )
        .replace(
            "YOUR_VOTE_PUBKEY",
            "CcaHc2L43ZWjwCHART3oZoJvHLAe9hzT2DJNUpBzoTN1",
        )
}

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn load(name: &str) -> Config {
    // Secrets are `env:` references; provide them so resolution succeeds.
    for (k, v) in [
        ("PAGERDUTY_INTEGRATION_KEY", "test-key"),
        ("TELEGRAM_BOT_TOKEN", "test-token"),
        ("TELEGRAM_CHAT_ID", "test-chat"),
        ("HEARTBEAT_URL", "https://hc-ping.com/test"),
    ] {
        std::env::set_var(k, v);
    }

    let path = examples_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    Config::parse(&realize(&raw))
        .unwrap_or_else(|e| panic!("{} is not a valid config: {e:#}", path.display()))
}

fn all_examples() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(examples_dir())
        .expect("examples directory should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_example_config_parses() {
    let names = all_examples();
    assert!(!names.is_empty(), "no example configs found");
    for name in &names {
        load(name);
    }
}

#[test]
fn the_documented_layouts_are_all_present() {
    let names = all_examples();
    for expected in [
        "1-standalone.toml",
        "2-on-validator.toml",
        "3-hub-on-failover.toml",
        "4-redundant-pair.toml",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "examples/README.md documents {expected}, which is missing"
        );
    }
}

#[test]
fn the_standalone_layout_needs_nothing_else() {
    // The whole point of layout 1: no peers, no hosts, no second machine.
    let c = load("1-standalone.toml");
    assert!(c.peers.is_empty(), "standalone must not require peers");
    assert!(c.hosts.is_empty(), "standalone must not require node_exporter");
    assert!(!c.endpoints.is_empty());
    assert!(
        c.heartbeat.is_some(),
        "with no hub, the heartbeat is what reports the watchtower dying"
    );
}

#[test]
fn the_validator_layout_owns_its_own_scope() {
    let c = load("2-on-validator.toml");
    assert_eq!(
        c.peering.alerting,
        Alerting::Always,
        "a validator-local instance must alert without deferring to anything"
    );
    assert_eq!(
        c.validators.len(),
        1,
        "it must list only its own validator, or it would duplicate its peers"
    );
    assert_eq!(c.hosts.len(), 1, "it should watch its own disks");
}

#[test]
fn the_hub_reports_only_peer_liveness() {
    let c = load("3-hub-on-failover.toml");
    assert_eq!(
        c.peering.alerting,
        Alerting::Peers,
        "the hub must not duplicate the validators' own alerting"
    );
    assert!(
        !c.peers.is_empty(),
        "a hub with no peers supervises nothing"
    );
    assert!(
        c.peers.iter().all(|p| p.validator.is_some()),
        "every peer needs a validator link, or silence cannot be fused with \
         cluster evidence and the hub can only ever notify"
    );
    assert!(
        !c.endpoints.is_empty(),
        "the fusion rule needs the hub's own cluster view"
    );
}

#[test]
fn the_redundant_pair_arbitrates_by_priority() {
    let c = load("4-redundant-pair.toml");
    assert_eq!(c.peering.alerting, Alerting::Auto);
    assert!(
        c.peers.iter().all(|p| p.priority != c.peering.priority),
        "shared priorities would leave both instances believing they alert"
    );
    assert!(
        !c.peering.takeover_after.is_zero(),
        "a zero grace period would hand alerting back and forth on any blip"
    );
}

#[test]
fn every_example_keeps_metrics_off_the_public_internet() {
    // These get copied verbatim. A 0.0.0.0 bind in a shipped example is how an
    // unauthenticated endpoint ends up exposed.
    for name in all_examples() {
        let raw = std::fs::read_to_string(examples_dir().join(&name)).unwrap();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || !trimmed.starts_with("listen") {
                continue;
            }
            assert!(
                !trimmed.contains("0.0.0.0"),
                "{name} binds metrics to 0.0.0.0: {trimmed}"
            );
        }
    }
}

/// Alert text is assembled from multi-line Rust string literals, and a mangled
/// line continuation leaves a run of spaces in the middle of a sentence. That
/// went out to PagerDuty eight times before anyone noticed, because it only
/// shows up in a delivered alert and not in any unit test's assertions.
#[test]
fn no_alert_string_contains_a_run_of_stray_spaces() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable source dir") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // `status.rs` renders an aligned terminal table; runs of spaces there
            // are deliberate column padding, not mangled prose.
            if path.file_name().and_then(|n| n.to_str()) == Some("status.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable source file");
            for (n, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // Only inspect lines that are part of a string literal, and skip
                // comments, where prose alignment is fine.
                if trimmed.starts_with("//") || !line.contains('"') {
                    continue;
                }
                let body = line.trim_start();
                // A run of 3+ spaces between two non-space characters cannot be
                // deliberate formatting in prose.
                let bytes: Vec<char> = body.chars().collect();
                let mut run = 0usize;
                for i in 0..bytes.len() {
                    if bytes[i] == ' ' {
                        run += 1;
                    } else {
                        if run >= 3 && i >= run + 1 {
                            let before = bytes[i - run - 1];
                            if before.is_alphanumeric() || ",.;:".contains(before) {
                                offenders.push(format!(
                                    "{}:{}",
                                    path.strip_prefix(root).unwrap_or(&path).display(),
                                    n + 1
                                ));
                                break;
                            }
                        }
                        run = 0;
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "stray whitespace inside alert strings at: {}",
        offenders.join(", ")
    );
}

/// `config.example.toml` is the file the README tells people to copy, and it is
/// the only config that documents every option. It was silently unparseable --
/// a duplicate key left behind by an edit -- because nothing ever loaded it.
#[test]
fn the_reference_config_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    let raw = std::fs::read_to_string(&path).expect("config.example.toml should exist");
    let realized = realize(&raw);
    if let Err(e) = toml::from_str::<Config>(&realized) {
        panic!("config.example.toml does not parse: {e}");
    }
}

/// The self-test defaults on, and every shipped example omits the section. If
/// that default ever flipped, every deployment would quietly stop verifying its
/// own alerting path -- the exact invisible failure the feature exists to catch.
#[test]
fn examples_without_a_self_test_section_still_verify_their_alerting() {
    for name in all_examples() {
        let config = load(&name);
        assert!(
            config.notify.self_test.enabled,
            "{name} would never verify that it can deliver an alert"
        );
        assert!(
            config.notify.self_test.interval >= perch::config::MIN_SELF_TEST_INTERVAL,
            "{name} has a self-test interval below the safety floor"
        );
    }
}

/// The reference config is what people copy, so every check it shows must
/// carry the value the code would use anyway. It said `vote_delinquent`
/// waited 4m while the default was 60s: anyone who copied it got a four times
/// slower delinquency page, with nothing telling them so.
#[test]
fn the_reference_config_shows_the_real_check_defaults() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    let raw = std::fs::read_to_string(&path).expect("config.example.toml should exist");
    let documented: Config = toml::from_str(&realize(&raw)).expect("parses");
    let defaults: Config = toml::from_str("").expect("an empty config parses");

    let lines = |c: &Config| -> Vec<String> {
        format!("{:#?}", c.checks).lines().map(str::to_string).collect()
    };
    let (doc, def) = (lines(&documented), lines(&defaults));
    let drift: Vec<String> = doc
        .iter()
        .zip(&def)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, (a, b))| {
            // The nearest enclosing field name, so the failure says which check.
            // `{:#?}` indents each top-level check by exactly four spaces.
            let owner = def[..i]
                .iter()
                .rev()
                .find(|l| l.starts_with("    ") && !l.starts_with("     "))
                .and_then(|l| l.trim().split(':').next())
                .unwrap_or_default();
            format!("checks.{owner}: example {} / default {}", a.trim(), b.trim())
        })
        .collect();
    assert!(
        drift.is_empty() && doc.len() == def.len(),
        "config.example.toml disagrees with the code defaults:\n{}",
        drift.join("\n")
    );
}
