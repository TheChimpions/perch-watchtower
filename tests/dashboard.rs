//! The shipped Grafana dashboard is a template other people import, so it is
//! checked like code. The version it replaced had panels drawn on top of each
//! other and queries that only worked against one operator's Prometheus.

use serde_json::Value;
use std::{collections::HashSet, path::Path};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn dashboard() -> Value {
    let raw = std::fs::read_to_string(root().join("grafana/perch-dashboard.json")).unwrap();
    serde_json::from_str(&raw).expect("dashboard is valid JSON")
}

fn panels(d: &Value) -> Vec<&Value> {
    d["panels"].as_array().unwrap().iter().collect()
}

fn exprs(d: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for p in panels(d) {
        for t in p["targets"].as_array().into_iter().flatten() {
            out.push(t["expr"].as_str().unwrap_or_default().to_string());
        }
    }
    for v in d["templating"]["list"].as_array().unwrap() {
        if let Some(q) = v["query"]["query"].as_str() {
            out.push(q.to_string());
        }
    }
    out
}

/// Metric names perch exports, read from the source that renders them.
fn exported() -> HashSet<String> {
    let src = std::fs::read_to_string(root().join("src/metrics.rs")).unwrap();
    let mut names = HashSet::new();
    for chunk in src.split("e.metric(").skip(1) {
        if let Some(name) = chunk.split('"').nth(1) {
            names.insert(name.to_string());
        }
    }
    names
}

#[test]
fn no_two_panels_share_a_grid_cell() {
    let d = dashboard();
    let mut taken = HashSet::new();
    for p in panels(&d) {
        let g = &p["gridPos"];
        let (x, y, w, h) = (
            g["x"].as_u64().unwrap(),
            g["y"].as_u64().unwrap(),
            g["w"].as_u64().unwrap(),
            g["h"].as_u64().unwrap(),
        );
        assert!(x + w <= 24, "{} runs off the grid", p["title"]);
        for cx in x..x + w {
            for cy in y..y + h {
                assert!(taken.insert((cx, cy)), "{} overlaps another panel", p["title"]);
            }
        }
    }
}

#[test]
fn panel_ids_are_unique() {
    let d = dashboard();
    let ids: Vec<u64> = panels(&d).iter().map(|p| p["id"].as_u64().unwrap()).collect();
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
}

/// A query against a metric perch does not export renders "No data" forever,
/// which looks like a broken install rather than a broken dashboard.
#[test]
fn every_queried_metric_is_one_perch_exports() {
    let d = dashboard();
    let exported = exported();
    assert!(exported.len() > 30, "could not read metric names from src/metrics.rs");
    for e in exprs(&d) {
        // A metric is a `perch_` name followed by its `{` selector. That leaves
        // out label names a query invents, such as label_replace's targets.
        for (i, _) in e.match_indices("perch_") {
            let name: String = e[i..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if e[i + name.len()..].starts_with('{') {
                assert!(exported.contains(&name), "dashboard queries {name}, which perch does not export");
            }
        }
    }
}

/// Nothing tied to one deployment: the job is discovered, the datasource is a
/// variable (so file provisioning works, not only the import dialog), and no
/// label is assumed that perch does not export itself.
#[test]
fn nothing_is_specific_to_one_prometheus() {
    let raw = std::fs::read_to_string(root().join("grafana/perch-dashboard.json")).unwrap();
    for forbidden in ["job=\\\"perch\\\"", "DS_PROMETHEUS", "mainnet"] {
        assert!(!raw.contains(forbidden), "dashboard contains {forbidden:?}");
    }
    // A bare `cluster` label is one Prometheus setups add themselves; perch
    // exports `solana_cluster` precisely so the dashboard never relies on it.
    for (i, _) in raw.match_indices("cluster=~") {
        assert!(raw[..i].ends_with("solana_"), "dashboard filters on a `cluster` label perch does not export");
    }
    let d = dashboard();
    for p in panels(&d) {
        if p["type"] == "row" {
            continue;
        }
        assert_eq!(p["datasource"]["uid"], "${datasource}", "{} pins a datasource", p["title"]);
        for t in p["targets"].as_array().unwrap() {
            let e = t["expr"].as_str().unwrap();
            assert!(
                e.contains("$instance"),
                "{}: query is not scoped by $instance: {e}",
                p["title"]
            );
        }
    }
}

/// The JSON is generated. Editing it by hand is how the last one decayed, so
/// the committed file must be exactly what the generator writes.
#[test]
fn the_dashboard_is_what_the_generator_produces() {
    let script = root().join("grafana/build_dashboard.py");
    let out = std::env::temp_dir().join(format!("perch-dash-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let copy = out.join("build_dashboard.py");
    std::fs::copy(&script, &copy).unwrap();
    let status = match std::process::Command::new("python3").arg(&copy).output() {
        Ok(o) => o.status,
        Err(e) => panic!("python3 is needed to check the dashboard is generated: {e}"),
    };
    assert!(status.success(), "build_dashboard.py failed");
    let generated = std::fs::read_to_string(out.join("perch-dashboard.json")).unwrap();
    let committed = std::fs::read_to_string(root().join("grafana/perch-dashboard.json")).unwrap();
    std::fs::remove_dir_all(&out).ok();
    assert!(
        generated == committed,
        "grafana/perch-dashboard.json differs from what build_dashboard.py writes; \
         edit the script and run `python3 grafana/build_dashboard.py`"
    );
}
