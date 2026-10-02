#!/usr/bin/env python3
"""Generate grafana/perch-dashboard.json.

The dashboard is written here rather than by hand: 1,900 lines of panel JSON
edited in the Grafana UI drift into overlapping panels and queries that only
work against one person's Prometheus. Every panel below uses the same variables
and filters, and the layout is computed, so neither can happen.

    python3 grafana/build_dashboard.py

Nothing here is specific to one deployment. The dashboard needs only perch's
own metrics: no relabeling, no particular job name, no particular datasource.
"""

import json
from pathlib import Path

DS = {"type": "prometheus", "uid": "${datasource}"}

# Every query is scoped by these. `job` is discovered, not assumed.
I = 'job=~"$job", instance=~"$instance"'
V = I + ', validator=~"$validator"'

# Default alert thresholds (src/config.rs). Drawn on the graphs so a line
# crossing them means what perch would do; they are defaults, not your config.
VOTE_LAG_SLOTS = 200
ROOT_LAG_SLOTS = 400
ENDPOINT_LAG_SLOTS = 300
SKIP_WARN, SKIP_PAGE = 20, 45
BALANCE_WARN, BALANCE_PAGE = 3, 0.5
FILL_WARN_S, FILL_PAGE_S = 24 * 3600, 6 * 3600
INODE_WARN, INODE_PAGE = 85, 95

GREEN, YELLOW, ORANGE, RED, GRAY, BLUE = "green", "yellow", "orange", "red", "#808080", "blue"


class Layout:
    """Places panels left to right, wrapping at 24 columns. Rows reset it."""

    def __init__(self):
        self.panels, self.x, self.y, self.row_h, self.next_id = [], 0, 0, 0, 1

    def _id(self):
        self.next_id += 1
        return self.next_id - 1

    def row(self, title):
        self._newline()
        self.panels.append({
            "type": "row", "title": title, "collapsed": False, "panels": [],
            "id": self._id(), "gridPos": {"h": 1, "w": 24, "x": 0, "y": self.y},
        })
        self.y += 1

    def _newline(self):
        if self.x:
            self.y += self.row_h
            self.x, self.row_h = 0, 0

    def add(self, panel, w, h, empty=None):
        # What an empty panel means. Most of these are empty when things are
        # fine, or when a feature is not configured, and a bare "No data"
        # reads like a broken dashboard.
        if empty:
            panel["fieldConfig"]["defaults"]["noValue"] = empty
        if self.x + w > 24:
            self._newline()
        panel["id"] = self._id()
        panel["gridPos"] = {"h": h, "w": w, "x": self.x, "y": self.y}
        panel["datasource"] = DS
        self.panels.append(panel)
        self.x += w
        self.row_h = max(self.row_h, h)


def named(expr):
    """Attach the instance's `[watchtower] name` as a `name` label.

    A scrape address like `10.0.0.5:9469` is what Prometheus calls an instance;
    "chimps-box" is what the operator calls it. Multiplying by the info metric
    (always 1) adds the label without changing the value.
    """
    return f"({expr}) * on (instance) group_left (name) perch_watchtower_info{{{I}}}"


def target(expr, legend="", ref="A", instant=False, fmt=None):
    # Legends and table rows name instances by perch's own name, not the
    # scrape address, wherever the query is per instance.
    if "{{instance}}" in legend:
        expr, legend = named(expr), legend.replace("{{instance}}", "{{name}}")
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref,
         "editorMode": "code", "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def steps(*pairs):
    """steps((None, GREEN), (5, RED)) -> threshold steps."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in pairs]}


def mapping(values):
    """{1: ("Healthy", GREEN), ...} -> a value mapping."""
    return [{"type": "value", "options": {
        str(k): {"text": t, "color": c, "index": i} for i, (k, (t, c)) in enumerate(values.items())}}]


def stat(title, desc, expr, unit="short", thresholds=None, mappings=None, decimals=None, color_mode="background"):
    defaults = {"unit": unit, "thresholds": thresholds or steps((None, GREEN)),
                "color": {"mode": "thresholds"}, "mappings": mappings or []}
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat", "title": title, "description": desc,
        "targets": [target(expr, instant=True)],
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"colorMode": color_mode, "graphMode": "none", "justifyMode": "center",
                    "textMode": "value", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    }


def timeseries(title, desc, targets, unit="short", thresholds=None, threshold_style="off",
               draw="line", stack=False, min_=None, max_=None, decimals=None, legend_calcs=("lastNotNull",),
               log=False, legend="bottom"):
    custom = {"drawStyle": draw, "lineWidth": 2 if draw == "line" else 1,
              "fillOpacity": 10 if draw == "line" else 80, "showPoints": "never",
              "lineInterpolation": "stepAfter" if draw == "line" else "linear",
              "spanNulls": False, "axisSoftMin": 0,
              "thresholdsStyle": {"mode": threshold_style},
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    if log:
        # Values that span orders of magnitude: 0.02 SOL next to 170,000.
        custom["scaleDistribution"] = {"type": "log", "log": 10}
        custom.pop("axisSoftMin")
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"},
                "thresholds": thresholds or steps((None, GREEN))}
    if min_ is not None:
        defaults["min"] = min_
    if max_ is not None:
        defaults["max"] = max_
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "timeseries", "title": title, "description": desc, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": legend, "showLegend": True,
                               "calcs": list(legend_calcs)},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def state_timeline(title, desc, targets, states):
    """`states` is {value: (text, color)}. The colors go in as thresholds as
    well as mappings: state-timeline colors bars from thresholds, so mappings
    alone render every state in the same gray."""
    mappings = mapping(states)
    ordered = sorted(states.items())
    thresholds = steps(*[(None if i == 0 else v - 0.5, c) for i, (v, (_, c)) in enumerate(ordered)])
    return {
        "type": "state-timeline", "title": title, "description": desc, "targets": targets,
        "fieldConfig": {"defaults": {"mappings": mappings, "color": {"mode": "thresholds"},
                                     "thresholds": thresholds or steps((None, GRAY)),
                                     "custom": {"fillOpacity": 80, "lineWidth": 0}},
                        "overrides": []},
        "options": {"showValue": "never", "mergeValues": True, "rowHeight": 0.8, "alignValue": "left",
                    "legend": {"showLegend": False}, "tooltip": {"mode": "single"}},
    }


def table(title, desc, targets, join_on, keep, rename, overrides=(), sort=None):
    # `join_on=None` merges on every shared label instead: right when a row is
    # identified by more than one (instance and channel), where joining on one
    # field would multiply rows.
    join = ({"id": "merge", "options": {}} if join_on is None
            else {"id": "joinByField", "options": {"byField": join_on, "mode": "outer"}})
    transformations = [
        join,
        {"id": "filterFieldsByName", "options": {"include": {"pattern": "^(" + "|".join(keep) + ")$"}}},
        {"id": "organize", "options": {"indexByName": {k: i for i, k in enumerate(keep)},
                                       "renameByName": rename}},
    ]
    if sort:
        transformations.append({"id": "sortBy", "options": {"sort": [{"field": sort}]}})
    return {
        "type": "table", "title": title, "description": desc, "targets": targets,
        "transformations": transformations,
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                                     "thresholds": steps((None, GREEN))},
                        "overrides": list(overrides)},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    }


def colored(field, mappings=None, thresholds=None, unit=None, decimals=None):
    props = [{"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}}]
    if mappings:
        props.append({"id": "mappings", "value": mappings})
    if thresholds:
        props.append({"id": "thresholds", "value": thresholds})
    if unit:
        props.append({"id": "unit", "value": unit})
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    return {"matcher": {"id": "byName", "options": field}, "properties": props}


def plain(field, unit=None, decimals=None, mappings=None):
    props = []
    if unit:
        props.append({"id": "unit", "value": unit})
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    if mappings:
        props.append({"id": "mappings", "value": mappings})
    return {"matcher": {"id": "byName", "options": field}, "properties": props}


L = Layout()

# --- Fleet ----------------------------------------------------------------------
L.row("Fleet")
L.add(stat("Instances up", "perch instances Prometheus could scrape, out of those that have ever reported.",
           f'count(up{{{I}}} == 1) or vector(0)', thresholds=steps((None, GREEN)), color_mode="value"), 4, 4)
L.add(stat("Checks firing", "Checks past their hold-down and alerting right now, across the selected instances.",
           f'sum(perch_check_firing{{{I}}}) or vector(0)', thresholds=steps((None, GREEN), (1, RED))), 4, 4)
L.add(stat("Validators delinquent", "Selected validators any endpoint reports as delinquent.",
           f'count(max by (validator) (perch_validator_delinquent{{{V}}}) == 1) or vector(0)',
           thresholds=steps((None, GREEN), (1, RED))), 4, 4)
L.add(stat("Instances blind", "Instances that could not get enough answers from their RPC endpoints to evaluate checks. "
           "Blindness is reported on its own schedule; it never pages as a validator problem.",
           f'count(perch_visible{{{I}}} == 0) or vector(0)', thresholds=steps((None, GREEN), (1, ORANGE))), 4, 4)
L.add(stat("In maintenance", "Instances with an active silence or maintenance window (perch maint).",
           f'count(perch_silenced{{{I}}} == 1) or vector(0)', thresholds=steps((None, GREEN), (1, BLUE))), 4, 4)
L.add(stat("Lost notifications", "Alerts that failed every delivery retry during the selected time range. "
           "Anything above zero means someone was not told.",
           f'round(sum(increase(perch_notify_failures_total{{{I}}}[$__range]))) or vector(0)',
           thresholds=steps((None, GREEN), (1, RED))), 4, 4)

UPDOWN = mapping({1: ("up", GREEN), 0: ("DOWN", RED)})
YESNO_BAD = mapping({0: ("no", GREEN), 1: ("YES", RED)})
L.add(table(
    "Instances",
    "One row per perch instance. Cycle age climbing past a few minutes means that instance is wedged. "
    "Owner shows which instance sends alerts for its scope. Validator is the build its own local RPC reports.",
    [
        target(f'max by (instance, name, solana_cluster) (perch_watchtower_info{{{I}}})', ref="A", instant=True, fmt="table"),
        target(f'max by (instance) (up{{{I}}})', ref="B", instant=True, fmt="table"),
        target(f'max by (instance) (perch_visible{{{I}}})', ref="C", instant=True, fmt="table"),
        target(f'sum by (instance) (perch_check_firing{{{I}}})', ref="D", instant=True, fmt="table"),
        target(f'time() - max by (instance) (perch_last_cycle_timestamp_seconds{{{I}}})', ref="E", instant=True, fmt="table"),
        target(f'max by (instance) (perch_alerting_owner{{{I}}})', ref="F", instant=True, fmt="table"),
        target(f'max by (instance) (perch_silenced{{{I}}})', ref="G", instant=True, fmt="table"),
        target(f'max by (instance, perch_version) (label_join(perch_build_info{{{I}}}, "perch_version", " ", "version", "commit"))',
               ref="H", instant=True, fmt="table"),
        target(f'max by (instance, validator_version) (label_replace(perch_node_version{{{I}}}, "validator_version", "$1", "version", "(.*)"))',
               ref="J", instant=True, fmt="table"),
    ],
    join_on="instance",
    keep=["name", "solana_cluster", "Value #B", "Value #C", "Value #D", "Value #E",
          "Value #F", "Value #G", "perch_version", "validator_version", "instance"],
    rename={"instance": "Instance", "name": "Name", "solana_cluster": "Cluster", "Value #B": "Scrape",
            "Value #C": "Visible", "Value #D": "Firing", "Value #E": "Cycle age", "Value #F": "Owner",
            "Value #G": "Silenced", "perch_version": "perch", "validator_version": "Validator",
            "instance": "Scrape target"},
    overrides=[
        colored("Scrape", mappings=UPDOWN),
        colored("Visible", mappings=mapping({1: ("yes", GREEN), 0: ("BLIND", ORANGE)})),
        colored("Firing", thresholds=steps((None, GREEN), (1, RED)), decimals=0),
        colored("Cycle age", thresholds=steps((None, GREEN), (180, YELLOW), (600, RED)), unit="s", decimals=0),
        plain("Owner", mappings=mapping({1: ("yes", GREEN), 0: ("standby", GRAY)})),
        colored("Silenced", mappings=mapping({0: ("no", GREEN), 1: ("yes", BLUE)})),
    ],
    sort="Name",
), 24, 7)

# --- Checks ---------------------------------------------------------------------
L.row("Checks")
L.add(state_timeline(
    "Checks not healthy (empty is good)",
    "Only the periods a check was unhealthy (red) or could not be evaluated (gray). Gray is time you were not "
    "actually being monitored for that check: usually an RPC outage, or a check still warming up.",
    [target(f'perch_check_verdict{{{I}}} < 1', "{{instance}} {{check}}")],
    {0: ("unhealthy", RED), -1: ("unknown", GRAY)},
), 24, 8, empty="Every check healthy")
L.add(timeseries(
    "Hold-down progress",
    "How far each unhealthy check is toward firing: 100% is its hold-down (pending_for). A check that climbs "
    "repeatedly but never reaches 100% is a real condition the hold-down is keeping quiet.",
    [target(f'(perch_check_unhealthy_seconds{{{I}}} > 0) / on (instance, check) '
            f'(perch_check_pending_for_seconds{{{I}}} > 0) * 100', "{{instance}} {{check}}")],
    unit="percent", min_=0, thresholds=steps((None, GREEN), (100, RED)), threshold_style="dashed",
), 12, 8, empty="Nothing unhealthy")
L.add(table(
    "Firing now",
    "Every check currently alerting, and how long it has been confirmed unhealthy.",
    [target(named(f'perch_check_unhealthy_seconds{{{I}}} and on (instance, check) (perch_check_firing{{{I}}} == 1)'),
            ref="A", instant=True, fmt="table")],
    join_on="check",
    keep=["name", "check", "Value"],
    rename={"name": "Instance", "check": "Check", "Value": "Unhealthy for"},
    overrides=[plain("Unhealthy for", unit="s", decimals=0)],
), 12, 8, empty="Nothing firing")

# --- Validators -----------------------------------------------------------------
L.row("Validators")
L.add(timeseries(
    "Vote and root distance",
    f"Slots between the cluster tip (the most advanced endpoint) and the validator's last vote and root. "
    f"Dashed lines are the default alert limits: {VOTE_LAG_SLOTS} for votes, {ROOT_LAG_SLOTS} for roots.",
    [target(f'max by (validator) (max by (instance) (perch_endpoint_slot{{{I}}}) - on (instance) group_right '
            f'perch_validator_last_vote_slot{{{V}}})', "{{validator}} vote", "A"),
     target(f'max by (validator) (max by (instance) (perch_endpoint_slot{{{I}}}) - on (instance) group_right '
            f'perch_validator_root_slot{{{V}}})', "{{validator}} root", "B")],
    unit="none", min_=0, thresholds=steps((None, GREEN), (VOTE_LAG_SLOTS, ORANGE), (ROOT_LAG_SLOTS, RED)),
    threshold_style="dashed",
), 12, 9)
L.add(state_timeline(
    "Delinquent",
    "Whether any endpoint reported the validator delinquent. perch pages only when several independent "
    "endpoints agree, so a single red sliver here may not have paged.",
    [target(f'max by (validator) (perch_validator_delinquent{{{V}}})', "{{validator}}")],
    {0: ("voting", GREEN), 1: ("delinquent", RED)},
), 12, 9)
L.add(timeseries(
    "Vote credits per hour",
    "Credits earned per hour. A drop to zero while the validator is not delinquent is the "
    "voting-but-not-landing failure that vote_stalled pages for.",
    [target(f'max by (validator) (increase(perch_validator_credits{{{V}}}[1h]))', "{{validator}}")],
    unit="short", min_=0, decimals=0,
), 8, 8, empty="Needs an hour of history")
L.add(timeseries(
    "Skip rate this epoch",
    f"Leader slots that produced no block, as a percentage of slots assigned so far this epoch. Default "
    f"limits: {SKIP_WARN}% notifies, {SKIP_PAGE}% pages.",
    [target(f'max by (validator) (perch_validator_skip_percent{{{V}}})', "{{validator}}")],
    unit="percent", min_=0, thresholds=steps((None, GREEN), (SKIP_WARN, ORANGE), (SKIP_PAGE, RED)),
    threshold_style="dashed",
), 8, 8)
L.add(timeseries(
    "Identity balance",
    f"SOL in the identity account, which pays for votes. Default limits: below {BALANCE_WARN} SOL notifies, "
    f"below {BALANCE_PAGE} SOL pages.",
    [target(f'max by (validator) (perch_validator_balance_sol{{{V}, account="identity"}})', "{{validator}}")],
    unit="none", decimals=2,
    thresholds=steps((None, RED), (BALANCE_PAGE, ORANGE), (BALANCE_WARN, GREEN)), threshold_style="dashed",
), 8, 8)
L.add(table(
    "Leader slots this epoch",
    "Assigned leader slots and blocks produced so far this epoch.",
    [target(f'max by (validator) (perch_validator_leader_slots{{{V}}})', ref="A", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_blocks_produced{{{V}}})', ref="B", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_skip_percent{{{V}}})', ref="C", instant=True, fmt="table")],
    join_on="validator",
    keep=["validator", "Value #A", "Value #B", "Value #C"],
    rename={"validator": "Validator", "Value #A": "Leader slots", "Value #B": "Produced", "Value #C": "Skipped"},
    overrides=[plain("Leader slots", decimals=0), plain("Produced", decimals=0),
               colored("Skipped", thresholds=steps((None, GREEN), (SKIP_WARN, ORANGE), (SKIP_PAGE, RED)),
                       unit="percent", decimals=1)],
    sort="Validator",
), 24, 6, empty="No leader slots yet this epoch")

# --- Alpenglow ------------------------------------------------------------------
# SIMD-0357: at each epoch boundary a vote account needs a BLS key and
# rent-exempt plus one VAT, or it sits out the epoch after next.
MINIMUM = f'scalar(max(perch_vote_account_minimum_sol{{{I}}}))'
VAT = f'scalar(max(perch_vat_per_epoch_sol{{{I}}}))'
BALANCE = f'max by (validator) (perch_validator_vote_account_balance_sol{{{V}}})'
L.row("Alpenglow")
L.add(stat("Alpenglow", "Whether Alpenglow is in force on this cluster. Once it is scheduled, the very next epoch "
           "boundary already checks every vote account.",
           f'max(perch_alpenglow_phase{{{I}}})',
           mappings=mapping({0: ("not scheduled", BLUE), 1: ("activates next epoch", ORANGE), 2: ("active", GREEN)}),
           thresholds=steps((None, BLUE), (0.5, ORANGE), (1.5, GREEN))), 6, 4, empty="Not reported")
L.add(stat("VAT per epoch", "The Validator Admission Ticket burned from every admitted vote account at each epoch "
           "boundary. It falls as slot times shorten.",
           f'max(perch_vat_per_epoch_sol{{{I}}})', unit="none", decimals=2, color_mode="value"), 6, 4,
      empty="Not reported")
L.add(stat("Vote accounts under the minimum", "Selected validators whose vote account holds less than rent-exempt "
           "plus one VAT. Under Alpenglow they will be excluded at the next boundary.",
           f'count({BALANCE} < {MINIMUM}) or vector(0)', thresholds=steps((None, GREEN), (1, RED))), 6, 4)
L.add(stat("Missing BLS keys", "Selected validators whose vote account has no BLS public key. Under Alpenglow a vote "
           "account without one cannot vote or produce blocks.",
           f'count(max by (validator) (perch_validator_bls_registered{{{V}}}) == 0) or vector(0)',
           thresholds=steps((None, GREEN), (1, RED))), 6, 4)
L.add(timeseries(
    "Vote account balance",
    "Each vote account against the balance it must hold at the next epoch boundary (dashed): rent-exempt plus one "
    "VAT. The VAT is burned at every boundary, so a vote account with no commission income steps down by one VAT "
    "per epoch.",
    [target(BALANCE, "{{validator}}", "A"),
     target(f'max(perch_vote_account_minimum_sol{{{I}}})', "required at next boundary", "B")],
    unit="none", decimals=2, log=True, legend="right",
), 24, 7, empty="No vote accounts reported")
L.panels[-1]["fieldConfig"]["overrides"] = [{
    "matcher": {"id": "byFrameRefID", "options": "B"},
    "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": RED}},
                   {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                   {"id": "custom.fillOpacity", "value": 0}]}]
L.add(table(
    "Vote accounts",
    "Balance, BLS key, and what the commission earned last epoch does against the VAT. Epochs left counts the "
    "boundaries the balance still passes at that rate; blank means the account earns more than the VAT and is "
    "not draining. Before Alpenglow is scheduled these are what would happen.",
    [target(BALANCE, ref="A", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_bls_registered{{{V}}})', ref="B", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_vote_income_sol{{{V}}})', ref="C", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_vote_net_sol_per_epoch{{{V}}})', ref="D", instant=True, fmt="table"),
     target(f'max by (validator) (perch_validator_vote_runway_epochs{{{V}}})', ref="E", instant=True, fmt="table")],
    join_on="validator",
    keep=["validator", "Value #A", "Value #B", "Value #C", "Value #D", "Value #E"],
    rename={"validator": "Validator", "Value #A": "Balance (SOL)", "Value #B": "BLS key",
            "Value #C": "Income/epoch", "Value #D": "Net/epoch", "Value #E": "Epochs left"},
    overrides=[plain("Balance (SOL)", decimals=2),
               colored("BLS key", mappings=mapping({1: ("registered", GREEN), 0: ("MISSING", RED)})),
               plain("Income/epoch", decimals=2),
               colored("Net/epoch", thresholds=steps((None, ORANGE), (0, GREEN)), decimals=2),
               {"matcher": {"id": "byName", "options": "Epochs left"},
                "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                               {"id": "thresholds", "value": steps((None, RED), (3, ORANGE), (10, GREEN))},
                               {"id": "decimals", "value": 0},
                               # Absent means not draining: the best case, so it
                               # must not inherit the red base threshold.
                               {"id": "mappings", "value": [{"type": "special", "options": {
                                   "match": "null", "result": {"text": "not draining", "color": GREEN, "index": 0}}}]}]}],
    sort="Validator",
), 24, 7, empty="No vote accounts reported")

# --- Endpoints ------------------------------------------------------------------
L.row("RPC endpoints")
L.add(state_timeline(
    "Endpoint usable",
    "Whether each endpoint gave a usable answer each cycle. Red is noise perch absorbed: an endpoint that "
    "fails never pages on its own.",
    [target(f'perch_endpoint_usable{{{I}}}', "{{instance}} {{endpoint}}")],
    {1: ("usable", GREEN), 0: ("failed", RED)},
), 12, 8)
L.add(timeseries(
    "Endpoint errors per minute",
    "Transient errors (timeouts, 429s, 5xx) are expected on free endpoints. Config errors (a bad key, a plan "
    "that does not cover the call) do not go away by themselves and quietly cost you quorum.",
    [target(f'rate(perch_endpoint_transient_errors_total{{{I}}}[5m]) * 60', "{{instance}} {{endpoint}} transient", "A"),
     target(f'rate(perch_endpoint_config_errors_total{{{I}}}[5m]) * 60', "{{instance}} {{endpoint}} config", "B")],
    unit="short", min_=0, decimals=1,
), 12, 8, empty="No endpoint errors")
L.add(timeseries(
    "Slots behind the most advanced endpoint",
    f"An endpoint more than {ENDPOINT_LAG_SLOTS} slots behind (the default) has its answers discarded for "
    f"that cycle, so a frozen endpoint cannot vote a broken validator healthy.",
    [target(f'max by (instance) (perch_endpoint_slot{{{I}}}) - on (instance) group_right perch_endpoint_slot{{{I}}}',
            "{{instance}} {{endpoint}}")],
    unit="none", min_=0, thresholds=steps((None, GREEN), (ENDPOINT_LAG_SLOTS, RED)), threshold_style="dashed",
), 24, 7)

# --- Disks ----------------------------------------------------------------------
L.row("Disks")
L.add(timeseries(
    "Projected time to full",
    "perch's own least-squares projection, the exact value its alert tests. Absent means not filling, or not "
    "enough history yet. Default limits: under 24h notifies, under 6h pages.",
    [target(f'perch_filesystem_seconds_to_full{{{I}}}', "{{host}} {{mountpoint}}")],
    unit="s", min_=0, thresholds=steps((None, RED), (FILL_PAGE_S, ORANGE), (FILL_WARN_S, GREEN)),
    threshold_style="dashed",
), 12, 8, empty="Not filling, or under 45m of history")
L.add(timeseries(
    "Free space",
    "Space available to the validator on each monitored filesystem.",
    [target(f'perch_filesystem_avail_bytes{{{I}}}', "{{host}} {{mountpoint}}")],
    unit="bytes", min_=0,
), 12, 8, empty="No [[hosts]] configured")
L.add(timeseries(
    "Used and inodes",
    f"Space and inodes in use. A filesystem can run out of inodes with space to spare; default inode limits "
    f"are {INODE_WARN}% and {INODE_PAGE}%.",
    [target(f'perch_filesystem_used_percent{{{I}}}', "{{host}} {{mountpoint}} space", "A"),
     target(f'perch_filesystem_inodes_used_percent{{{I}}}', "{{host}} {{mountpoint}} inodes", "B")],
    unit="percent", min_=0, max_=100, thresholds=steps((None, GREEN), (INODE_WARN, ORANGE), (INODE_PAGE, RED)),
    threshold_style="dashed",
), 12, 8, empty="No [[hosts]] configured")
L.add(state_timeline(
    "Read-only and scrape health",
    "A filesystem remounted read-only is how a disk usually fails under a validator; perch pages immediately. "
    "A failed node_exporter scrape freezes the disk checks rather than alerting.",
    [target(f'perch_filesystem_readonly{{{I}}}', "{{host}} {{mountpoint}} read-only", "A"),
     target(f'1 - perch_host_scrape_ok{{{I}}}', "{{host}} scrape failed", "B")],
    {0: ("ok", GREEN), 1: ("PROBLEM", RED)},
), 12, 8, empty="No [[hosts]] configured")

# --- Watchtowers ----------------------------------------------------------------
L.row("Watchtowers")
L.add(timeseries(
    "Cycle age",
    "Seconds since each instance last finished a cycle. It resets every interval; a line that keeps climbing "
    "is a wedged watchtower.",
    [target(f'time() - perch_last_cycle_timestamp_seconds{{{I}}}', "{{instance}}")],
    unit="s", min_=0, thresholds=steps((None, GREEN), (600, RED)), threshold_style="dashed",
), 8, 7)
L.add(timeseries(
    "Cycle duration",
    "How long each probe cycle took. Approaching the interval means endpoints are slow or timing out.",
    [target(f'perch_cycle_duration_seconds{{{I}}}', "{{instance}}")],
    unit="s", min_=0,
), 8, 7)
L.add(state_timeline(
    "Alerting owner",
    "Which instance is responsible for sending alerts. With alerting = \"auto\", exactly one instance of a "
    "redundant pair should be the owner at any moment.",
    [target(f'perch_alerting_owner{{{I}}}', "{{instance}}")],
    {1: ("owner", GREEN), 0: ("standby", GRAY)},
), 8, 7)
L.add(state_timeline(
    "Peers, as each instance sees them",
    "Whether each instance can reach the peers it watches. A peer that is unreachable while its validator "
    "keeps voting is lost visibility, not an outage.",
    [target(f'perch_peer_reachable{{{I}}}', "{{instance}} → {{peer}}")],
    {1: ("reachable", GREEN), 0: ("unreachable", RED)},
), 12, 7, empty="No [[peers]] configured")
L.add(timeseries(
    "Peer cycle age",
    "How long ago each peer completed a cycle, as reported by the instance watching it.",
    [target(f'perch_peer_last_cycle_age_seconds{{{I}}}', "{{instance}} → {{peer}}")],
    unit="s", min_=0,
), 12, 7, empty="No [[peers]] configured")

# --- Notifications --------------------------------------------------------------
L.row("Notifications")
L.add(table(
    "Delivered in range",
    "Notifications each instance actually delivered during the selected time range, by channel. A restart "
    "resets perch's counters; increase() accounts for that.",
    [target(named(f'round(sum by (instance, channel) (increase(perch_notify_deliveries_total{{{I}}}[$__range])))'),
            ref="A", instant=True, fmt="table"),
     target(named(f'round(sum by (instance, channel) (increase(perch_notify_failures_total{{{I}}}[$__range])))'),
            ref="B", instant=True, fmt="table")],
    join_on=None,
    keep=["name", "channel", "Value #A", "Value #B"],
    rename={"name": "Instance", "channel": "Channel", "Value #A": "Delivered", "Value #B": "Lost"},
    overrides=[plain("Delivered", decimals=0),
               colored("Lost", thresholds=steps((None, GREEN), (1, RED)), decimals=0)],
    sort="Instance",
), 8, 8, empty="Nothing sent in this range")
nt = timeseries(
    "Notifications over time",
    "Deliveries per interval by instance and channel. Lost deliveries, in red, failed every retry.",
    [target(f'round(sum by (instance, channel) (increase(perch_notify_deliveries_total{{{I}}}[$__interval]))) > 0',
            "{{instance}} {{channel}}", "A"),
     target(f'round(sum by (instance, channel) (increase(perch_notify_failures_total{{{I}}}[$__interval]))) > 0',
            "{{instance}} {{channel}} lost", "B")],
    draw="bars", stack=True, decimals=0, legend_calcs=("sum",),
)
nt["interval"] = "5m"
nt["fieldConfig"]["overrides"] = [{"matcher": {"id": "byFrameRefID", "options": "B"},
                                   "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": RED}}]}]
L.add(nt, 16, 8, empty="Nothing sent in this range")
L.add(timeseries(
    "Time since the alert path was last proven",
    "Age of the last successful self-test per channel (perch test-notify, or the weekly scheduled one). The "
    "dashed line is two weeks: two missed weekly tests.",
    [target(f'time() - (perch_notify_self_test_timestamp_seconds{{{I}}} > 0)', "{{instance}} {{channel}}")],
    unit="s", min_=0, thresholds=steps((None, GREEN), (14 * 86400, RED)), threshold_style="dashed",
), 24, 6, empty="No self-test yet: run perch test-notify, or wait for the weekly one")


def query_var(name, label, query, multi=True, include_all=True, desc=""):
    return {
        "name": name, "label": label, "type": "query", "datasource": DS, "description": desc,
        "query": {"query": query, "refId": f"{name}-var"}, "definition": query,
        "refresh": 2, "sort": 1, "multi": multi, "includeAll": include_all,
        "allValue": ".*" if include_all else None,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]} if include_all else {},
        "options": [], "hide": 0, "regex": "",
    }


dashboard = {
    "__inputs": [],
    "__requires": [
        {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
        {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
        {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
        {"type": "panel", "id": "table", "name": "Table", "version": ""},
        {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
        {"type": "panel", "id": "state-timeline", "name": "State timeline", "version": ""},
    ],
    "title": "perch",
    "description": "Solana validator watchtower: validators, checks, RPC endpoints, disks, peers and notifications. "
                   "https://github.com/TheChimpions/perch-watchtower",
    "uid": "perch",
    "tags": ["perch", "solana", "validator"],
    "editable": True,
    "graphTooltip": 1,
    "time": {"from": "now-6h", "to": "now"},
    "refresh": "1m",
    "schemaVersion": 39,
    "version": 1,
    "timezone": "",
    "links": [{"title": "perch docs", "type": "link", "icon": "doc", "targetBlank": True,
               "url": "https://github.com/TheChimpions/perch-watchtower/blob/main/docs/operations.md#grafana"}],
    "annotations": {"list": [{
        "builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
        "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"}]},
    "templating": {"list": [
        {"name": "datasource", "label": "Prometheus", "type": "datasource", "query": "prometheus",
         "current": {}, "hide": 0, "refresh": 1, "regex": "", "options": [],
         "description": "The Prometheus that scrapes your perch instances."},
        query_var("job", "Job", "label_values(perch_build_info, job)", multi=False, include_all=False,
                  desc="The Prometheus job your perch targets are scraped under. Found automatically."),
        query_var("cluster", "Cluster", 'label_values(perch_watchtower_info{job=~"$job"}, solana_cluster)',
                  desc="The Solana cluster each instance is pinned to with [watchtower] cluster."),
        query_var("instance", "Instance",
                  'label_values(perch_watchtower_info{job=~"$job", solana_cluster=~"$cluster"}, instance)'),
        query_var("validator", "Validator",
                  'label_values(perch_validator_last_vote_slot{job=~"$job", instance=~"$instance"}, validator)',
                  desc="Validators by their configured label."),
    ]},
    "panels": L.panels,
}

out = Path(__file__).with_name("perch-dashboard.json")
out.write_text(json.dumps(dashboard, indent=2) + "\n")
print(f"wrote {out} ({len(L.panels)} panels)")
