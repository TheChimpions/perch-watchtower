#!/usr/bin/env bash
#
# Set sane period/grace on the perch dead-man's-switch checks at healthchecks.io.
#
# Auto-created checks inherit the project defaults (1 day / 1 hour), which means
# a dead box would not raise an alarm for roughly 25 hours. This sets each check
# to the cadence perch actually pings at.
#
#   export HC_API_KEY=...                         # Project Settings -> API Access
#   export PERCH_HC_SLUGS="chimps-1 chimps-2"     # your checks' slugs, one per box
#   ./tune-healthchecks.sh                        # dry run: show what would change
#   ./tune-healthchecks.sh --apply                # make the changes
#   ./tune-healthchecks.sh --apply --delete-orphans
#
# --slugs a,b,c works instead of PERCH_HC_SLUGS.
#
# The key is read from the environment and never appears in argv, so it stays
# out of shell history and out of `ps`.
set -euo pipefail

API="https://healthchecks.io/api/v3"
PERIOD=60     # perch pings every cycle; interval is 60s
GRACE=900     # 15m: above the 10m blind-notify, so this is the backstop and
              # not a second alarm for the same blindness event

APPLY=0; DELETE_ORPHANS=0; SLUG_LIST="${PERCH_HC_SLUGS:-}"
while [ $# -gt 0 ]; do
  a=$1; shift
  case "$a" in
    --apply) APPLY=1 ;;
    --delete-orphans) DELETE_ORPHANS=1 ;;
    --slugs) SLUG_LIST="${1:?--slugs needs a value}"; shift ;;
    --slugs=*) SLUG_LIST="${a#--slugs=}" ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

# Only these are touched. Anything else in the project is left alone -- unless
# --delete-orphans is given, so the list must be complete before using that.
read -r -a SLUGS <<<"${SLUG_LIST//,/ }"
[ "${#SLUGS[@]}" -gt 0 ] || { echo "no checks named: set PERCH_HC_SLUGS or pass --slugs" >&2; exit 2; }

: "${HC_API_KEY:?set HC_API_KEY first (export HC_API_KEY=...)}"
command -v jq >/dev/null || { echo "this script needs jq" >&2; exit 1; }

api() {  # api <method> <path> [json-body]
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -fsS -X "$method" -H "X-Api-Key: $HC_API_KEY" \
         -H "Content-Type: application/json" -d "$body" "$API$path"
  else
    curl -fsS -X "$method" -H "X-Api-Key: $HC_API_KEY" "$API$path"
  fi
}

echo "Fetching checks..."
CHECKS=$(api GET /checks/) || { echo "API call failed -- is HC_API_KEY correct?" >&2; exit 1; }
TOTAL=$(jq '.checks | length' <<<"$CHECKS")
echo "  project has $TOTAL check(s)"
[ "$APPLY" -eq 1 ] || echo "  DRY RUN -- nothing will be changed (pass --apply)"
echo

printf '  %-20s %-12s %-12s %s\n' SLUG PERIOD GRACE ACTION
changed=0; missing=0
for slug in "${SLUGS[@]}"; do
  row=$(jq -c --arg s "$slug" '.checks[] | select(.slug == $s)' <<<"$CHECKS")
  if [ -z "$row" ]; then
    printf '  %-20s %-12s %-12s %s\n' "$slug" - - "NOT FOUND"
    missing=$((missing+1)); continue
  fi
  uuid=$(jq -r '.uuid // (.ping_url | split("/") | last)' <<<"$row")
  t=$(jq -r '.timeout' <<<"$row"); g=$(jq -r '.grace' <<<"$row")
  if [ "$t" = "$PERIOD" ] && [ "$g" = "$GRACE" ]; then
    printf '  %-20s %-12s %-12s %s\n' "$slug" "${t}s" "${g}s" "already correct"
    continue
  fi
  if [ "$APPLY" -eq 1 ]; then
    api POST "/checks/$uuid" "{\"timeout\": $PERIOD, \"grace\": $GRACE}" >/dev/null
    printf '  %-20s %-12s %-12s %s\n' "$slug" "${t}s -> ${PERIOD}s" "${g}s -> ${GRACE}s" "UPDATED"
  else
    printf '  %-20s %-12s %-12s %s\n' "$slug" "${t}s -> ${PERIOD}s" "${g}s -> ${GRACE}s" "would update"
  fi
  changed=$((changed+1))
done

# Anything in the project that is not a perch slug. Reported always; only
# removed when explicitly asked, because this cannot be undone.
echo
ORPHANS=$(jq -r --argjson keep "$(printf '%s\n' "${SLUGS[@]}" | jq -R . | jq -s .)" \
  '.checks[] | select((.slug // "") | IN($keep[]) | not) | "\(.slug // "")\t\(.uuid // (.ping_url | split("/") | last))\t\(.last_ping // "never")"' \
  <<<"$CHECKS")
if [ -z "$ORPHANS" ]; then
  echo "  no checks outside the perch fleet"
else
  echo "  checks NOT in the perch fleet (nothing pings these):"
  while IFS=$'\t' read -r s u lp; do
    [ -z "$s" ] && continue
    if [ "$DELETE_ORPHANS" -eq 1 ] && [ "$APPLY" -eq 1 ]; then
      api DELETE "/checks/$u" >/dev/null && echo "    $s  (last ping $lp)  DELETED"
    else
      echo "    ${s:-<unnamed>}  (last ping $lp)  -- pass --delete-orphans to remove"
    fi
  done <<<"$ORPHANS"
fi

echo
echo "Summary: $changed to change, $missing missing."
if [ "$APPLY" -eq 1 ]; then
  echo "Verifying..."
  api GET /checks/ | jq -r --argjson keep "$(printf '%s\n' "${SLUGS[@]}" | jq -R . | jq -s .)" \
    '.checks[] | select((.slug // "") | IN($keep[])) | "  \(.slug): timeout=\(.timeout)s grace=\(.grace)s status=\(.status)"'
fi
