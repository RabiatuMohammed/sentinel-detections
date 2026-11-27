#!/usr/bin/env bash
# Builds self-contained test queries: fixtures + detection. Paste the output into any
# Log Analytics / Sentinel Logs blade and run. No real data is read.
# The fixtures shadow OfficeActivity and the sign-in tables with let statements;
# the watchlist call is swapped for the TestWatchlist fixture.
# Blank lines are stripped: Log Analytics runs only the blank-line-delimited block under the cursor.
set -euo pipefail
cd "$(dirname "$0")"
swap() { sed "s/_GetWatchlist('PHI-Sensitive-Sites')/TestWatchlist/" "$1"; }
{ cat fixtures.kql; swap ../detection.kql; } | sed "/^\s*$/d" > test-rewritten.kql
{ cat fixtures.kql; swap ../v1-original.kql;  } | sed "/^\s*$/d" > test-original.kql
{ cat fixtures.kql; cat debug-tail.kql;    } > debug-pipeline.kql
echo "Built test-rewritten.kql, test-original.kql, debug-pipeline.kql"
