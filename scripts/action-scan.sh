#!/usr/bin/env bash
# Runs a vulnhound scan for the GitHub Action (action.yml).
#
# Inputs arrive as environment variables, never interpolated into the
# script, so they cannot inject shell commands:
#   SCAN_PATH  directory to scan
#   FAIL_ON    severity threshold, or empty
#   SKIP_DEV   "true" to ignore dev dependencies
#
# The scan runs once with JSON output; the log lines, step outputs, and job
# summary are all derived from that report. vulnhound's exit code is passed
# through: 1 means findings at or above FAIL_ON, 2 means the scan failed.
set -euo pipefail

# Unique per run, so two scans in one job keep separate reports.
report="$RUNNER_TEMP/vulnhound-report-$(date +%s)-$$.json"
args=(scan dir "${SCAN_PATH:-.}" --format json --output "$report")
if [[ -n "${FAIL_ON:-}" ]]; then
  args+=(--fail-on "$FAIL_ON")
fi
if [[ "${SKIP_DEV:-false}" == "true" ]]; then
  args+=(--skip-dev)
fi

set +e
vulnhound "${args[@]}"
code=$?
set -e

# Exit code 2 means no trustworthy report was written.
if [[ $code -eq 2 || ! -s "$report" ]]; then
  echo "::error title=vulnhound::scan failed (exit code $code)"
  exit "$code"
fi

findings=$(jq '.findings | length' "$report")
{
  echo "report=$report"
  echo "findings=$findings"
} >> "$GITHUB_OUTPUT"

# Log: one line per finding.
jq -r '
  "vulnhound: \(.packages | length) packages, \(.findings | length) vulnerabilities in \(.target)",
  (.findings[] | "  \(.severity)\t\(.package.name)@\(.package.version)\t\(.id)\tfixed in: \(.fixed_in // "-")")
' "$report"

# Job summary: a Markdown table.
jq -r '
  def cell: tostring | gsub("\\|"; "\\|");
  "### 🐕 vulnhound",
  "",
  "Scanned `\(.target)`: **\(.packages | length)** packages, **\(.findings | length)** vulnerabilities.",
  "",
  if (.findings | length) == 0 then
    "No known vulnerabilities found. ✅"
  else
    ( "| Severity | Package | Version | Vulnerability | Fixed in | Location |",
      "|---|---|---|---|---|---|",
      ( .findings[]
        | "| \(.severity) | \(.package.name | cell) | \(.package.version | cell) | [\(.id)](\(.url)) | \(.fixed_in // "-" | cell) | \(.package.locations[0] // "-" | cell) |" ) )
  end,
  ""
' "$report" >> "$GITHUB_STEP_SUMMARY"

if [[ $code -eq 1 ]]; then
  echo "::error title=vulnhound::vulnerabilities found at or above '${FAIL_ON:-}'"
fi
exit "$code"
