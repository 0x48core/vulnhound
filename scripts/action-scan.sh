#!/usr/bin/env bash
# Runs a vulnhound scan for the GitHub Action (action.yml).
#
# Inputs arrive as environment variables, never interpolated into the
# script, so they cannot inject shell commands:
#   SCAN_PATH    directory to scan
#   FAIL_ON      severity threshold, or empty
#   SKIP_DEV     "true" to ignore dev dependencies
#   EXCLUDE      patterns to skip, separated by newlines or commas
#   IGNORE_FILE  ignore file path, or empty for the default
#   SARIF        "true" to also write a SARIF report
#
# The scan runs once with JSON output; the log lines, step outputs, and job
# summary are all derived from that report. vulnhound's exit code (1:
# findings at or above FAIL_ON, 2: scan failed) is written to the exit-code
# output instead of failing this step, so action.yml can still upload SARIF
# before its last step fails the job.
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
while IFS= read -r pattern; do
  pattern="${pattern#"${pattern%%[![:space:]]*}"}" # trim leading space
  pattern="${pattern%"${pattern##*[![:space:]]}"}" # trim trailing space
  if [[ -n "$pattern" ]]; then
    args+=(--exclude "$pattern")
  fi
done < <(printf '%s\n' "${EXCLUDE:-}" | tr ',' '\n')
if [[ -n "${IGNORE_FILE:-}" ]]; then
  args+=(--ignore-file "$IGNORE_FILE")
fi
sarif=""
if [[ "${SARIF:-false}" == "true" ]]; then
  sarif="${report%.json}.sarif"
  args+=(--sarif-output "$sarif")
fi

set +e
vulnhound "${args[@]}"
code=$?
set -e

echo "exit-code=$code" >> "$GITHUB_OUTPUT"

# Exit code 2 means no trustworthy report was written.
if [[ $code -eq 2 || ! -s "$report" ]]; then
  exit 0
fi

findings=$(jq '.findings | length' "$report")
{
  echo "report=$report"
  echo "findings=$findings"
  echo "sarif=$sarif"
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
        | "| \(.severity) | \(.package.name | cell) | \(.package.version | cell) | [\(.id)](\(.url)) | \(.fixed_in // "-" | cell) | \(.package.locations[0] | if . then .path + (if .line then ":\(.line)" else "" end) else "-" end | cell) |" ) )
  end,
  "",
  if (.ignored // [] | length) > 0 then
    "_Ignored \(.ignored | length) by `\(.ignore_file)`: \([.ignored[].id] | join(", "))_", ""
  else empty end
' "$report" >> "$GITHUB_STEP_SUMMARY"
