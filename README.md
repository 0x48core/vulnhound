# 🐕 vulnhound

Fast, single-binary security scanner written in Go. vulnhound finds your
dependencies, checks them against [OSV.dev](https://osv.dev), and reports
known vulnerabilities with the version that fixes them.

> **Status: early MVP.** Directory scanning for Go and npm works today.
> See the [roadmap](#roadmap) for what is coming.

## Install

Download a binary for Linux, macOS, or Windows from the
[releases page](https://github.com/0x48core/vulnhound/releases), or:

```bash
go install github.com/0x48core/vulnhound/cmd/vulnhound@latest
```

Changes in each release are listed in [CHANGELOG.md](CHANGELOG.md).

Or build from source:

```bash
make build   # produces bin/vulnhound
```

## Usage

```bash
vulnhound scan dir .                          # table output
vulnhound scan dir ./myapp -f json -o report.json
vulnhound scan dir . --fail-on high           # for CI: exit 1 on HIGH or CRITICAL
vulnhound scan dir . --skip-dev               # ignore devDependencies
vulnhound scan dir . --exclude testdata       # skip fixture directories
vulnhound scan dir . -f sarif -o vulnhound.sarif           # for GitHub code scanning
vulnhound scan dir . --sarif-output vulnhound.sarif        # table on screen + SARIF file
```

```
Scanned 33 packages in /home/me/goledger
Found 13 vulnerabilities in 3 packages: 2 critical · 1 low · 10 unknown

github.com/jackc/pgx/v5 v5.7.5  → v5.9.2  Go · go.mod:8
  CRITICAL  GHSA-9jj7-4m8r-rfcm  v5.9.0   Memory-safety vulnerability in github.com/jackc/pgx/v5.
  CRITICAL  GHSA-xgrm-4fwx-7qm8  v5.9.0   pgx contains memory-safety vulnerability
  LOW       GHSA-j88v-2chj-qfwx  v5.9.2   pgx: SQL Injection via placeholder confusion with dollar…

golang.org/x/crypto v0.55.0  → v0.56.0 fixes 2 of 3  Go · go.mod:31 · indirect
  UNKNOWN   GO-2026-5932         no fix   The golang.org/x/crypto/openpgp package is unmaintained…
  UNKNOWN   GO-2026-6354         v0.56.0  Prevent DoS on deadlocked undecided channel in golang.org…
  ...

Upgrading 3 packages fixes 12 of 13 vulnerabilities.
```

Findings are grouped by package, most severe first. Each package line shows
the single upgrade that fixes the most findings (`→ v5.9.2`), or
`no fix available`, and the file and line that declare the package.

### Output formats

| Format | Use |
|--------|-----|
| `table` | Default; for people |
| `json` | For scripts. Every package carries `locations: [{"path", "line"}]` |
| `sarif` | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub code scanning: one alert per vulnerable package per file, pointing at the declaring line |

SARIF file paths are written relative to the current directory when the
scanned directory is inside it, so run the scan from the repository root and
alerts link to the right files even when you scan a subdirectory.

### Excluding paths

`--exclude` (repeatable, or comma-separated) skips files and directories:

| Pattern | Skips |
|---------|-------|
| `testdata` | Every file or directory named `testdata`, at any depth |
| `*.min.js` | Matching file names at any depth |
| `examples/legacy` | That path from the scan root (patterns with `/`) |
| `services/*/fixtures` | `fixtures` under any direct child of `services` |

Patterns use Go's [`path.Match`](https://pkg.go.dev/path#Match) syntax;
`**` is not supported. `node_modules`, `vendor`, and `.git` are always
skipped.

### Ignoring accepted vulnerabilities

Put a `.vulnhoundignore` file in the scanned directory (or pass
`--ignore-file`). Each line names a vulnerability ID or any alias such as a
CVE, optionally limited to one package and given an expiry date:

```
# Not reachable: we never parse untrusted HTML.
GO-2026-6860
CVE-2026-1234  pkg=github.com/jackc/pgx/v5  until=2026-12-31  # upgrade planned in Q4
```

Ignored findings don't count toward `--fail-on` and are left out of SARIF.
They are still listed: in a line under the table and in the JSON `ignored`
array with their reason. After its `until` date (UTC), a rule stops applying
and vulnhound warns, so accepted risks get reviewed instead of hidden
forever. A malformed line is an error, so a typo never silently fails to
ignore, or ignores the wrong thing.

### Colors

In a terminal, severities, upgrades, and missing fixes are colored, and
vulnerability IDs are clickable links to osv.dev (in terminals that support
links). Summaries are cut to fit the terminal width.

| Flag / variable | Effect |
|-----------------|--------|
| `--color auto` | Default: color only when writing to a terminal |
| `--color always` | Color even when piped, e.g. CI logs or `less -R` |
| `--color never` | No color (`--no-color` also works) |
| `NO_COLOR=1` | Disables `auto` color ([no-color.org](https://no-color.org)) |
| `VULNHOUND_COLORS` | Custom colors, see below |

`VULNHOUND_COLORS` takes `role=SGR` pairs separated by `:`, where SGR is an
ANSI code such as `1;31` (bold red). An empty value turns a role's color off.

```bash
# Bold red CRITICAL text instead of a red badge, magenta HIGH, uncolored summaries
export VULNHOUND_COLORS='critical=1;31:high=1;35:summary='
```

| Role | Default | Used for |
|------|---------|----------|
| `critical` | `1;97;41` bold white on red | CRITICAL severity |
| `high` | `1;31` bold red | HIGH severity |
| `medium` | `1;33` bold yellow | MEDIUM severity |
| `low` | `1;36` bold cyan | LOW severity |
| `unknown` | `1;90` bold grey | UNKNOWN severity |
| `package` | `1` bold | Package name |
| `version` | *(none)* | Installed and fixed versions |
| `meta` | `2` dim | Ecosystem, location, `indirect`, `dev` |
| `id` | *(none)* | Vulnerability ID |
| `summary` | *(none)* | Vulnerability summary |
| `upgrade` | `32` green | An upgrade that fixes everything |
| `partial` | `33` yellow | An upgrade that fixes some findings |
| `nofix` | `31` red | No fix available |
| `title` | `1` bold | Counts in the header |

Unknown roles or invalid codes are skipped with a warning, so a typo never
breaks the output. JSON output never contains color codes.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Scan error (bad flags, unreadable target, OSV unreachable) |

### Supported files

| Ecosystem | File | Notes |
|-----------|------|-------|
| Go | `go.mod` | Honors `replace`; local-path replacements are skipped |
| npm | `package-lock.json` | lockfileVersion 1, 2, and 3; aliases and dev deps |

`node_modules/`, `vendor/`, and `.git/` are not scanned.

### Severity

Severity comes from the CVSS v3 vector when OSV has one, otherwise from the
advisory's own rating. Records with neither (common for Go vulnerability
database entries without a GitHub advisory) show as `UNKNOWN`. Records that
alias each other, such as `GO-2023-1737` and `GHSA-2c4m-59x9-fr2g`, are merged
into one finding.

## GitHub Action

Use vulnhound in any repository's workflow:

```yaml
permissions:
  contents: read
  security-events: write # only needed for upload-sarif

steps:
  - uses: actions/checkout@v4
  - uses: 0x48core/vulnhound@v0
    with:
      fail-on: high
      skip-dev: true
      exclude: testdata
      upload-sarif: true
```

The scan results appear as a table in the run's **Summary** tab, a JSON
report is written for later steps, and with `upload-sarif` findings appear
in the repository's **Security → Code scanning** tab and as pull request
annotations. SARIF is uploaded even when `fail-on` fails the job.

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `fail-on` | *(empty)* | Fail at or above `low`, `medium`, `high`, or `critical` |
| `skip-dev` | `false` | Ignore development-only dependencies |
| `exclude` | *(empty)* | Paths to skip, separated by newlines or commas |
| `ignore-file` | *(empty)* | Ignore file; defaults to `.vulnhoundignore` in `path` |
| `sarif` | `false` | Also write a SARIF report |
| `upload-sarif` | `false` | Upload SARIF to code scanning (implies `sarif`; needs `security-events: write`) |
| `setup-go` | `true` | Install Go to build vulnhound; set `false` if the job already has Go 1.26+ |

| Output | Description |
|--------|-------------|
| `findings` | Number of vulnerabilities found, excluding ignored ones |
| `report` | Path to the JSON report |
| `sarif` | Path to the SARIF report, when `sarif` or `upload-sarif` is set |

The action builds vulnhound from its own source, so the scanner version always
matches the action ref you pin. See [docs/workflow.md](docs/workflow.md#using-vulnhound-in-your-own-pipeline)
for more examples.

## How it works

```
Source ──► Analyzers ──► Packages ──► Matcher ──► Reporter
(dir)      (go.mod,      (deduped)    (OSV.dev    (table,
           package-lock)               API)        JSON)
```

Every source exposes an `fs.FS`, so analyzers work the same whether files
come from a directory, a Git clone, or a container image.

| Path | Purpose |
|------|---------|
| `cmd/vulnhound` | CLI (cobra) |
| `internal/source` | Targets exposed as `fs.FS` |
| `internal/analyzer` | Per-ecosystem package detection |
| `internal/matcher` | OSV lookup, alias merging, CVSS scoring, fixed versions |
| `internal/report` | Table and JSON output |
| `pkg/types` | Public data model: `Package`, `Finding`, `Report` |

More detail:

- [Architecture](docs/architecture.md): components, data model, matching
  logic, concurrency, error handling, extension points
- [Workflow](docs/workflow.md): what a scan does step by step, development
  and testing, adding ecosystems, CI/CD and pipeline usage

## Roadmap

- [x] `scan dir` with Go and npm, OSV matching, table and JSON output, `--fail-on`
- [x] GitHub Action with job summary and JSON report
- [x] Colored table grouped by package with upgrade advice
- [x] SARIF output and code scanning upload, `--exclude`, `.vulnhoundignore`
- [ ] 🚧 `scan image`: container images (Alpine, Debian, Go binaries)
- [ ] 🚧 Offline vulnerability database (SQLite cache of OSV dumps)
- [ ] 🚧 PyPI, Cargo, Maven, RPM
- [ ] 🚧 `scan repo` and secret detection
- [ ] 🚧 SBOM export (CycloneDX, SPDX)

## License

[Apache 2.0](LICENSE)
