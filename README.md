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
```

```
Scanned 33 packages in /home/me/goledger
Found 13 vulnerabilities in 3 packages: 2 critical · 1 low · 10 unknown

github.com/jackc/pgx/v5 v5.7.5  → v5.9.2  Go · go.mod
  CRITICAL  GHSA-9jj7-4m8r-rfcm  v5.9.0   Memory-safety vulnerability in github.com/jackc/pgx/v5.
  CRITICAL  GHSA-xgrm-4fwx-7qm8  v5.9.0   pgx contains memory-safety vulnerability
  LOW       GHSA-j88v-2chj-qfwx  v5.9.2   pgx: SQL Injection via placeholder confusion with dollar…

golang.org/x/crypto v0.55.0  → v0.56.0 fixes 2 of 3  Go · go.mod · indirect
  UNKNOWN   GO-2026-5932         no fix   The golang.org/x/crypto/openpgp package is unmaintained…
  UNKNOWN   GO-2026-6354         v0.56.0  Prevent DoS on deadlocked undecided channel in golang.org…
  ...

Upgrading 3 packages fixes 12 of 13 vulnerabilities.
```

Findings are grouped by package, most severe first. Each package line shows
the single upgrade that fixes the most findings (`→ v5.9.2`), or
`no fix available`.

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
- uses: actions/checkout@v4
- uses: 0x48core/vulnhound@main # use @v0 once the first release (v0.1.0) is published
  with:
    fail-on: high
    skip-dev: true
```

The scan results appear as a table in the run's **Summary** tab, and a JSON
report is written for later steps.

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `fail-on` | *(empty)* | Fail at or above `low`, `medium`, `high`, or `critical` |
| `skip-dev` | `false` | Ignore development-only dependencies |
| `setup-go` | `true` | Install Go to build vulnhound; set `false` if the job already has Go 1.26+ |

| Output | Description |
|--------|-------------|
| `findings` | Number of vulnerabilities found |
| `report` | Path to the JSON report |

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
- [ ] 🚧 SARIF output for GitHub code scanning
- [ ] 🚧 `scan image`: container images (Alpine, Debian, Go binaries)
- [ ] 🚧 Offline vulnerability database (SQLite cache of OSV dumps)
- [ ] 🚧 PyPI, Cargo, Maven, RPM
- [ ] 🚧 `scan repo` and secret detection
- [ ] 🚧 SBOM export (CycloneDX, SPDX)

## License

[Apache 2.0](LICENSE)
