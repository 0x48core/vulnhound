# 🐕 vulnhound

Fast, single-binary security scanner written in Go. vulnhound finds your
dependencies, checks them against [OSV.dev](https://osv.dev), and reports
known vulnerabilities with the version that fixes them.

> **Status: early MVP.** Directory scanning for Go and npm works today.
> See the [roadmap](#roadmap) for what is coming.

## Install

```bash
go install github.com/0x48core/vulnhound/cmd/vulnhound@latest
```

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
Target: /home/me/myapp (dir)
Packages: 11   Vulnerabilities: 39 (1 CRITICAL, 5 HIGH, 13 MEDIUM, 3 LOW, 17 UNKNOWN)

PACKAGE   VERSION  ECOSYSTEM  ID                   SEVERITY  FIXED IN  LOCATION           SUMMARY
minimist  1.2.0    npm        GHSA-xvch-5gv4-984h  CRITICAL  1.2.6     package-lock.json  Prototype Pollution in minimist
lodash    4.17.15  npm        GHSA-p6mc-m468-83gw  HIGH      4.17.19   package-lock.json  Prototype Pollution in lodash
...
```

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
- [ ] 🚧 SARIF output for GitHub code scanning
- [ ] 🚧 `scan image`: container images (Alpine, Debian, Go binaries)
- [ ] 🚧 Offline vulnerability database (SQLite cache of OSV dumps)
- [ ] 🚧 PyPI, Cargo, Maven, RPM
- [ ] 🚧 `scan repo` and secret detection
- [ ] 🚧 SBOM export (CycloneDX, SPDX)

## License

[Apache 2.0](LICENSE)
