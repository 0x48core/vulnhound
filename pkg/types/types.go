// Package types defines the data model shared by every vulnhound stage:
// sources produce files, analyzers turn files into Packages, matchers turn
// Packages into Findings, and reporters render a Report.
package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OSV ecosystem names. See https://ossf.github.io/osv-schema/#affectedpackage-field.
const (
	EcosystemGo  = "Go"
	EcosystemNpm = "npm"
)

// Package is a single dependency discovered in a target.
type Package struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Ecosystem string     `json:"ecosystem"`
	PURL      string     `json:"purl"`
	Locations []Location `json:"locations"`
	Direct    bool       `json:"direct"`
	Dev       bool       `json:"dev,omitempty"`

	// SourceName and SourceVersion identify the distro source package a
	// binary package was built from (e.g. libssl3 from openssl). Debian,
	// Ubuntu, and Alpine advisories are published per source package.
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// AdvisoryName is the name advisories use for this package.
func (p Package) AdvisoryName() string {
	if p.SourceName != "" {
		return p.SourceName
	}
	return p.Name
}

// AdvisoryVersion is the version advisories use for this package.
func (p Package) AdvisoryVersion() string {
	if p.SourceVersion != "" {
		return p.SourceVersion
	}
	return p.Version
}

// Location is where a package was declared: a slash-separated path relative
// to the scan root, and the 1-based line when the analyzer knows it.
type Location struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

func (l Location) String() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	}
	return l.Path
}

// Key identifies a package independently of where it was found.
func (p Package) Key() string {
	return p.Ecosystem + "|" + p.Name + "|" + p.Version
}

// Severity is an ordered vulnerability severity level.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return severityNames[0]
	}
	return severityNames[s]
}

// ParseSeverity parses a severity name. MODERATE (used by GitHub advisories)
// is accepted as an alias for MEDIUM.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, nil
	case "HIGH":
		return SeverityHigh, nil
	case "MEDIUM", "MODERATE":
		return SeverityMedium, nil
	case "LOW":
		return SeverityLow, nil
	case "UNKNOWN", "":
		return SeverityUnknown, nil
	}
	return SeverityUnknown, fmt.Errorf("unknown severity %q", s)
}

// SeverityFromScore maps a CVSS base score to a severity rating.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	*s = v
	return err
}

// Finding is a vulnerability affecting a specific package.
type Finding struct {
	Package   Package  `json:"package"`
	VulnID    string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Severity  Severity `json:"severity"`
	CVSSScore float64  `json:"cvss_score,omitempty"`
	FixedIn   string   `json:"fixed_in,omitempty"`
	URL       string   `json:"url"`
}

// IgnoredFinding is a finding suppressed by an ignore file.
type IgnoredFinding struct {
	Finding
	Reason string `json:"reason,omitempty"`
	Until  string `json:"until,omitempty"` // YYYY-MM-DD the rule expires
}

// Report is the complete result of a scan.
type Report struct {
	Target      string           `json:"target"`
	TargetType  string           `json:"target_type"`
	GeneratedAt time.Time        `json:"generated_at"`
	Packages    []Package        `json:"packages"`
	Findings    []Finding        `json:"findings"`
	Ignored     []IgnoredFinding `json:"ignored,omitempty"`
	IgnoreFile  string           `json:"ignore_file,omitempty"`
}
