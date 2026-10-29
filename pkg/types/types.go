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
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	PURL      string   `json:"purl"`
	Locations []string `json:"locations"`
	Direct    bool     `json:"direct"`
	Dev       bool     `json:"dev,omitempty"`
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

// Report is the complete result of a scan.
type Report struct {
	Target      string    `json:"target"`
	TargetType  string    `json:"target_type"`
	GeneratedAt time.Time `json:"generated_at"`
	Packages    []Package `json:"packages"`
	Findings    []Finding `json:"findings"`
}
