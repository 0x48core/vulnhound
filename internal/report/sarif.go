package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/0x48core/vulnhound/pkg/types"
)

// SARIF 2.1.0, the subset GitHub code scanning reads.
// See https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     sarifText          `json:"shortDescription"`
	FullDescription      sarifText          `json:"fullDescription"`
	HelpURI              string             `json:"helpUri"`
	Help                 sarifHelp          `json:"help"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
	Properties           sarifRuleProps     `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	// GitHub maps this CVSS-style score to critical/high/medium/low.
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, r *types.Report, opts Options) error {
	rules := make(map[string]sarifRule)
	results := []sarifResult{}
	for _, f := range r.Findings {
		if _, ok := rules[f.VulnID]; !ok {
			rules[f.VulnID] = sarifRuleFor(f)
		}
		// One result per declaring file: each lockfile is fixed separately.
		locs := f.Package.Locations
		if len(locs) == 0 {
			locs = []types.Location{{Path: "."}}
		}
		for _, loc := range locs {
			results = append(results, sarifResultFor(f, loc, opts.PathPrefix))
		}
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	driver := sarifDriver{
		Name:           "vulnhound",
		InformationURI: "https://github.com/0x48core/vulnhound",
		Version:        opts.ToolVersion,
		Rules:          make([]sarifRule, 0, len(ids)),
	}
	for _, id := range ids {
		driver.Rules = append(driver.Rules, rules[id])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	})
}

func sarifRuleFor(f types.Finding) sarifRule {
	summary := f.Summary
	if summary == "" {
		summary = f.VulnID
	}
	ids := append([]string{f.VulnID}, f.Aliases...)
	help := fmt.Sprintf("%s\n\nIdentifiers: %s\nDetails: %s", summary, strings.Join(ids, ", "), f.URL)
	markdown := fmt.Sprintf("**%s**\n\nIdentifiers: %s\n\n[View on OSV.dev](%s)", summary, strings.Join(ids, ", "), f.URL)

	rule := sarifRule{
		ID:                   f.VulnID,
		Name:                 "VulnerableDependency",
		ShortDescription:     sarifText{Text: summary},
		FullDescription:      sarifText{Text: summary},
		HelpURI:              f.URL,
		Help:                 sarifHelp{Text: help, Markdown: markdown},
		DefaultConfiguration: sarifConfiguration{Level: sarifLevel(f.Severity)},
		Properties: sarifRuleProps{
			SecuritySeverity: securitySeverity(f),
			Tags:             []string{"security", "vulnerability", strings.ToLower(f.Package.Ecosystem)},
		},
	}
	return rule
}

func sarifResultFor(f types.Finding, loc types.Location, prefix string) sarifResult {
	uri := path.Join(prefix, loc.Path)
	line := max(loc.Line, 1) // GitHub requires a region

	fix := "No fixed version is known."
	if f.FixedIn != "" {
		fix = "Upgrade to " + f.FixedIn + "."
	}
	msg := fmt.Sprintf("%s %s (%s) is affected by %s: %s. %s",
		f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.VulnID, strings.TrimSuffix(f.Summary, "."), fix)
	if f.Summary == "" {
		msg = fmt.Sprintf("%s %s (%s) is affected by %s. %s",
			f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.VulnID, fix)
	}

	// Stable across line shifts, so GitHub tracks the same alert over time.
	sum := sha256.Sum256([]byte(f.VulnID + "\x00" + f.Package.Name + "\x00" + f.Package.Version + "\x00" + uri))
	return sarifResult{
		RuleID:  f.VulnID,
		Level:   sarifLevel(f.Severity),
		Message: sarifText{Text: msg},
		Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifact{URI: uri},
			Region:           sarifRegion{StartLine: line},
		}}},
		PartialFingerprints: map[string]string{"vulnhound/v1": hex.EncodeToString(sum[:16])},
	}
}

func sarifLevel(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityLow:
		return "note"
	}
	return "warning"
}

// securitySeverity is the CVSS score when known, otherwise a representative
// score for the severity band. Unknown severity is left unset.
func securitySeverity(f types.Finding) string {
	if f.CVSSScore > 0 {
		return fmt.Sprintf("%.1f", f.CVSSScore)
	}
	switch f.Severity {
	case types.SeverityCritical:
		return "9.5"
	case types.SeverityHigh:
		return "8.0"
	case types.SeverityMedium:
		return "5.5"
	case types.SeverityLow:
		return "2.0"
	}
	return ""
}
