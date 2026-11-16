package kms

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExportJSON generates a canonical JSON representation of the audit report.
func ExportJSON(report *AuditReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExportTable formats the audit report as an ANSI terminal box table.
func ExportTable(report *AuditReport) string {
	var b strings.Builder

	statusColor := "\033[32m" // green
	if report.Status != "PASS" {
		statusColor = "\033[31m" // red
	}
	resetColor := "\033[0m"
	bold := "\033[1m"

	b.WriteString(fmt.Sprintf("%s========================================================================================%s\n", bold, resetColor))
	b.WriteString(fmt.Sprintf("%s           LOGIHERTZ SOVEREIGN KMS - 10-RULE SECURITY POSTURE AUDITOR                   %s\n", bold, resetColor))
	b.WriteString(fmt.Sprintf("%s========================================================================================%s\n", bold, resetColor))
	b.WriteString(fmt.Sprintf(" Policy ID:     %s\n", report.PolicyID))
	b.WriteString(fmt.Sprintf(" Policy Name:   %s\n", report.PolicyName))
	b.WriteString(fmt.Sprintf(" Organization:  %s\n", report.Organization))
	b.WriteString(fmt.Sprintf(" Evaluated At:  %s\n", report.Timestamp))
	b.WriteString(fmt.Sprintf(" Posture Score: %s%d/100 [%s]%s\n", statusColor+bold, report.PostureScore, report.Status, resetColor))
	b.WriteString(fmt.Sprintf(" Rules Tested:  %d | Passed: %d | Failed: %d | Deductions: -%d\n", report.TotalRules, report.PassedRules, report.FailedRules, report.Deductions))
	b.WriteString("----------------------------------------------------------------------------------------\n")

	if len(report.Findings) == 0 {
		b.WriteString(fmt.Sprintf(" %s[+] ALL 10 NORMATIVE SECURITY RULES COMPLIANT - MAXIMUM SOVEREIGNTY ASSURED%s\n", statusColor, resetColor))
	} else {
		b.WriteString(fmt.Sprintf(" %-12s | %-8s | %-8s | %-4s | %s\n", "RULE ID", "SEVERITY", "CWE", "DED", "TITLE & RECOMMENDATION"))
		b.WriteString("----------------------------------------------------------------------------------------\n")
		for _, f := range report.Findings {
			sevColor := "\033[33m" // yellow for medium/low
			if f.Severity == "CRITICAL" {
				sevColor = "\033[31;1m" // bold red
			} else if f.Severity == "HIGH" {
				sevColor = "\033[31m" // red
			}
			b.WriteString(fmt.Sprintf(" %-12s | %s%-8s%s | %-8s | -%-3d | %s\n", f.RuleID, sevColor, f.Severity, resetColor, f.CWE, f.Deduction, f.Title))
			b.WriteString(fmt.Sprintf("              |          |          |      | -> Rec: %s\n", f.Recommendation))
		}
	}
	b.WriteString(fmt.Sprintf("%s========================================================================================%s\n", bold, resetColor))
	return b.String()
}

// SarifReport structures an OASIS SARIF v2.1.0 output document.
type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool      SarifTool     `json:"tool"`
	Artifacts []SarifTarget `json:"artifacts"`
	Results   []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"semanticVersion"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     SarifMessage           `json:"shortDescription"`
	FullDescription      SarifMessage           `json:"fullDescription"`
	DefaultConfiguration SarifRuleConfiguration `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type SarifRuleConfiguration struct {
	Level string `json:"level"`
}

type SarifTarget struct {
	Location SarifLocationDetail `json:"location"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifLocationDetail `json:"artifactLocation"`
	Region           SarifRegion         `json:"region"`
}

type SarifLocationDetail struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

// ExportSARIF converts an AuditReport to OASIS SARIF v2.1.0 JSON.
func ExportSARIF(report *AuditReport) (string, error) {
	ruleCatalog := map[string]struct {
		title string
		cwe   string
		level string
	}{
		"LH-KMS-001": {"Plaintext Root Key Exposure or Weak Shamir Unseal Quorum", "CWE-321", "error"},
		"LH-KMS-002": {"Weak or Unauthenticated Envelope Cipher", "CWE-327", "error"},
		"LH-KMS-003": {"Missing Mutual TLS Client Verification or Unauthenticated RPC", "CWE-306", "error"},
		"LH-KMS-004": {"Unbound Envelope Additional Authenticated Data (AAD)", "CWE-345", "error"},
		"LH-KMS-005": {"Automated KEK Version Rotation Disabled or Excessive Interval", "CWE-324", "error"},
		"LH-KMS-006": {"Missing Key Memory Locking, Swap Protection, or Immediate Zeroization", "CWE-226", "error"},
		"LH-KMS-007": {"Missing CSPRNG Health Check or Excessive GCM Invocations", "CWE-330", "error"},
		"LH-KMS-008": {"Raw KEK Export Permitted or Weak Key Grant Separation", "CWE-285", "warning"},
		"LH-KMS-009": {"Short Key Deletion Safety Window or Missing Intrusion Auto-Seal", "CWE-400", "warning"},
		"LH-KMS-010": {"Missing Hash-Chained Tamper-Evident Audit Log", "CWE-778", "note"},
	}

	var rules []SarifRule
	for id, meta := range ruleCatalog {
		rules = append(rules, SarifRule{
			ID:               id,
			Name:             meta.title,
			ShortDescription: SarifMessage{Text: meta.title},
			FullDescription:  SarifMessage{Text: fmt.Sprintf("%s (%s)", meta.title, meta.cwe)},
			DefaultConfiguration: SarifRuleConfiguration{
				Level: meta.level,
			},
			Properties: map[string]interface{}{
				"cwe": meta.cwe,
			},
		})
	}

	var results []SarifResult
	for _, f := range report.Findings {
		level := "warning"
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			level = "error"
		} else if f.Severity == "LOW" {
			level = "note"
		}

		results = append(results, SarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: SarifMessage{
				Text: fmt.Sprintf("[%s] %s: %s (Recommendation: %s)", f.RuleID, f.Title, f.Description, f.Recommendation),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifLocationDetail{
							URI: report.PolicyID,
						},
						Region: SarifRegion{
							StartLine: 1,
						},
					},
				},
			},
		})
	}

	sarif := SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "lh-kms",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sovereign-kms-lite",
						Rules:          rules,
					},
				},
				Artifacts: []SarifTarget{
					{
						Location: SarifLocationDetail{
							URI: report.PolicyID,
						},
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
