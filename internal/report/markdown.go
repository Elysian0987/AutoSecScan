package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/internal/scanner"
)

// GenerateMarkdown creates a markdown security report
func GenerateMarkdown(result *models.ScanResult, filename string) error {
	report := buildMarkdownReport(result)

	// Write to file
	if err := os.WriteFile(filename, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write markdown report: %w", err)
	}

	return nil
}

// GetMarkdownString returns the markdown report as a string
func GetMarkdownString(result *models.ScanResult) string {
	return buildMarkdownReport(result)
}

func buildMarkdownReport(result *models.ScanResult) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# 🔒 Security Audit Report\n\n")

	// Metadata
	sb.WriteString("## 📋 Scan Information\n\n")
	sb.WriteString(fmt.Sprintf("- **Target URL**: %s\n", result.Target.URL))
	sb.WriteString(fmt.Sprintf("- **Domain**: %s\n", result.Target.Domain))
	sb.WriteString(fmt.Sprintf("- **IP Address**: %s\n", result.Target.IP))
	sb.WriteString(fmt.Sprintf("- **Scan Date**: %s\n", result.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **Duration**: %v\n", result.EndTime.Sub(result.StartTime).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("- **Risk Level**: **%s** %s\n\n", result.RiskLevel, getRiskEmoji(result.RiskLevel)))

	// Executive Summary
	sb.WriteString("## 📊 Executive Summary\n\n")
	sb.WriteString(buildExecutiveSummary(result))

	// Security Headers
	if result.HeaderResults != nil {
		sb.WriteString("\n## 🛡️ Security Headers Analysis\n\n")
		sb.WriteString(fmt.Sprintf("**Overall Score**: %d/100\n\n", result.HeaderResults.SecurityScore))

		if len(result.HeaderResults.MissingHeaders) > 0 {
			sb.WriteString("### ❌ Missing Headers\n\n")
			sb.WriteString("| Header | Severity | Description |\n")
			sb.WriteString("|--------|----------|-------------|\n")
			for _, header := range result.HeaderResults.MissingHeaders {
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n",
					header.Name, strings.ToUpper(header.Severity), header.Description))
			}
			sb.WriteString("\n")
		}

		if len(result.HeaderResults.WeakHeaders) > 0 {
			sb.WriteString("### ⚠️ Weak Headers\n\n")
			sb.WriteString("| Header | Value | Issue |\n")
			sb.WriteString("|--------|-------|-------|\n")
			for _, header := range result.HeaderResults.WeakHeaders {
				sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n",
					header.Name, truncate(header.Value, 50), header.Description))
			}
			sb.WriteString("\n")
		}

		if len(result.HeaderResults.PresentHeaders) > 0 {
			sb.WriteString("### ✅ Present Headers\n\n")
			for _, header := range result.HeaderResults.PresentHeaders {
				sb.WriteString(fmt.Sprintf("- **%s**: `%s`\n", header.Name, truncate(header.Value, 80)))
			}
			sb.WriteString("\n")
		}

		// Recommendations
		recommendations := scanner.GetHeaderRecommendations(result.HeaderResults)
		if len(recommendations) > 0 {
			sb.WriteString("#### 💡 Recommendations\n\n")
			for _, rec := range recommendations {
				sb.WriteString(fmt.Sprintf("- %s\n", rec))
			}
			sb.WriteString("\n")
		}
	}

	// TLS/SSL Analysis
	if result.TLSResults != nil {
		sb.WriteString("## 🔐 TLS/SSL Configuration\n\n")
		sb.WriteString(fmt.Sprintf("**Security Score**: %d/100\n\n", result.TLSResults.Score))

		status := "✅ Secure"
		if !result.TLSResults.IsSecure {
			status = "❌ Insecure"
		}
		sb.WriteString(fmt.Sprintf("**Status**: %s\n\n", status))

		sb.WriteString("### Configuration Details\n\n")
		sb.WriteString(fmt.Sprintf("- **Protocol Version**: %s\n", result.TLSResults.Protocol))
		sb.WriteString(fmt.Sprintf("- **Cipher Suite**: %s\n\n", result.TLSResults.CipherSuite))

		if result.TLSResults.Certificate.Subject != "" {
			sb.WriteString("### 📜 Certificate Information\n\n")
			sb.WriteString(fmt.Sprintf("- **Subject**: %s\n", result.TLSResults.Certificate.Subject))
			sb.WriteString(fmt.Sprintf("- **Issuer**: %s\n", result.TLSResults.Certificate.Issuer))
			sb.WriteString(fmt.Sprintf("- **Valid From**: %s\n", result.TLSResults.Certificate.ValidFrom.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Valid To**: %s\n", result.TLSResults.Certificate.ValidTo.Format("2006-01-02")))

			if result.TLSResults.Certificate.IsExpired {
				sb.WriteString("- **Status**: ❌ **EXPIRED**\n\n")
			} else {
				sb.WriteString(fmt.Sprintf("- **Days Until Expiry**: %d\n\n", result.TLSResults.Certificate.DaysToExpiry))
			}
		}

		if len(result.TLSResults.Vulnerabilities) > 0 {
			sb.WriteString("### 🚨 Detected Vulnerabilities\n\n")
			for _, vuln := range result.TLSResults.Vulnerabilities {
				sb.WriteString(fmt.Sprintf("- %s\n", vuln))
			}
			sb.WriteString("\n")
		}

		recommendations := scanner.GetTLSRecommendations(result.TLSResults)
		if len(recommendations) > 0 {
			sb.WriteString("#### 💡 Recommendations\n\n")
			for _, rec := range recommendations {
				sb.WriteString(fmt.Sprintf("- %s\n", rec))
			}
			sb.WriteString("\n")
		}
	}

	// SQL Injection Vulnerabilities
	if len(result.SQLiResults) > 0 {
		sb.WriteString("## 💉 SQL Injection Vulnerabilities\n\n")
		sb.WriteString(fmt.Sprintf("**Found**: %d vulnerabilities\n\n", len(result.SQLiResults)))

		sb.WriteString("| Severity | Location | Payload | Evidence |\n")
		sb.WriteString("|----------|----------|---------|----------|\n")
		for _, vuln := range result.SQLiResults {
			sb.WriteString(fmt.Sprintf("| %s %s | %s | `%s` | %s |\n",
				getSeverityEmoji(vuln.Severity), strings.ToUpper(vuln.Severity),
				vuln.Location, truncate(vuln.Payload, 30), truncate(vuln.Evidence, 40)))
		}
		sb.WriteString("\n")

		recommendations := scanner.GetSQLiRecommendations(result.SQLiResults)
		if len(recommendations) > 0 {
			sb.WriteString("### 💡 Remediation Steps\n\n")
			for i, rec := range recommendations {
				sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			sb.WriteString("\n")
		}
	}

	// XSS Vulnerabilities
	if len(result.XSSResults) > 0 {
		sb.WriteString("## 🎯 Cross-Site Scripting (XSS) Vulnerabilities\n\n")
		sb.WriteString(fmt.Sprintf("**Found**: %d vulnerabilities\n\n", len(result.XSSResults)))

		sb.WriteString("| Severity | Location | Payload | Evidence |\n")
		sb.WriteString("|----------|----------|---------|----------|\n")
		for _, vuln := range result.XSSResults {
			sb.WriteString(fmt.Sprintf("| %s %s | %s | `%s` | %s |\n",
				getSeverityEmoji(vuln.Severity), strings.ToUpper(vuln.Severity),
				vuln.Location, truncate(vuln.Payload, 30), truncate(vuln.Evidence, 40)))
		}
		sb.WriteString("\n")

		recommendations := scanner.GetXSSRecommendations(result.XSSResults)
		if len(recommendations) > 0 {
			sb.WriteString("### 💡 Remediation Steps\n\n")
			for i, rec := range recommendations {
				sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			sb.WriteString("\n")
		}
	}

	// Port Scan Results
	if result.NmapResults != nil && len(result.NmapResults.OpenPorts) > 0 {
		sb.WriteString("## 🔌 Open Ports\n\n")
		sb.WriteString(fmt.Sprintf("**Scan Duration**: %v\n\n", result.NmapResults.Duration.Round(time.Second)))

		sb.WriteString("| Port | Protocol | State | Service | Version |\n")
		sb.WriteString("|------|----------|-------|---------|----------|\n")
		for _, port := range result.NmapResults.OpenPorts {
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
				port.Number, port.Protocol, port.State, port.Service, truncate(port.Version, 30)))
		}
		sb.WriteString("\n")
	}

	// Overall Recommendations
	sb.WriteString("## 🎯 Priority Actions\n\n")
	sb.WriteString(buildPriorityActions(result))

	// Footer
	sb.WriteString("\n---\n\n")
	sb.WriteString("*Report generated by AutoSecScan v1.0.0*\n")
	sb.WriteString(fmt.Sprintf("*Scan completed on %s*\n", time.Now().Format("2006-01-02 15:04:05")))

	return sb.String()
}

func buildExecutiveSummary(result *models.ScanResult) string {
	var sb strings.Builder

	totalVulns := len(result.SQLiResults) + len(result.XSSResults)

	if totalVulns == 0 && result.HeaderResults != nil && result.HeaderResults.SecurityScore > 70 &&
		result.TLSResults != nil && result.TLSResults.IsSecure {
		sb.WriteString("✅ **Good Security Posture**: No critical vulnerabilities detected. ")
		sb.WriteString("The target demonstrates good security practices.\n\n")
	} else {
		sb.WriteString("⚠️ **Security Issues Detected**: ")
		sb.WriteString(fmt.Sprintf("Found %d vulnerabilities requiring attention.\n\n", totalVulns))
	}

	sb.WriteString("### Quick Stats\n\n")
	if result.HeaderResults != nil {
		sb.WriteString(fmt.Sprintf("- **Security Headers**: %d/100 score\n", result.HeaderResults.SecurityScore))
	}
	if result.TLSResults != nil {
		sb.WriteString(fmt.Sprintf("- **TLS/SSL**: %d/100 score\n", result.TLSResults.Score))
	}
	sb.WriteString(fmt.Sprintf("- **SQL Injection**: %d vulnerabilities\n", len(result.SQLiResults)))
	sb.WriteString(fmt.Sprintf("- **XSS**: %d vulnerabilities\n", len(result.XSSResults)))
	if result.NmapResults != nil {
		sb.WriteString(fmt.Sprintf("- **Open Ports**: %d\n", len(result.NmapResults.OpenPorts)))
	}

	return sb.String()
}

func buildPriorityActions(result *models.ScanResult) string {
	var sb strings.Builder
	priority := 1

	// Critical vulnerabilities first
	criticalCount := 0
	for _, v := range result.SQLiResults {
		if v.Severity == "critical" {
			criticalCount++
		}
	}
	for _, v := range result.XSSResults {
		if v.Severity == "critical" {
			criticalCount++
		}
	}

	if criticalCount > 0 {
		sb.WriteString(fmt.Sprintf("%d. 🚨 **CRITICAL**: Fix %d critical vulnerabilities immediately\n", priority, criticalCount))
		priority++
	}

	if len(result.SQLiResults) > 0 {
		sb.WriteString(fmt.Sprintf("%d. 💉 Implement parameterized queries to prevent SQL injection\n", priority))
		priority++
	}

	if len(result.XSSResults) > 0 {
		sb.WriteString(fmt.Sprintf("%d. 🎯 Add proper input validation and output encoding for XSS prevention\n", priority))
		priority++
	}

	if result.TLSResults != nil && !result.TLSResults.IsSecure {
		sb.WriteString(fmt.Sprintf("%d. 🔐 Upgrade TLS configuration to TLS 1.3 with strong ciphers\n", priority))
		priority++
	}

	if result.HeaderResults != nil && result.HeaderResults.SecurityScore < 50 {
		sb.WriteString(fmt.Sprintf("%d. 🛡️ Implement missing security headers (HSTS, CSP, X-Frame-Options)\n", priority))
		priority++
	}

	if priority == 1 {
		sb.WriteString("✅ No immediate priority actions required. Continue monitoring security posture.\n")
	}

	return sb.String()
}

func getRiskEmoji(risk string) string {
	switch risk {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

func getSeverityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
