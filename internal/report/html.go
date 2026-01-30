package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/internal/scanner"
)

// TemplateData holds all data for HTML template
type TemplateData struct {
	Result           *models.ScanResult
	GeneratedAt      string
	RiskColor        string
	RiskEmoji        string
	HeaderScore      int
	TLSScore         int
	SQLiCount        int
	XSSCount         int
	OpenPortsCount   int
	TotalVulns       int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	HeaderRecs       []string
	TLSRecs          []string
	SQLiRecs         []string
	XSSRecs          []string
	PriorityActions  []string
}

// GenerateHTML creates an HTML security report
func GenerateHTML(result *models.ScanResult, filename string) error {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"truncate":        truncate,
		"upper":           strings.ToUpper,
		"severityColor":   getSeverityColor,
		"severityBadge":   getSeverityBadge,
	}).Parse(htmlTemplate))

	// Prepare template data
	data := prepareTemplateData(result)

	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	return nil
}

func prepareTemplateData(result *models.ScanResult) TemplateData {
	data := TemplateData{
		Result:      result,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		RiskColor:   getRiskColor(result.RiskLevel),
		RiskEmoji:   getRiskEmoji(result.RiskLevel),
	}

	// Calculate scores and counts
	if result.HeaderResults != nil {
		data.HeaderScore = result.HeaderResults.SecurityScore
		data.HeaderRecs = scanner.GetHeaderRecommendations(result.HeaderResults)
	}

	if result.TLSResults != nil {
		data.TLSScore = result.TLSResults.Score
		data.TLSRecs = scanner.GetTLSRecommendations(result.TLSResults)
	}

	data.SQLiCount = len(result.SQLiResults)
	data.XSSCount = len(result.XSSResults)
	data.SQLiRecs = scanner.GetSQLiRecommendations(result.SQLiResults)
	data.XSSRecs = scanner.GetXSSRecommendations(result.XSSResults)

	if result.NmapResults != nil {
		data.OpenPortsCount = len(result.NmapResults.OpenPorts)
	}

	// Count vulnerabilities by severity
	for _, vuln := range result.SQLiResults {
		data.TotalVulns++
		switch vuln.Severity {
		case "critical":
			data.CriticalCount++
		case "high":
			data.HighCount++
		case "medium":
			data.MediumCount++
		case "low":
			data.LowCount++
		}
	}

	for _, vuln := range result.XSSResults {
		data.TotalVulns++
		switch vuln.Severity {
		case "critical":
			data.CriticalCount++
		case "high":
			data.HighCount++
		case "medium":
			data.MediumCount++
		case "low":
			data.LowCount++
		}
	}

	// Build priority actions
	data.PriorityActions = buildPriorityActionsList(result, data.CriticalCount)

	return data
}

func buildPriorityActionsList(result *models.ScanResult, criticalCount int) []string {
	actions := []string{}

	if criticalCount > 0 {
		actions = append(actions, fmt.Sprintf("🚨 CRITICAL: Fix %d critical vulnerabilities immediately", criticalCount))
	}

	if len(result.SQLiResults) > 0 {
		actions = append(actions, "💉 Implement parameterized queries to prevent SQL injection")
	}

	if len(result.XSSResults) > 0 {
		actions = append(actions, "🎯 Add proper input validation and output encoding for XSS prevention")
	}

	if result.TLSResults != nil && !result.TLSResults.IsSecure {
		actions = append(actions, "🔐 Upgrade TLS configuration to TLS 1.3 with strong ciphers")
	}

	if result.HeaderResults != nil && result.HeaderResults.SecurityScore < 50 {
		actions = append(actions, "🛡️ Implement missing security headers (HSTS, CSP, X-Frame-Options)")
	}

	if len(actions) == 0 {
		actions = append(actions, "✅ No immediate priority actions required. Continue monitoring security posture.")
	}

	return actions
}

func getRiskColor(risk string) string {
	switch risk {
	case "CRITICAL":
		return "#dc3545"
	case "HIGH":
		return "#fd7e14"
	case "MEDIUM":
		return "#ffc107"
	case "LOW":
		return "#28a745"
	default:
		return "#6c757d"
	}
}

func getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "#dc3545"
	case "high":
		return "#fd7e14"
	case "medium":
		return "#ffc107"
	case "low":
		return "#28a745"
	default:
		return "#6c757d"
	}
}

func getSeverityBadge(severity string) string {
	color := getSeverityColor(severity)
	return fmt.Sprintf(`<span class="badge" style="background-color: %s;">%s</span>`, color, strings.ToUpper(severity))
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {{.Result.Target.Domain}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section-title {
            font-size: 1.8rem;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .info-card h3 {
            font-size: 0.9rem;
            color: #6c757d;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .info-card p {
            font-size: 1.3rem;
            font-weight: bold;
            color: #2c3e50;
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2rem;
            color: white;
            background-color: {{.RiskColor}};
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: bold;
            color: white;
        }
        .score {
            font-size: 3rem;
            font-weight: bold;
            color: #667eea;
        }
        .score-container {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .vulnerability-list {
            list-style: none;
        }
        .vulnerability-item {
            background: #fff5f5;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .recommendation-list {
            list-style: none;
            padding-left: 0;
        }
        .recommendation-list li {
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 4px;
        }
        .priority-actions {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .priority-actions h3 {
            color: #856404;
            margin-bottom: 15px;
        }
        .priority-actions ol {
            padding-left: 20px;
        }
        .priority-actions li {
            margin-bottom: 10px;
            color: #856404;
        }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9rem;
        }
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: white;
            border: 2px solid #e9ecef;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.9rem;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Audit Report</h1>
            <p>Comprehensive Security Assessment</p>
        </div>

        <div class="content">
            <!-- Scan Information -->
            <div class="section">
                <h2 class="section-title">📋 Scan Information</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h3>Target URL</h3>
                        <p>{{.Result.Target.URL}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Domain</h3>
                        <p>{{.Result.Target.Domain}}</p>
                    </div>
                    <div class="info-card">
                        <h3>IP Address</h3>
                        <p>{{.Result.Target.IP}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Scan Date</h3>
                        <p>{{.Result.StartTime.Format "2006-01-02 15:04"}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Duration</h3>
                        <p>{{.Result.EndTime.Sub .Result.StartTime}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Risk Level</h3>
                        <p><span class="risk-badge">{{.RiskEmoji}} {{.Result.RiskLevel}}</span></p>
                    </div>
                </div>
            </div>

            <!-- Executive Summary -->
            <div class="section">
                <h2 class="section-title">📊 Executive Summary</h2>
                <div class="stats-grid">
                    {{if .Result.HeaderResults}}
                    <div class="stat-box">
                        <div class="stat-number">{{.HeaderScore}}</div>
                        <div class="stat-label">Security Headers Score</div>
                    </div>
                    {{end}}
                    {{if .Result.TLSResults}}
                    <div class="stat-box">
                        <div class="stat-number">{{.TLSScore}}</div>
                        <div class="stat-label">TLS/SSL Score</div>
                    </div>
                    {{end}}
                    <div class="stat-box">
                        <div class="stat-number" style="color: #dc3545;">{{.SQLiCount}}</div>
                        <div class="stat-label">SQL Injection Vulns</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #fd7e14;">{{.XSSCount}}</div>
                        <div class="stat-label">XSS Vulnerabilities</div>
                    </div>
                    {{if .Result.NmapResults}}
                    <div class="stat-box">
                        <div class="stat-number">{{.OpenPortsCount}}</div>
                        <div class="stat-label">Open Ports</div>
                    </div>
                    {{end}}
                </div>

                {{if gt .TotalVulns 0}}
                <div class="priority-actions">
                    <h3>🎯 Priority Actions</h3>
                    <ol>
                        {{range .PriorityActions}}
                        <li>{{.}}</li>
                        {{end}}
                    </ol>
                </div>
                {{end}}
            </div>

            <!-- Security Headers -->
            {{if .Result.HeaderResults}}
            <div class="section">
                <h2 class="section-title">🛡️ Security Headers Analysis</h2>
                <div class="score-container">
                    <div class="score">{{.HeaderScore}}/100</div>
                    <p>Overall Security Headers Score</p>
                </div>

                {{if .Result.HeaderResults.MissingHeaders}}
                <h3 style="color: #dc3545; margin: 20px 0 10px 0;">❌ Missing Headers</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Result.HeaderResults.MissingHeaders}}
                        <tr>
                            <td><code>{{.Name}}</code></td>
                            <td>{{severityBadge .Severity}}</td>
                            <td>{{.Description}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
                {{end}}

                {{if .HeaderRecs}}
                <h3 style="margin: 20px 0 10px 0;">💡 Recommendations</h3>
                <ul class="recommendation-list">
                    {{range .HeaderRecs}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}

            <!-- TLS/SSL -->
            {{if .Result.TLSResults}}
            <div class="section">
                <h2 class="section-title">🔐 TLS/SSL Configuration</h2>
                <div class="score-container">
                    <div class="score">{{.TLSScore}}/100</div>
                    <p>TLS/SSL Security Score</p>
                </div>

                <div class="info-grid">
                    <div class="info-card">
                        <h3>Protocol Version</h3>
                        <p>{{.Result.TLSResults.Protocol}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Status</h3>
                        <p>{{if .Result.TLSResults.IsSecure}}✅ Secure{{else}}❌ Insecure{{end}}</p>
                    </div>
                    <div class="info-card">
                        <h3>Cipher Suite</h3>
                        <p style="font-size: 0.9rem;">{{truncate .Result.TLSResults.CipherSuite 30}}</p>
                    </div>
                </div>

                {{if .Result.TLSResults.Vulnerabilities}}
                <h3 style="color: #dc3545; margin: 20px 0 10px 0;">🚨 Detected Vulnerabilities</h3>
                <ul class="vulnerability-list">
                    {{range .Result.TLSResults.Vulnerabilities}}
                    <li class="vulnerability-item">{{.}}</li>
                    {{end}}
                </ul>
                {{end}}

                {{if .TLSRecs}}
                <h3 style="margin: 20px 0 10px 0;">💡 Recommendations</h3>
                <ul class="recommendation-list">
                    {{range .TLSRecs}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}

            <!-- SQL Injection -->
            {{if gt .SQLiCount 0}}
            <div class="section">
                <h2 class="section-title">💉 SQL Injection Vulnerabilities</h2>
                <p style="color: #dc3545; font-weight: bold; margin-bottom: 20px;">Found {{.SQLiCount}} vulnerabilities</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Payload</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Result.SQLiResults}}
                        <tr>
                            <td>{{severityBadge .Severity}}</td>
                            <td>{{.Location}}</td>
                            <td><code>{{truncate .Payload 40}}</code></td>
                            <td>{{truncate .Evidence 50}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>

                {{if .SQLiRecs}}
                <h3 style="margin: 20px 0 10px 0;">💡 Remediation Steps</h3>
                <ul class="recommendation-list">
                    {{range .SQLiRecs}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}

            <!-- XSS -->
            {{if gt .XSSCount 0}}
            <div class="section">
                <h2 class="section-title">🎯 Cross-Site Scripting (XSS)</h2>
                <p style="color: #fd7e14; font-weight: bold; margin-bottom: 20px;">Found {{.XSSCount}} vulnerabilities</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Payload</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Result.XSSResults}}
                        <tr>
                            <td>{{severityBadge .Severity}}</td>
                            <td>{{.Location}}</td>
                            <td><code>{{truncate .Payload 40}}</code></td>
                            <td>{{truncate .Evidence 50}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>

                {{if .XSSRecs}}
                <h3 style="margin: 20px 0 10px 0;">💡 Remediation Steps</h3>
                <ul class="recommendation-list">
                    {{range .XSSRecs}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}

            <!-- Open Ports -->
            {{if .Result.NmapResults}}
            {{if gt .OpenPortsCount 0}}
            <div class="section">
                <h2 class="section-title">🔌 Open Ports</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Result.NmapResults.OpenPorts}}
                        <tr>
                            <td><strong>{{.Number}}</strong></td>
                            <td>{{.Protocol}}</td>
                            <td>{{.State}}</td>
                            <td>{{.Service}}</td>
                            <td>{{truncate .Version 40}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
            {{end}}
        </div>

        <div class="footer">
            <p>Report generated by <strong>AutoSecScan v1.0.0</strong></p>
            <p>Scan completed on {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>`
