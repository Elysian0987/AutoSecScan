package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/pkg/utils"
)

// SQL injection test payloads
var sqliPayloads = []struct {
	payload     string
	description string
}{
	{"'", "Single quote test"},
	{"' OR '1'='1", "Classic OR bypass"},
	{"' OR '1'='1' --", "OR bypass with comment"},
	{"' OR 1=1 --", "Numeric OR bypass"},
	{"admin' --", "Comment injection"},
	{"' UNION SELECT NULL--", "UNION injection test"},
	{"1' AND '1'='2", "False condition test"},
	{"'; DROP TABLE users--", "Destructive command test"},
	{"' OR 'x'='x", "Alternative OR bypass"},
	{"1' ORDER BY 1--", "ORDER BY enumeration"},
}

// SQL error patterns that indicate vulnerability
var sqlErrorPatterns = []string{
	"sql syntax",
	"mysql_fetch",
	"mysql_num_rows",
	"mysqli",
	"sqlexception",
	"postgresql",
	"sqlite",
	"oracle",
	"odbc",
	"mssql",
	"jdbc",
	"ora-",
	"pg_query",
	"pg_exec",
	"syntax error",
	"unterminated quoted string",
	"unclosed quotation mark",
	"error in your sql syntax",
	"you have an error in your sql",
}

// ScanSQLi performs SQL injection vulnerability scanning
func ScanSQLi(target *models.TargetInfo) ([]models.Vulnerability, error) {
	utils.Debug("Starting SQL injection scan for %s", target.URL)

	vulnerabilities := []models.Vulnerability{}

	// Parse URL to get query parameters
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	queryParams := parsedURL.Query()

	// If no query parameters, try common parameter names
	if len(queryParams) == 0 {
		utils.Debug("No query parameters found, testing common parameter names")
		queryParams = url.Values{
			"id":       {"1"},
			"user":     {"admin"},
			"page":     {"1"},
			"search":   {"test"},
			"q":        {"test"},
			"username": {"admin"},
		}
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get baseline response (normal request)
	baselineResp, err := client.Get(target.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to get baseline response: %w", err)
	}
	baselineBody, _ := io.ReadAll(baselineResp.Body)
	baselineResp.Body.Close()
	baselineLength := len(baselineBody)

	utils.Debug("Baseline response: status=%d, length=%d", baselineResp.StatusCode, baselineLength)

	// Test each parameter with each payload
	for paramName := range queryParams {
		utils.Debug("Testing parameter: %s", paramName)

		for _, payloadInfo := range sqliPayloads {
			testParams := cloneURLValues(queryParams)
			testParams.Set(paramName, payloadInfo.payload)

			testURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + "?" + testParams.Encode()

			resp, err := client.Get(testURL)
			if err != nil {
				utils.Debug("Request failed for payload '%s': %v", payloadInfo.payload, err)
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := strings.ToLower(string(body))

			// Check for SQL errors in response
			sqlError := detectSQLError(bodyStr)
			if sqlError != "" {
				utils.Warn("SQL injection vulnerability detected in parameter '%s'", paramName)
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        "sqli",
					Severity:    "critical",
					Location:    fmt.Sprintf("Parameter: %s", paramName),
					Payload:     payloadInfo.payload,
					Evidence:    fmt.Sprintf("SQL error detected: %s", sqlError),
					Description: fmt.Sprintf("%s - SQL error exposed", payloadInfo.description),
				})
				break // Found vulnerability, no need to test more payloads for this param
			}

			// Check for significant response differences (time-based or boolean-based)
			if detectBehaviorChange(baselineResp.StatusCode, resp.StatusCode, baselineLength, len(body)) {
				utils.Warn("Potential SQL injection (behavior change) in parameter '%s'", paramName)
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        "sqli",
					Severity:    "high",
					Location:    fmt.Sprintf("Parameter: %s", paramName),
					Payload:     payloadInfo.payload,
					Evidence:    fmt.Sprintf("Response behavior changed: baseline=%d bytes, test=%d bytes", baselineLength, len(body)),
					Description: fmt.Sprintf("%s - Response indicates potential SQL injection", payloadInfo.description),
				})
				break
			}

			// Small delay to avoid overwhelming the server
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Also test path parameters if URL has path segments
	if len(parsedURL.Path) > 1 {
		testPathInjection(client, target, &vulnerabilities)
	}

	utils.Info("SQL injection scan completed: found %d potential vulnerabilities", len(vulnerabilities))

	return vulnerabilities, nil
}

// detectSQLError checks if response contains SQL error messages
func detectSQLError(body string) string {
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(body, pattern) {
			return pattern
		}
	}
	return ""
}

// detectBehaviorChange detects significant differences in response
func detectBehaviorChange(baselineStatus, testStatus, baselineLength, testLength int) bool {
	// Status code changed
	if baselineStatus != testStatus {
		return true
	}

	// Significant length difference (more than 10%)
	lengthDiff := float64(testLength-baselineLength) / float64(baselineLength)
	if lengthDiff > 0.1 || lengthDiff < -0.1 {
		return true
	}

	return false
}

// testPathInjection tests for SQL injection in URL path
func testPathInjection(client *http.Client, target *models.TargetInfo, vulnerabilities *[]models.Vulnerability) {
	parsedURL, _ := url.Parse(target.URL)
	basePath := parsedURL.Path

	// Test a few simple payloads in the path
	pathPayloads := []string{"'", "' OR '1'='1"}

	for _, payload := range pathPayloads {
		testPath := basePath + "/" + url.PathEscape(payload)
		testURL := parsedURL.Scheme + "://" + parsedURL.Host + testPath

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := strings.ToLower(string(body))

		if sqlError := detectSQLError(bodyStr); sqlError != "" {
			*vulnerabilities = append(*vulnerabilities, models.Vulnerability{
				Type:        "sqli",
				Severity:    "critical",
				Location:    "URL Path",
				Payload:     payload,
				Evidence:    fmt.Sprintf("SQL error detected: %s", sqlError),
				Description: "SQL injection in URL path",
			})
			break
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// cloneURLValues creates a copy of url.Values
func cloneURLValues(v url.Values) url.Values {
	clone := url.Values{}
	for key, values := range v {
		clone[key] = append([]string{}, values...)
	}
	return clone
}

// GetSQLiRecommendations returns remediation recommendations
func GetSQLiRecommendations(vulnerabilities []models.Vulnerability) []string {
	if len(vulnerabilities) == 0 {
		return []string{}
	}

	return []string{
		"Use parameterized queries (prepared statements) for all database operations",
		"Implement input validation and sanitization",
		"Use ORM frameworks that handle SQL escaping automatically",
		"Apply principle of least privilege to database accounts",
		"Enable WAF (Web Application Firewall) with SQL injection rules",
		"Never concatenate user input directly into SQL queries",
		"Implement proper error handling (don't expose SQL errors to users)",
		"Regular security audits and penetration testing",
	}
}
