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

// XSS test payloads
var xssPayloads = []struct {
	payload     string
	pattern     string
	description string
}{
	{
		payload:     "<script>alert('XSS')</script>",
		pattern:     "<script>alert('xss')</script>",
		description: "Basic script injection",
	},
	{
		payload:     "<img src=x onerror=alert('XSS')>",
		pattern:     "<img src=x onerror=alert('xss')>",
		description: "Image tag with onerror handler",
	},
	{
		payload:     "<svg/onload=alert('XSS')>",
		pattern:     "<svg/onload=alert('xss')>",
		description: "SVG with onload handler",
	},
	{
		payload:     "\"><script>alert('XSS')</script>",
		pattern:     "\"><script>alert('xss')</script>",
		description: "Breaking out of attribute",
	},
	{
		payload:     "javascript:alert('XSS')",
		pattern:     "javascript:alert('xss')",
		description: "JavaScript protocol handler",
	},
	{
		payload:     "<iframe src=javascript:alert('XSS')>",
		pattern:     "<iframe src=javascript:alert('xss')>",
		description: "Iframe with JavaScript URL",
	},
	{
		payload:     "<body onload=alert('XSS')>",
		pattern:     "<body onload=alert('xss')>",
		description: "Body tag with onload",
	},
	{
		payload:     "<input onfocus=alert('XSS') autofocus>",
		pattern:     "<input onfocus=alert('xss') autofocus>",
		description: "Input with autofocus",
	},
	{
		payload:     "<marquee onstart=alert('XSS')>",
		pattern:     "<marquee onstart=alert('xss')>",
		description: "Marquee tag exploitation",
	},
	{
		payload:     "<details open ontoggle=alert('XSS')>",
		pattern:     "<details open ontoggle=alert('xss')>",
		description: "Details tag with ontoggle",
	},
}

// ScanXSS performs Cross-Site Scripting vulnerability scanning
func ScanXSS(target *models.TargetInfo) ([]models.Vulnerability, error) {
	utils.Debug("Starting XSS scan for %s", target.URL)

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
			"q":       {"test"},
			"search":  {"test"},
			"query":   {"test"},
			"keyword": {"test"},
			"name":    {"test"},
			"comment": {"test"},
			"message": {"test"},
			"input":   {"test"},
		}
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test each parameter with each payload
	for paramName := range queryParams {
		utils.Debug("Testing parameter: %s", paramName)

		for _, payloadInfo := range xssPayloads {
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

			// Check if payload appears unescaped in response
			if strings.Contains(bodyStr, payloadInfo.pattern) {
				utils.Warn("XSS vulnerability detected in parameter '%s'", paramName)
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        "xss",
					Severity:    "high",
					Location:    fmt.Sprintf("Parameter: %s", paramName),
					Payload:     payloadInfo.payload,
					Evidence:    "Payload reflected unescaped in response",
					Description: fmt.Sprintf("%s - Payload found in response without proper encoding", payloadInfo.description),
				})
				break // Found vulnerability, move to next parameter
			}

			// Check for partial reflection (encoded but potentially bypassable)
			if checkPartialReflection(bodyStr, payloadInfo.payload) {
				utils.Warn("Potential XSS (partial reflection) in parameter '%s'", paramName)
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Type:        "xss",
					Severity:    "medium",
					Location:    fmt.Sprintf("Parameter: %s", paramName),
					Payload:     payloadInfo.payload,
					Evidence:    "Payload partially reflected, may be bypassable",
					Description: fmt.Sprintf("%s - Input reflected with partial encoding", payloadInfo.description),
				})
				break
			}

			// Small delay to avoid overwhelming the server
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Test for DOM-based XSS indicators
	testDOMXSS(client, target, &vulnerabilities)

	utils.Info("XSS scan completed: found %d potential vulnerabilities", len(vulnerabilities))

	return vulnerabilities, nil
}

// checkPartialReflection checks if payload is partially reflected
func checkPartialReflection(body, payload string) bool {
	// Remove tags to see if content is reflected
	cleanPayload := strings.ReplaceAll(payload, "<", "")
	cleanPayload = strings.ReplaceAll(cleanPayload, ">", "")
	cleanPayload = strings.ReplaceAll(cleanPayload, "'", "")
	cleanPayload = strings.ReplaceAll(cleanPayload, "\"", "")
	cleanPayload = strings.ToLower(cleanPayload)

	// If the "alert" or "xss" part is reflected, it's suspicious
	if strings.Contains(cleanPayload, "alert") && strings.Contains(body, "alert") {
		return true
	}
	if strings.Contains(cleanPayload, "xss") && strings.Contains(body, "xss") {
		return true
	}

	return false
}

// testDOMXSS looks for potential DOM-based XSS vulnerabilities
func testDOMXSS(client *http.Client, target *models.TargetInfo, vulnerabilities *[]models.Vulnerability) {
	parsedURL, _ := url.Parse(target.URL)

	// Test for hash-based reflection (DOM XSS)
	testURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + "#<script>alert('XSS')</script>"

	resp, err := client.Get(testURL)
	if err != nil {
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := strings.ToLower(string(body))

	// Look for dangerous JavaScript patterns that might use location.hash
	dangerousPatterns := []string{
		"location.hash",
		"window.location.hash",
		"document.location.hash",
		"location.href",
		"document.write(",
		"eval(",
		"innerhtml",
		"outerhtml",
	}

	foundDangerous := false
	dangerousPattern := ""
	for _, pattern := range dangerousPatterns {
		if strings.Contains(bodyStr, pattern) {
			foundDangerous = true
			dangerousPattern = pattern
			break
		}
	}

	if foundDangerous {
		utils.Warn("Potential DOM-based XSS vulnerability detected")
		*vulnerabilities = append(*vulnerabilities, models.Vulnerability{
			Type:        "xss",
			Severity:    "medium",
			Location:    "DOM (client-side JavaScript)",
			Payload:     "DOM manipulation pattern detected",
			Evidence:    fmt.Sprintf("Found dangerous pattern: %s", dangerousPattern),
			Description: "Page uses potentially unsafe DOM manipulation that could lead to XSS",
		})
	}
}

// GetXSSRecommendations returns remediation recommendations
func GetXSSRecommendations(vulnerabilities []models.Vulnerability) []string {
	if len(vulnerabilities) == 0 {
		return []string{}
	}

	recommendations := []string{
		"Implement proper output encoding based on context (HTML, JavaScript, URL, CSS)",
		"Use Content-Security-Policy (CSP) headers to mitigate XSS impact",
		"Validate and sanitize all user input on the server side",
		"Use security-focused template engines with auto-escaping",
		"Avoid using dangerous functions like eval(), innerHTML, document.write()",
		"Set HttpOnly flag on cookies to prevent JavaScript access",
		"Use DOM-based APIs like textContent instead of innerHTML when possible",
		"Implement input validation with whitelist approach",
		"Regular security testing and code reviews",
	}

	// Add specific recommendations based on vulnerability types
	hasDOMXSS := false
	for _, vuln := range vulnerabilities {
		if strings.Contains(vuln.Location, "DOM") {
			hasDOMXSS = true
			break
		}
	}

	if hasDOMXSS {
		recommendations = append(recommendations,
			"Review all client-side JavaScript for unsafe DOM manipulation",
			"Avoid using location.hash, location.search directly without sanitization")
	}

	return recommendations
}
