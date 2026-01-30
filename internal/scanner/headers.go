package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/pkg/utils"
)

// SecurityHeaderDefinition defines expected security headers
type SecurityHeaderDefinition struct {
	Name        string
	Description string
	Severity    string
}

var securityHeaders = []SecurityHeaderDefinition{
	{
		Name:        "Strict-Transport-Security",
		Description: "Enforces secure HTTPS connections",
		Severity:    "high",
	},
	{
		Name:        "Content-Security-Policy",
		Description: "Prevents XSS and data injection attacks",
		Severity:    "high",
	},
	{
		Name:        "X-Frame-Options",
		Description: "Prevents clickjacking attacks",
		Severity:    "medium",
	},
	{
		Name:        "X-Content-Type-Options",
		Description: "Prevents MIME-type sniffing",
		Severity:    "medium",
	},
	{
		Name:        "Referrer-Policy",
		Description: "Controls referrer information",
		Severity:    "low",
	},
	{
		Name:        "Permissions-Policy",
		Description: "Controls browser features and APIs",
		Severity:    "medium",
	},
	{
		Name:        "X-XSS-Protection",
		Description: "Legacy XSS filter (deprecated but still useful)",
		Severity:    "low",
	},
}

// ScanHeaders analyzes HTTP security headers
func ScanHeaders(target *models.TargetInfo) (*models.HeaderScan, error) {
	utils.Debug("Starting security headers scan for %s", target.URL)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Make HEAD request first (lighter), fallback to GET if needed
	resp, err := client.Head(target.URL)
	if err != nil || resp.StatusCode >= 400 {
		utils.Debug("HEAD request failed, trying GET: %v", err)
		resp, err = client.Get(target.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	}
	defer resp.Body.Close()

	utils.Debug("Response status: %d", resp.StatusCode)

	scan := &models.HeaderScan{
		Headers:        make(map[string]string),
		MissingHeaders: []models.SecurityHeader{},
		WeakHeaders:    []models.SecurityHeader{},
		PresentHeaders: []models.SecurityHeader{},
		SecurityScore:  0,
	}

	// Store all headers
	for key, values := range resp.Header {
		scan.Headers[key] = strings.Join(values, "; ")
	}

	// Analyze security headers
	for _, headerDef := range securityHeaders {
		value, exists := resp.Header[headerDef.Name]
		
		if !exists {
			scan.MissingHeaders = append(scan.MissingHeaders, models.SecurityHeader{
				Name:        headerDef.Name,
				Value:       "",
				Status:      "missing",
				Severity:    headerDef.Severity,
				Description: headerDef.Description,
			})
		} else {
			headerValue := strings.Join(value, "; ")
			
			// Check if header value is weak
			if isWeakHeader(headerDef.Name, headerValue) {
				scan.WeakHeaders = append(scan.WeakHeaders, models.SecurityHeader{
					Name:        headerDef.Name,
					Value:       headerValue,
					Status:      "weak",
					Severity:    headerDef.Severity,
					Description: headerDef.Description + " (weak configuration)",
				})
			} else {
				scan.PresentHeaders = append(scan.PresentHeaders, models.SecurityHeader{
					Name:        headerDef.Name,
					Value:       headerValue,
					Status:      "present",
					Severity:    "info",
					Description: headerDef.Description,
				})
				// Award points for present headers
				scan.SecurityScore += 15
			}
		}
	}

	// Calculate final score (0-100)
	maxScore := len(securityHeaders) * 15
	if scan.SecurityScore > maxScore {
		scan.SecurityScore = maxScore
	}

	// Convert to percentage
	scan.SecurityScore = (scan.SecurityScore * 100) / maxScore

	utils.Info("Security headers scan completed: Score %d/100, %d missing, %d weak, %d present",
		scan.SecurityScore, len(scan.MissingHeaders), len(scan.WeakHeaders), len(scan.PresentHeaders))

	return scan, nil
}

// isWeakHeader checks if a header value is considered weak
func isWeakHeader(name, value string) bool {
	lowerValue := strings.ToLower(value)

	switch name {
	case "Strict-Transport-Security":
		// Check for sufficient max-age (at least 6 months)
		if !strings.Contains(lowerValue, "max-age=") {
			return true
		}
		// Weak if max-age is less than 15552000 (6 months)
		if strings.Contains(lowerValue, "max-age=") {
			maxAge := extractMaxAge(lowerValue)
			if maxAge < 15552000 {
				return true
			}
		}

	case "Content-Security-Policy":
		// Weak if using 'unsafe-inline' or 'unsafe-eval'
		if strings.Contains(lowerValue, "unsafe-inline") || strings.Contains(lowerValue, "unsafe-eval") {
			return true
		}
		// Weak if using wildcard '*'
		if strings.Contains(lowerValue, "*") && !strings.Contains(lowerValue, "'*'") {
			return true
		}

	case "X-Frame-Options":
		// Weak if set to ALLOW
		if strings.Contains(lowerValue, "allow") {
			return true
		}

	case "X-XSS-Protection":
		// Weak if set to 0 (disabled)
		if strings.Contains(lowerValue, "0") {
			return true
		}
	}

	return false
}

// extractMaxAge extracts max-age value from HSTS header
func extractMaxAge(value string) int {
	parts := strings.Split(value, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			var maxAge int
			fmt.Sscanf(part, "max-age=%d", &maxAge)
			return maxAge
		}
	}
	return 0
}

// GetHeaderRecommendations returns recommendations for missing/weak headers
func GetHeaderRecommendations(scan *models.HeaderScan) []string {
	recommendations := []string{}

	for _, header := range scan.MissingHeaders {
		switch header.Name {
		case "Strict-Transport-Security":
			recommendations = append(recommendations, 
				"Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
		case "Content-Security-Policy":
			recommendations = append(recommendations,
				"Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'")
		case "X-Frame-Options":
			recommendations = append(recommendations,
				"Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking")
		case "X-Content-Type-Options":
			recommendations = append(recommendations,
				"Add X-Content-Type-Options: nosniff to prevent MIME sniffing")
		case "Referrer-Policy":
			recommendations = append(recommendations,
				"Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer")
		case "Permissions-Policy":
			recommendations = append(recommendations,
				"Add Permissions-Policy to control browser features")
		}
	}

	for _, header := range scan.WeakHeaders {
		recommendations = append(recommendations,
			fmt.Sprintf("Strengthen %s: Current value is weak", header.Name))
	}

	return recommendations
}
