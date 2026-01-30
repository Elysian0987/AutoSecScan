package utils

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
)

// ValidateAndParseURL validates a URL and returns structured target information
func ValidateAndParseURL(rawURL string) (*models.TargetInfo, error) {
	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported protocol: %s (only http/https allowed)", parsedURL.Scheme)
	}

	// Extract domain
	domain := parsedURL.Hostname()
	if domain == "" {
		return nil, fmt.Errorf("could not extract domain from URL")
	}

	// Determine port
	port := parsedURL.Port()
	portNum := 80
	if parsedURL.Scheme == "https" {
		portNum = 443
	}
	if port != "" {
		fmt.Sscanf(port, "%d", &portNum)
	}

	// Resolve IP address
	ipAddr, err := resolveIP(domain)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Check reachability
	if err := checkReachability(rawURL); err != nil {
		return nil, fmt.Errorf("target unreachable: %w", err)
	}

	target := &models.TargetInfo{
		URL:      rawURL,
		Domain:   domain,
		IP:       ipAddr,
		Protocol: parsedURL.Scheme,
		Port:     portNum,
	}

	return target, nil
}

// resolveIP performs DNS resolution
func resolveIP(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain")
	}

	// Return first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// Fallback to first IP (might be IPv6)
	return ips[0].String(), nil
}

// checkReachability tests if the target is reachable
func checkReachability(targetURL string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// SanitizeURL removes sensitive information from URLs for logging
func SanitizeURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove user info (username:password)
	parsedURL.User = nil

	// Remove query parameters that might contain sensitive data
	query := parsedURL.Query()
	for key := range query {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "token") ||
			strings.Contains(lowerKey, "key") ||
			strings.Contains(lowerKey, "secret") ||
			strings.Contains(lowerKey, "password") {
			query.Set(key, "[REDACTED]")
		}
	}
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}
