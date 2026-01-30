package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanTLS(t *testing.T) {
	// Create a test HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract host from server URL
	serverURL := server.URL

	// Scan TLS
	result := ScanTLS(serverURL)

	// Verify result is not nil
	if result == nil {
		t.Fatal("ScanTLS() returned nil")
	}

	// Basic checks
	if result.Protocol == "" {
		t.Error("TLS protocol should not be empty")
	}

	if result.CipherSuite == "" {
		t.Error("TLS cipher suite should not be empty")
	}
}

func TestCheckCertificateExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantExpiry bool
		wantDays   int
	}{
		{
			name:       "Valid certificate - expires in 100 days",
			notBefore:  now.AddDate(0, 0, -10),
			notAfter:   now.AddDate(0, 0, 100),
			wantExpiry: false,
			wantDays:   100,
		},
		{
			name:       "Expired certificate",
			notBefore:  now.AddDate(0, 0, -100),
			notAfter:   now.AddDate(0, 0, -10),
			wantExpiry: true,
			wantDays:   -10,
		},
		{
			name:       "Expires today",
			notBefore:  now.AddDate(0, 0, -30),
			notAfter:   now,
			wantExpiry: false,
			wantDays:   0,
		},
		{
			name:       "Expires in 1 day",
			notBefore:  now.AddDate(0, 0, -30),
			notAfter:   now.AddDate(0, 0, 1),
			wantExpiry: false,
			wantDays:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			isExpired, daysUntilExpiry := checkCertificateExpiry(cert)

			if isExpired != tt.wantExpiry {
				t.Errorf("isExpired = %v, want %v", isExpired, tt.wantExpiry)
			}

			// Allow 1 day tolerance for timing differences
			if daysUntilExpiry < tt.wantDays-1 || daysUntilExpiry > tt.wantDays+1 {
				t.Errorf("daysUntilExpiry = %d, want approximately %d", daysUntilExpiry, tt.wantDays)
			}
		})
	}
}

func TestIssueToVulnerability(t *testing.T) {
	tests := []struct {
		name         string
		issue        string
		wantSeverity string
	}{
		{
			name:         "Certificate expired",
			issue:        "Certificate expired",
			wantSeverity: "HIGH",
		},
		{
			name:         "Certificate expires soon",
			issue:        "Certificate expires in 5 days",
			wantSeverity: "MEDIUM",
		},
		{
			name:         "Weak cipher",
			issue:        "Weak cipher suite detected",
			wantSeverity: "HIGH",
		},
		{
			name:         "Self-signed certificate",
			issue:        "Self-signed certificate",
			wantSeverity: "MEDIUM",
		},
		{
			name:         "Other issue",
			issue:        "Some other issue",
			wantSeverity: "MEDIUM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := issueToVulnerability(tt.issue)

			if vuln.Severity != tt.wantSeverity {
				t.Errorf("Severity = %s, want %s", vuln.Severity, tt.wantSeverity)
			}

			if vuln.Description != tt.issue {
				t.Errorf("Description = %s, want %s", vuln.Description, tt.issue)
			}
		})
	}
}

func TestCheckVulnerabilities(t *testing.T) {
	tests := []struct {
		name          string
		protocol      string
		cipher        string
		wantVulnCount int
	}{
		{
			name:          "TLS 1.2 with strong cipher",
			protocol:      "TLS 1.2",
			cipher:        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			wantVulnCount: 0,
		},
		{
			name:          "TLS 1.3 with strong cipher",
			protocol:      "TLS 1.3",
			cipher:        "TLS_AES_256_GCM_SHA384",
			wantVulnCount: 0,
		},
		{
			name:          "SSL 3.0 - vulnerable to POODLE",
			protocol:      "SSL 3.0",
			cipher:        "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantVulnCount: 1,
		},
		{
			name:          "TLS 1.0 with CBC - vulnerable to BEAST",
			protocol:      "TLS 1.0",
			cipher:        "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantVulnCount: 1,
		},
		{
			name:          "Weak cipher - RC4",
			protocol:      "TLS 1.2",
			cipher:        "TLS_RSA_WITH_RC4_128_SHA",
			wantVulnCount: 1,
		},
		{
			name:          "Weak cipher - DES",
			protocol:      "TLS 1.1",
			cipher:        "TLS_RSA_WITH_DES_CBC_SHA",
			wantVulnCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connState := &tls.ConnectionState{
				Version:     getTLSVersion(tt.protocol),
				CipherSuite: getTLSCipher(tt.cipher),
			}

			issues := checkVulnerabilities(connState)

			if len(issues) != tt.wantVulnCount {
				t.Errorf("Vulnerability count = %d, want %d (issues: %v)", len(issues), tt.wantVulnCount, issues)
			}
		})
	}
}

// Helper functions for testing
func getTLSVersion(name string) uint16 {
	versions := map[string]uint16{
		"SSL 3.0": 0x0300,
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"TLS 1.2": tls.VersionTLS12,
		"TLS 1.3": tls.VersionTLS13,
	}
	if v, ok := versions[name]; ok {
		return v
	}
	return tls.VersionTLS12
}

func getTLSCipher(name string) uint16 {
	ciphers := map[string]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":              tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":          tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_DES_CBC_SHA":              0x0009,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_AES_256_GCM_SHA384":                tls.TLS_AES_256_GCM_SHA384,
	}
	if c, ok := ciphers[name]; ok {
		return c
	}
	return tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
}
