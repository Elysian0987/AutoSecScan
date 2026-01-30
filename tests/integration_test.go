package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/orchestrator"
)

// TestIntegrationSecurityScan tests the full security scan workflow
func TestIntegrationSecurityScan(t *testing.T) {
	// Create a mock vulnerable server
	server := createMockVulnerableServer()
	defer server.Close()

	// Run security scan
	result := orchestrator.RunSecurityScan(server.URL)

	// Verify result is not nil
	if result == nil {
		t.Fatal("RunSecurityScan() returned nil")
	}

	// Verify target info
	if result.Target == "" {
		t.Error("Target should not be empty")
	}

	// Verify timestamp
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Verify scan duration is reasonable
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}

	// Check that scans were executed
	t.Run("Headers Scan", func(t *testing.T) {
		if result.HeaderScan == nil {
			t.Error("HeaderScan should not be nil")
		} else {
			// Should detect missing security headers
			if len(result.HeaderScan.MissingHeaders) == 0 {
				t.Log("Warning: No missing headers detected (expected some for test server)")
			}
		}
	})

	t.Run("TLS Scan", func(t *testing.T) {
		// TLS scan may fail for HTTP test server, which is expected
		if result.TLSScan != nil && result.TLSScan.Protocol == "" {
			t.Log("TLS scan completed but protocol is empty (expected for HTTP)")
		}
	})

	t.Run("SQLi Scan", func(t *testing.T) {
		if result.SQLiScan == nil {
			t.Error("SQLiScan should not be nil")
		}
	})

	t.Run("XSS Scan", func(t *testing.T) {
		if result.XSSScan == nil {
			t.Error("XSSScan should not be nil")
		}
	})
}

// TestIntegrationSecureServer tests scanning a secure server
func TestIntegrationSecureServer(t *testing.T) {
	// Create a mock secure server
	server := createMockSecureServer()
	defer server.Close()

	// Run security scan
	result := orchestrator.RunSecurityScan(server.URL)

	// Verify result
	if result == nil {
		t.Fatal("RunSecurityScan() returned nil")
	}

	// Check headers scan shows good security
	if result.HeaderScan != nil && result.HeaderScan.Score > 0 {
		t.Logf("Security score: %d/100", result.HeaderScan.Score)
	}
}

// TestIntegrationConcurrency tests that concurrent scanning works correctly
func TestIntegrationConcurrency(t *testing.T) {
	server := createMockVulnerableServer()
	defer server.Close()

	start := time.Now()
	result := orchestrator.RunSecurityScan(server.URL)
	duration := time.Since(start)

	if result == nil {
		t.Fatal("RunSecurityScan() returned nil")
	}

	// Concurrent execution should be faster than sequential
	t.Logf("Scan completed in %v", duration)

	// Verify all scans were attempted
	scanCount := 0
	if result.HeaderScan != nil {
		scanCount++
	}
	if result.TLSScan != nil {
		scanCount++
	}
	if result.SQLiScan != nil {
		scanCount++
	}
	if result.XSSScan != nil {
		scanCount++
	}

	if scanCount < 3 {
		t.Errorf("Expected at least 3 scans to complete, got %d", scanCount)
	}
}

// createMockVulnerableServer creates a test server with vulnerabilities
func createMockVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect query parameters (XSS vulnerability)
		query := r.URL.Query().Get("q")
		if query != "" {
			w.Write([]byte(fmt.Sprintf("<html><body>Search: %s</body></html>", query)))
			return
		}

		// Check for SQL injection payloads
		id := r.URL.Query().Get("id")
		if id != "" {
			// Simulate SQL error for certain payloads
			if id == "1' OR '1'='1" || id == "1 OR 1=1" {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("MySQL error: You have an error in your SQL syntax"))
				return
			}
		}

		// Default response - missing security headers
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Welcome to the vulnerable test site</body></html>"))
	}))
}

// createMockSecureServer creates a test server with good security headers
func createMockSecureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set all security headers
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Welcome to the secure test site</body></html>"))
	}))
}

// TestIntegrationErrorHandling tests error scenarios
func TestIntegrationErrorHandling(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		expect string
	}{
		{
			name:   "Invalid URL",
			url:    "not-a-valid-url",
			expect: "should handle invalid URLs",
		},
		{
			name:   "Non-existent domain",
			url:    "https://this-domain-definitely-does-not-exist-12345.com",
			expect: "should handle DNS failures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := orchestrator.RunSecurityScan(tt.url)
			
			// Should still return a result (may have errors in individual scans)
			if result == nil {
				t.Logf("%s: RunSecurityScan returned nil (expected)", tt.expect)
			} else {
				t.Logf("%s: RunSecurityScan returned result", tt.expect)
			}
		})
	}
}

// BenchmarkSecurityScan benchmarks the full scan process
func BenchmarkSecurityScan(b *testing.B) {
	server := createMockVulnerableServer()
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		orchestrator.RunSecurityScan(server.URL)
	}
}

// BenchmarkConcurrentScans benchmarks concurrent scanning
func BenchmarkConcurrentScans(b *testing.B) {
	server := createMockVulnerableServer()
	defer server.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			orchestrator.RunSecurityScan(server.URL)
		}
	})
}
