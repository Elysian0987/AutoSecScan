package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanXSS(t *testing.T) {
	tests := []struct {
		name           string
		reflectPayload bool
		wantVulnCount  int
	}{
		{
			name:           "Vulnerable - reflects payloads",
			reflectPayload: true,
			wantVulnCount:  1, // At least one vulnerability
		},
		{
			name:           "Not vulnerable - no reflection",
			reflectPayload: false,
			wantVulnCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query().Get("q")

				if tt.reflectPayload && query != "" {
					// Reflect the payload back (vulnerable behavior)
					w.Write([]byte("Search results for: " + query))
				} else {
					// Safe response
					w.Write([]byte("Search results"))
				}
			}))
			defer server.Close()

			// Add query parameter
			testURL := server.URL + "?q=test"

			// Scan for XSS
			result := ScanXSS(testURL)

			// Verify result is not nil
			if result == nil {
				t.Fatal("ScanXSS() returned nil")
			}

			// Check vulnerability count
			actualVulnCount := len(result.Vulnerabilities)
			if tt.wantVulnCount > 0 && actualVulnCount == 0 {
				t.Errorf("Expected vulnerabilities to be detected but none were found")
			}
			if tt.wantVulnCount == 0 && actualVulnCount > 0 {
				t.Errorf("Expected no vulnerabilities but %d were found", actualVulnCount)
			}
		})
	}
}

func TestCheckXSSReflection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		payload  string
		wantRefl bool
	}{
		{
			name:     "Exact payload reflection",
			body:     "Search results for: <script>alert('xss')</script>",
			payload:  "<script>alert('xss')</script>",
			wantRefl: true,
		},
		{
			name:     "Payload in body",
			body:     "Results: <img src=x onerror=alert(1)>",
			payload:  "<img src=x onerror=alert(1)>",
			wantRefl: true,
		},
		{
			name:     "No reflection",
			body:     "Search results for: safe content",
			payload:  "<script>alert('xss')</script>",
			wantRefl: false,
		},
		{
			name:     "Partial reflection - encoded",
			body:     "Results: &lt;script&gt;alert('xss')&lt;/script&gt;",
			payload:  "<script>alert('xss')</script>",
			wantRefl: false, // HTML encoded is safe
		},
		{
			name:     "Empty body",
			body:     "",
			payload:  "<script>alert(1)</script>",
			wantRefl: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflected := checkXSSReflection(tt.body, tt.payload)
			if reflected != tt.wantRefl {
				t.Errorf("checkXSSReflection() = %v, want %v", reflected, tt.wantRefl)
			}
		})
	}
}

func TestInjectXSSPayload(t *testing.T) {
	tests := []struct {
		name         string
		urlStr       string
		param        string
		payload      string
		wantContains string
	}{
		{
			name:         "Single parameter injection",
			urlStr:       "https://example.com?q=test",
			param:        "q",
			payload:      "<script>alert(1)</script>",
			wantContains: "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		},
		{
			name:         "Multiple parameters - inject specific one",
			urlStr:       "https://example.com?id=1&q=test&page=2",
			param:        "q",
			payload:      "<img src=x>",
			wantContains: "q=%3Cimg+src%3Dx%3E",
		},
		{
			name:         "No existing parameters",
			urlStr:       "https://example.com",
			param:        "q",
			payload:      "<script>",
			wantContains: "q=%3Cscript%3E",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := injectXSSPayload(tt.urlStr, tt.param, tt.payload)

			if !strings.Contains(result, tt.wantContains) {
				t.Errorf("Result URL should contain %q, got: %s", tt.wantContains, result)
			}
		})
	}
}

func TestExtractParametersXSS(t *testing.T) {
	tests := []struct {
		name      string
		urlStr    string
		wantCount int
	}{
		{
			name:      "Multiple parameters",
			urlStr:    "https://example.com?q=search&id=1&page=2",
			wantCount: 3,
		},
		{
			name:      "Single parameter",
			urlStr:    "https://example.com?q=test",
			wantCount: 1,
		},
		{
			name:      "No parameters",
			urlStr:    "https://example.com",
			wantCount: 0,
		},
		{
			name:      "Empty values",
			urlStr:    "https://example.com?q=&id=",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := extractParameters(tt.urlStr)

			if len(params) != tt.wantCount {
				t.Errorf("Parameter count = %d, want %d", len(params), tt.wantCount)
			}
		})
	}
}

func TestXSSPayloads(t *testing.T) {
	// Test that XSS payloads are properly defined
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<select onfocus=alert(1) autofocus>",
		"<textarea onfocus=alert(1) autofocus>",
		"<keygen onfocus=alert(1) autofocus>",
		"<video><source onerror=alert(1)>",
	}

	if len(payloads) == 0 {
		t.Error("No XSS payloads defined")
	}

	for i, payload := range payloads {
		if payload == "" {
			t.Errorf("Payload %d is empty", i)
		}
		if !strings.Contains(payload, "alert") && !strings.Contains(payload, "javascript:") {
			t.Errorf("Payload %d doesn't contain alert or javascript: %s", i, payload)
		}
	}
}
