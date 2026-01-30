package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanSQLi(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		wantVulnCount int
	}{
		{
			name:          "SQL error in response",
			response:      "MySQL error: You have an error in your SQL syntax",
			wantVulnCount: 1, // At least one vulnerability detected
		},
		{
			name:          "PostgreSQL error",
			response:      "PostgreSQL query failed: syntax error at or near",
			wantVulnCount: 1,
		},
		{
			name:          "No SQL errors",
			response:      "Normal response without SQL errors",
			wantVulnCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			// Add query parameter to test URL
			testURL := server.URL + "?id=1"

			// Scan for SQLi
			result := ScanSQLi(testURL)

			// Verify result is not nil
			if result == nil {
				t.Fatal("ScanSQLi() returned nil")
			}

			// Check if vulnerabilities were detected as expected
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

func TestDetectSQLError(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "MySQL syntax error",
			body:    "You have an error in your SQL syntax",
			wantErr: true,
		},
		{
			name:    "PostgreSQL error",
			body:    "PostgreSQL query failed",
			wantErr: true,
		},
		{
			name:    "SQLite error",
			body:    "SQLite3::SQLException",
			wantErr: true,
		},
		{
			name:    "Oracle error",
			body:    "ORA-00933: SQL command not properly ended",
			wantErr: true,
		},
		{
			name:    "SQL Server error",
			body:    "Microsoft SQL Server Error",
			wantErr: true,
		},
		{
			name:    "Warning MySQL",
			body:    "Warning: mysql_fetch_array()",
			wantErr: true,
		},
		{
			name:    "Unclosed quotation mark",
			body:    "Unclosed quotation mark after the character string",
			wantErr: true,
		},
		{
			name:    "Normal response",
			body:    "This is a normal response without any SQL errors",
			wantErr: false,
		},
		{
			name:    "Empty response",
			body:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasError := detectSQLError(tt.body)
			if hasError != tt.wantErr {
				t.Errorf("detectSQLError() = %v, want %v", hasError, tt.wantErr)
			}
		})
	}
}

func TestExtractParameters(t *testing.T) {
	tests := []struct {
		name      string
		urlStr    string
		wantCount int
		wantParam string
	}{
		{
			name:      "Single parameter",
			urlStr:    "https://example.com?id=1",
			wantCount: 1,
			wantParam: "id",
		},
		{
			name:      "Multiple parameters",
			urlStr:    "https://example.com?id=1&name=test&page=2",
			wantCount: 3,
			wantParam: "id",
		},
		{
			name:      "No parameters",
			urlStr:    "https://example.com",
			wantCount: 0,
			wantParam: "",
		},
		{
			name:      "Empty parameter value",
			urlStr:    "https://example.com?id=",
			wantCount: 1,
			wantParam: "id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := extractParameters(tt.urlStr)

			if len(params) != tt.wantCount {
				t.Errorf("Parameter count = %d, want %d", len(params), tt.wantCount)
			}

			if tt.wantParam != "" {
				found := false
				for _, p := range params {
					if p == tt.wantParam {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected parameter %q not found in %v", tt.wantParam, params)
				}
			}
		})
	}
}

func TestIsSignificantChange(t *testing.T) {
	tests := []struct {
		name            string
		baseline        string
		current         string
		wantSignificant bool
	}{
		{
			name:            "Identical responses",
			baseline:        "Hello World",
			current:         "Hello World",
			wantSignificant: false,
		},
		{
			name:            "Significantly different lengths",
			baseline:        "Short",
			current:         strings.Repeat("Very long response ", 100),
			wantSignificant: true,
		},
		{
			name:            "Slightly different lengths",
			baseline:        "Hello World",
			current:         "Hello World!",
			wantSignificant: false,
		},
		{
			name:            "One empty response",
			baseline:        strings.Repeat("Normal response ", 10),
			current:         "",
			wantSignificant: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSignificant := isSignificantChange(tt.baseline, tt.current)
			if isSignificant != tt.wantSignificant {
				t.Errorf("isSignificantChange() = %v, want %v (baseline len: %d, current len: %d)",
					isSignificant, tt.wantSignificant, len(tt.baseline), len(tt.current))
			}
		})
	}
}
