package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Elysian0987/AutoSecScan/internal/models"
)

func TestScanHeaders(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		wantScore   int
		wantMissing int
		wantPresent int
	}{
		{
			name: "All security headers present",
			headers: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"Content-Security-Policy":   "default-src 'self'",
				"X-Frame-Options":           "DENY",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "no-referrer",
				"Permissions-Policy":        "geolocation=()",
				"X-XSS-Protection":          "1; mode=block",
			},
			wantScore:   100,
			wantMissing: 0,
			wantPresent: 7,
		},
		{
			name:        "No security headers",
			headers:     map[string]string{},
			wantScore:   0,
			wantMissing: 7,
			wantPresent: 0,
		},
		{
			name: "Partial security headers",
			headers: map[string]string{
				"X-Frame-Options":        "SAMEORIGIN",
				"X-Content-Type-Options": "nosniff",
			},
			wantScore:   28, // 2 out of 7 headers
			wantMissing: 5,
			wantPresent: 2,
		},
		{
			name: "Weak CSP header",
			headers: map[string]string{
				"Content-Security-Policy": "default-src *",
			},
			wantScore:   0, // Weak CSP counts as missing
			wantMissing: 7,
			wantPresent: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, value := range tt.headers {
					w.Header().Set(key, value)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Scan headers
			result := ScanHeaders(server.URL)

			// Verify result is not nil
			if result == nil {
				t.Fatal("ScanHeaders() returned nil")
			}

			// Check score
			if result.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", result.Score, tt.wantScore)
			}

			// Check missing headers count
			if len(result.MissingHeaders) != tt.wantMissing {
				t.Errorf("Missing headers count = %d, want %d", len(result.MissingHeaders), tt.wantMissing)
			}

			// Check present headers count
			if len(result.PresentHeaders) != tt.wantPresent {
				t.Errorf("Present headers count = %d, want %d", len(result.PresentHeaders), tt.wantPresent)
			}
		})
	}
}

func TestCheckCSP(t *testing.T) {
	tests := []struct {
		name     string
		cspValue string
		wantWeak bool
	}{
		{
			name:     "Strong CSP",
			cspValue: "default-src 'self'; script-src 'self'",
			wantWeak: false,
		},
		{
			name:     "Weak CSP with wildcard",
			cspValue: "default-src *",
			wantWeak: true,
		},
		{
			name:     "Weak CSP with unsafe-inline",
			cspValue: "script-src 'unsafe-inline'",
			wantWeak: true,
		},
		{
			name:     "Weak CSP with unsafe-eval",
			cspValue: "script-src 'unsafe-eval'",
			wantWeak: true,
		},
		{
			name:     "Empty CSP",
			cspValue: "",
			wantWeak: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isWeak := checkCSP(tt.cspValue)
			if isWeak != tt.wantWeak {
				t.Errorf("checkCSP() = %v, want %v", isWeak, tt.wantWeak)
			}
		})
	}
}

func TestCalculateHeaderScore(t *testing.T) {
	tests := []struct {
		name      string
		missing   []string
		weak      []string
		present   []string
		wantScore int
	}{
		{
			name:      "All present",
			missing:   []string{},
			weak:      []string{},
			present:   []string{"HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"},
			wantScore: 100,
		},
		{
			name:      "None present",
			missing:   []string{"HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"},
			weak:      []string{},
			present:   []string{},
			wantScore: 0,
		},
		{
			name:      "Half present",
			missing:   []string{"HSTS", "CSP", "X-Frame-Options"},
			weak:      []string{},
			present:   []string{"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"},
			wantScore: 57, // 4/7 = 57%
		},
		{
			name:      "Some weak",
			missing:   []string{"HSTS", "X-Frame-Options"},
			weak:      []string{"CSP"},
			present:   []string{"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"},
			wantScore: 57, // 4/7, weak headers don't count
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.HeaderScan{
				MissingHeaders: tt.missing,
				WeakHeaders:    tt.weak,
				PresentHeaders: tt.present,
			}
			calculateHeaderScore(result)

			if result.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", result.Score, tt.wantScore)
			}
		})
	}
}
