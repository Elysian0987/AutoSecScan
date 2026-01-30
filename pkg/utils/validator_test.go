package utils

import (
	"testing"
)

func TestValidateAndParseURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantHost  string
		wantProto string
	}{
		{
			name:      "Valid HTTPS URL",
			input:     "https://example.com",
			wantErr:   false,
			wantHost:  "example.com",
			wantProto: "https",
		},
		{
			name:      "Valid HTTP URL",
			input:     "http://example.com",
			wantErr:   false,
			wantHost:  "example.com",
			wantProto: "http",
		},
		{
			name:      "Valid URL with port",
			input:     "https://example.com:8443",
			wantErr:   false,
			wantHost:  "example.com",
			wantProto: "https",
		},
		{
			name:      "Valid URL with path",
			input:     "https://example.com/path/to/resource",
			wantErr:   false,
			wantHost:  "example.com",
			wantProto: "https",
		},
		{
			name:      "URL without scheme - should add https",
			input:     "example.com",
			wantErr:   false,
			wantHost:  "example.com",
			wantProto: "https",
		},
		{
			name:    "Empty URL",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Invalid scheme",
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "Non-existent domain",
			input:   "https://this-domain-definitely-does-not-exist-12345.com",
			wantErr: true,
		},
		{
			name:    "Invalid domain format",
			input:   "https://not a valid url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndParseURL(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateAndParseURL() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateAndParseURL() unexpected error: %v", err)
				return
			}

			if result.Domain != tt.wantHost {
				t.Errorf("ValidateAndParseURL() domain = %v, want %v", result.Domain, tt.wantHost)
			}

			if result.Protocol != tt.wantProto {
				t.Errorf("ValidateAndParseURL() protocol = %v, want %v", result.Protocol, tt.wantProto)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "URL with token parameter",
			input: "https://example.com?token=secret123",
			want:  "https://example.com?token=%5BREDACTED%5D",
		},
		{
			name:  "URL with password parameter",
			input: "https://example.com?password=pass123",
			want:  "https://example.com?password=%5BREDACTED%5D",
		},
		{
			name:  "URL with safe parameters",
			input: "https://example.com?id=1&name=test",
			want:  "https://example.com?id=1&name=test",
		},
		{
			name:  "Clean URL",
			input: "https://example.com",
			want:  "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeURL(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
