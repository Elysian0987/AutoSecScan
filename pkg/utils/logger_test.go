package utils

import (
	"os"
	"testing"
)

func TestInitLogger(t *testing.T) {
	tests := []struct {
		name     string
		verbose  bool
		logFile  string
		wantFile bool
	}{
		{
			name:     "Verbose mode without file",
			verbose:  true,
			logFile:  "",
			wantFile: false,
		},
		{
			name:     "Non-verbose mode",
			verbose:  false,
			logFile:  "",
			wantFile: false,
		},
		{
			name:     "With log file",
			verbose:  true,
			logFile:  "test_log.txt",
			wantFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up log file if it exists
			if tt.logFile != "" {
				defer os.Remove(tt.logFile)
			}

			err := InitLogger(tt.verbose, tt.logFile)
			if err != nil {
				t.Errorf("InitLogger() unexpected error: %v", err)
				return
			}

			// Verify file was created if expected
			if tt.wantFile {
				if _, err := os.Stat(tt.logFile); os.IsNotExist(err) {
					t.Errorf("InitLogger() log file was not created")
				}
			}
		})
	}
}

func TestLoggingFunctions(t *testing.T) {
	// Capture log output - note: emoji logging goes to stdout, not log
	// So we test that functions run without error
	InitLogger(true, "")

	tests := []struct {
		name    string
		logFunc func(string, ...interface{})
		message string
	}{
		{
			name:    "Debug log",
			logFunc: Debug,
			message: "debug message",
		},
		{
			name:    "Info log",
			logFunc: Info,
			message: "info message",
		},
		{
			name:    "Warn log",
			logFunc: Warn,
			message: "warning message",
		},
		{
			name:    "Error log",
			logFunc: Error,
			message: "error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just ensure the function doesn't panic
			tt.logFunc(tt.message)
		})
	}
}

func TestSuccessAndFailure(t *testing.T) {
	// These functions write directly to stdout, just ensure they don't panic
	t.Run("Success message", func(t *testing.T) {
		PrintSuccess("operation completed")
	})

	t.Run("Error message", func(t *testing.T) {
		PrintError("operation failed")
	})

	t.Run("Progress message", func(t *testing.T) {
		PrintProgress("working on task")
	})
}
