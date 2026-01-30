package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/internal/scanner"
	"github.com/Elysian0987/AutoSecScan/pkg/utils"
)

// ScanOptions configures the security scan
type ScanOptions struct {
	SkipNmap    bool
	SkipHeaders bool
	SkipTLS     bool
	SkipSQLi    bool
	SkipXSS     bool
	Timeout     time.Duration
	Progress    ProgressReporter
}

// ProgressReporter is an interface for reporting scan progress
type ProgressReporter interface {
	UpdateProgress(step string, percent int)
	UpdateStatus(message string)
}

// DefaultProgress is a simple console progress reporter
type DefaultProgress struct{}

func (dp *DefaultProgress) UpdateProgress(step string, percent int) {
	utils.PrintProgress(fmt.Sprintf("%s (%d%%)", step, percent))
}

func (dp *DefaultProgress) UpdateStatus(message string) {
	utils.PrintProgress(message)
}

// RunSecurityScan orchestrates all security scans concurrently
func RunSecurityScan(target *models.TargetInfo, options ScanOptions) (*models.ScanResult, error) {
	if options.Progress == nil {
		options.Progress = &DefaultProgress{}
	}

	result := &models.ScanResult{
		Target:    *target,
		StartTime: time.Now(),
		Errors:    []error{},
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()

	// Create wait group for concurrent execution
	var wg sync.WaitGroup

	// Mutex for thread-safe error collection
	var mu sync.Mutex

	// Track completed scans
	totalScans := 0
	completedScans := 0

	// Count how many scans we'll run
	if !options.SkipHeaders {
		totalScans++
	}
	if !options.SkipTLS {
		totalScans++
	}
	if !options.SkipSQLi {
		totalScans++
	}
	if !options.SkipXSS {
		totalScans++
	}
	if !options.SkipNmap && scanner.IsNmapInstalled() {
		totalScans++
	}

	updateProgress := func(scanName string) {
		mu.Lock()
		completedScans++
		percent := (completedScans * 100) / totalScans
		mu.Unlock()
		options.Progress.UpdateProgress(fmt.Sprintf("Completed %s", scanName), percent)
	}

	// 1. Security Headers Scan
	if !options.SkipHeaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options.Progress.UpdateStatus("Scanning HTTP security headers...")

			headerScan, err := scanner.ScanHeaders(target)

			mu.Lock()
			if err != nil {
				utils.Error("Headers scan failed: %v", err)
				result.Errors = append(result.Errors, err)
			} else {
				result.HeaderResults = headerScan
				utils.Info("Headers scan complete (Score: %d/100)", headerScan.SecurityScore)
			}
			mu.Unlock()

			updateProgress("Security Headers")
		}()
	}

	// 2. TLS/SSL Scan
	if !options.SkipTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options.Progress.UpdateStatus("Analyzing TLS/SSL configuration...")

			tlsScan, err := scanner.ScanTLS(target)

			mu.Lock()
			if err != nil {
				utils.Error("TLS scan failed: %v", err)
				result.Errors = append(result.Errors, err)
			} else {
				result.TLSResults = tlsScan
				status := "✓"
				if !tlsScan.IsSecure {
					status = "⚠"
				}
				utils.Info("TLS scan complete %s (Score: %d/100)", status, tlsScan.Score)
			}
			mu.Unlock()

			updateProgress("TLS/SSL")
		}()
	}

	// 3. SQL Injection Scan
	if !options.SkipSQLi {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options.Progress.UpdateStatus("Testing for SQL injection vulnerabilities...")

			sqliVulns, err := scanner.ScanSQLi(target)

			mu.Lock()
			if err != nil {
				utils.Error("SQLi scan failed: %v", err)
				result.Errors = append(result.Errors, err)
			} else {
				result.SQLiResults = sqliVulns
				if len(sqliVulns) > 0 {
					utils.Warn("SQLi scan complete - Found %d vulnerabilities!", len(sqliVulns))
				} else {
					utils.Info("SQLi scan complete - No vulnerabilities found")
				}
			}
			mu.Unlock()

			updateProgress("SQL Injection")
		}()
	}

	// 4. XSS Scan
	if !options.SkipXSS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options.Progress.UpdateStatus("Testing for Cross-Site Scripting (XSS)...")

			xssVulns, err := scanner.ScanXSS(target)

			mu.Lock()
			if err != nil {
				utils.Error("XSS scan failed: %v", err)
				result.Errors = append(result.Errors, err)
			} else {
				result.XSSResults = xssVulns
				if len(xssVulns) > 0 {
					utils.Warn("XSS scan complete - Found %d vulnerabilities!", len(xssVulns))
				} else {
					utils.Info("XSS scan complete - No vulnerabilities found")
				}
			}
			mu.Unlock()

			updateProgress("XSS")
		}()
	}

	// 5. Nmap Port Scan (sequential after others due to longer duration)
	if !options.SkipNmap && scanner.IsNmapInstalled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options.Progress.UpdateStatus("Running Nmap port scan...")

			nmapTimeout := options.Timeout / 2
			nmapScan, err := scanner.ScanNmap(target, nmapTimeout)

			mu.Lock()
			if err != nil {
				utils.Warn("Nmap scan failed: %v", err)
				result.Errors = append(result.Errors, err)
			} else {
				result.NmapResults = nmapScan
				utils.Info("Nmap scan complete - Found %d open ports", len(nmapScan.OpenPorts))
			}
			mu.Unlock()

			updateProgress("Nmap")
		}()
	}

	// Wait for all scans to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All scans completed successfully
		utils.Debug("All scans completed successfully")
	case <-ctx.Done():
		utils.Warn("Scan timeout reached, some scans may be incomplete")
		result.Errors = append(result.Errors, fmt.Errorf("scan timeout exceeded"))
	}

	result.EndTime = time.Now()
	result.RiskLevel = CalculateRiskLevel(result)

	options.Progress.UpdateProgress("All scans complete", 100)

	return result, nil
}

// CalculateRiskLevel determines overall risk based on scan results
func CalculateRiskLevel(result *models.ScanResult) string {
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	// Count vulnerabilities by severity
	for _, vuln := range result.SQLiResults {
		switch vuln.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	for _, vuln := range result.XSSResults {
		switch vuln.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	// Check TLS security
	if result.TLSResults != nil && !result.TLSResults.IsSecure {
		highCount++
	}

	// Check header security
	if result.HeaderResults != nil && result.HeaderResults.SecurityScore < 50 {
		mediumCount++
	}

	// Determine risk level
	if criticalCount > 0 {
		return "CRITICAL"
	}
	if highCount > 0 {
		return "HIGH"
	}
	if mediumCount > 0 {
		return "MEDIUM"
	}
	return "LOW"
}
