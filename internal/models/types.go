package models

import "time"

// TargetInfo contains information about the scan target
type TargetInfo struct {
	URL      string
	Domain   string
	IP       string
	Protocol string
	Port     int
}

// ScanResult contains all scan results
type ScanResult struct {
	Target        TargetInfo
	StartTime     time.Time
	EndTime       time.Time
	NmapResults   *NmapScan
	HeaderResults *HeaderScan
	TLSResults    *TLSScan
	SQLiResults   []Vulnerability
	XSSResults    []Vulnerability
	Errors        []error
	RiskLevel     string
}

// NmapScan contains Nmap scan results
type NmapScan struct {
	OpenPorts []Port
	Duration  time.Duration
}

// Port represents an open port with service information
type Port struct {
	Number   int
	Protocol string
	State    string
	Service  string
	Version  string
}

// HeaderScan contains security header analysis
type HeaderScan struct {
	Headers        map[string]string
	MissingHeaders []SecurityHeader
	WeakHeaders    []SecurityHeader
	PresentHeaders []SecurityHeader
	SecurityScore  int
}

// SecurityHeader represents a security header finding
type SecurityHeader struct {
	Name        string
	Value       string
	Status      string // "missing", "weak", "present"
	Severity    string // "critical", "high", "medium", "low"
	Description string
}

// TLSScan contains TLS/SSL analysis
type TLSScan struct {
	Protocol        string
	CipherSuite     string
	Certificate     CertificateInfo
	Vulnerabilities []string
	Score           int
	IsSecure        bool
}

// CertificateInfo contains SSL certificate details
type CertificateInfo struct {
	Issuer       string
	Subject      string
	ValidFrom    time.Time
	ValidTo      time.Time
	IsExpired    bool
	DaysToExpiry int
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	Type        string // "sqli", "xss", etc.
	Severity    string // "critical", "high", "medium", "low"
	Location    string
	Payload     string
	Evidence    string
	Description string
}
