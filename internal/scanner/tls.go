package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/pkg/utils"
)

// ScanTLS performs TLS/SSL security analysis
func ScanTLS(target *models.TargetInfo) (*models.TLSScan, error) {
	utils.Debug("Starting TLS/SSL scan for %s", target.Domain)

	// Only scan HTTPS targets
	if target.Protocol != "https" {
		return &models.TLSScan{
			IsSecure: false,
			Score:    0,
			Vulnerabilities: []string{"Target is not using HTTPS"},
		}, nil
	}

	// Connect with TLS
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// Use default TLS config first to get server's preferred config
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target.Domain, target.Port), &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true, // We want to check even invalid certs
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	scan := &models.TLSScan{
		Protocol:        getTLSVersion(state.Version),
		CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
		Vulnerabilities: []string{},
		IsSecure:        true,
		Score:           100,
	}

	// Analyze certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		
		daysToExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		
		scan.Certificate = models.CertificateInfo{
			Issuer:       cert.Issuer.String(),
			Subject:      cert.Subject.String(),
			ValidFrom:    cert.NotBefore,
			ValidTo:      cert.NotAfter,
			IsExpired:    time.Now().After(cert.NotAfter),
			DaysToExpiry: daysToExpiry,
		}

		// Check certificate validity
		if scan.Certificate.IsExpired {
			scan.Vulnerabilities = append(scan.Vulnerabilities, "Certificate has expired")
			scan.IsSecure = false
			scan.Score -= 50
		} else if daysToExpiry < 30 {
			scan.Vulnerabilities = append(scan.Vulnerabilities, 
				fmt.Sprintf("Certificate expires soon (%d days)", daysToExpiry))
			scan.Score -= 10
		}

		utils.Debug("Certificate: %s, Valid until: %s", cert.Subject.CommonName, cert.NotAfter)
	}

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		scan.Vulnerabilities = append(scan.Vulnerabilities,
			fmt.Sprintf("Outdated TLS version: %s (TLS 1.2+ recommended)", scan.Protocol))
		scan.IsSecure = false
		scan.Score -= 30
	} else if state.Version == tls.VersionTLS12 {
		scan.Vulnerabilities = append(scan.Vulnerabilities,
			"TLS 1.2 is acceptable but TLS 1.3 is recommended")
		scan.Score -= 5
	}

	// Check cipher suite security
	if isWeakCipher(state.CipherSuite) {
		scan.Vulnerabilities = append(scan.Vulnerabilities,
			fmt.Sprintf("Weak cipher suite: %s", scan.CipherSuite))
		scan.Score -= 20
		scan.IsSecure = false
	}

	// Test for common vulnerabilities
	vulnerabilities := testTLSVulnerabilities(target)
	scan.Vulnerabilities = append(scan.Vulnerabilities, vulnerabilities...)
	if len(vulnerabilities) > 0 {
		scan.Score -= 10 * len(vulnerabilities)
		scan.IsSecure = false
	}

	// Ensure score doesn't go negative
	if scan.Score < 0 {
		scan.Score = 0
	}

	utils.Info("TLS/SSL scan completed: Protocol=%s, Score=%d/100, Secure=%v",
		scan.Protocol, scan.Score, scan.IsSecure)

	return scan, nil
}

// getTLSVersion converts TLS version constant to string
func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isWeakCipher checks if cipher suite is considered weak
func isWeakCipher(suite uint16) bool {
	weakCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:                true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            true, // CBC mode
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            true, // CBC mode
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
	}

	return weakCiphers[suite]
}

// testTLSVulnerabilities tests for known TLS vulnerabilities
func testTLSVulnerabilities(target *models.TargetInfo) []string {
	vulnerabilities := []string{}

	// Test for SSLv3 support (POODLE vulnerability)
	if testProtocolSupport(target, tls.VersionSSL30) {
		vulnerabilities = append(vulnerabilities, "SSLv3 supported (POODLE vulnerability)")
	}

	// Test for TLS 1.0 support (BEAST vulnerability)
	if testProtocolSupport(target, tls.VersionTLS10) {
		vulnerabilities = append(vulnerabilities, "TLS 1.0 supported (BEAST vulnerability)")
	}

	// Test for weak cipher suites
	if testWeakCipherSupport(target) {
		vulnerabilities = append(vulnerabilities, "Weak cipher suites supported")
	}

	return vulnerabilities
}

// testProtocolSupport tests if a specific TLS version is supported
func testProtocolSupport(target *models.TargetInfo, version uint16) bool {
	config := &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target.Domain, target.Port), config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// testWeakCipherSupport tests if weak ciphers are supported
func testWeakCipherSupport(target *models.TargetInfo) bool {
	weakCipherSuites := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	config := &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true,
		CipherSuites:       weakCipherSuites,
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target.Domain, target.Port), config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GetTLSRecommendations returns security recommendations
func GetTLSRecommendations(scan *models.TLSScan) []string {
	recommendations := []string{}

	if !scan.IsSecure {
		recommendations = append(recommendations, "Upgrade to TLS 1.3 for best security")
	}

	if strings.Contains(scan.Protocol, "TLS 1.0") || strings.Contains(scan.Protocol, "TLS 1.1") {
		recommendations = append(recommendations, "Disable TLS 1.0 and 1.1 (known vulnerabilities)")
	}

	if scan.Certificate.IsExpired {
		recommendations = append(recommendations, "Renew SSL certificate immediately")
	} else if scan.Certificate.DaysToExpiry < 30 {
		recommendations = append(recommendations, "Plan certificate renewal soon")
	}

	if len(scan.Vulnerabilities) > 0 {
		recommendations = append(recommendations, "Address identified TLS vulnerabilities")
		recommendations = append(recommendations, "Consider using Mozilla SSL Configuration Generator")
	}

	return recommendations
}
