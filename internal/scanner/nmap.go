package scanner

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"time"

	"github.com/Elysian0987/AutoSecScan/internal/models"
	"github.com/Elysian0987/AutoSecScan/pkg/utils"
)

// NmapRun represents the root XML structure from Nmap
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a scanned host
type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts     `xml:"ports"`
}

// NmapAddress represents an IP address
type NmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

// NmapPorts contains port information
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// NmapPort represents a single port
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents service information
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// ScanNmap performs an Nmap scan on the target
func ScanNmap(target *models.TargetInfo, timeout time.Duration) (*models.NmapScan, error) {
	utils.Debug("Starting Nmap scan for %s", target.Domain)
	startTime := time.Now()

	// Check if nmap is installed
	if !isNmapInstalled() {
		return nil, fmt.Errorf("nmap is not installed or not in PATH")
	}

	// Build nmap command
	// Using -Pn (skip ping), -sV (version detection), -T4 (faster), --top-ports 1000
	args := []string{
		"-Pn",                 // Skip host discovery
		"-sV",                 // Service version detection
		"-T4",                 // Faster timing template
		"--top-ports", "1000", // Scan top 1000 ports
		"-oX", "-", // Output XML to stdout
		target.Domain,
	}

	utils.Debug("Executing: nmap %v", args)

	// Execute nmap with timeout
	cmd := exec.Command("nmap", args...)

	// Set timeout
	if timeout > 0 {
		time.AfterFunc(timeout, func() {
			cmd.Process.Kill()
		})
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %w (output: %s)", err, string(output))
	}

	utils.Debug("Nmap scan completed, parsing XML output")

	// Parse XML output
	nmapScan, err := parseNmapXML(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	duration := time.Since(startTime)
	nmapScan.Duration = duration

	utils.Info("Nmap scan completed: found %d open ports in %v", len(nmapScan.OpenPorts), duration)

	return nmapScan, nil
}

// parseNmapXML parses Nmap XML output
func parseNmapXML(data []byte) (*models.NmapScan, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, err
	}

	scan := &models.NmapScan{
		OpenPorts: []models.Port{},
	}

	// Extract open ports
	for _, host := range nmapRun.Hosts {
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				serviceVersion := port.Service.Product
				if port.Service.Version != "" {
					serviceVersion += " " + port.Service.Version
				}

				scan.OpenPorts = append(scan.OpenPorts, models.Port{
					Number:   port.PortID,
					Protocol: port.Protocol,
					State:    port.State.State,
					Service:  port.Service.Name,
					Version:  serviceVersion,
				})
			}
		}
	}

	return scan, nil
}

// isNmapInstalled checks if nmap is available in PATH
func isNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// GetNmapVersion returns the installed Nmap version
func GetNmapVersion() (string, error) {
	cmd := exec.Command("nmap", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
