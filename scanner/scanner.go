package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// PortInfo represents information about a scanned port
type PortInfo struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
}

// ScanResult represents the result of a port scan
type ScanResult struct {
	Target   string      `json:"target"`
	Ports    []PortInfo  `json:"ports"`
	Duration float64     `json:"duration"`
	Error    string      `json:"error,omitempty"`
}

// ProgressCallback is called during scanning to report progress
type ProgressCallback func(progress int, message string, port *PortInfo)

// Scanner manages nmap port scanning
type Scanner struct {
	timeout    time.Duration
	binaryPath string
}

// NewScanner creates a new port scanner
func NewScanner(nmapPath string) *Scanner {
	return &Scanner{
		timeout:    5 * time.Minute,
		binaryPath: nmapPath,
	}
}

// ScanPorts scans all ports on the target IPv6 address
func (s *Scanner) ScanPorts(target string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	result := &ScanResult{
		Target: target,
		Ports:  make([]PortInfo, 0),
	}

	// Validate IPv6 address
	if target == "" {
		result.Error = "target address is empty"
		return result, fmt.Errorf("target address is empty")
	}

	// Create nmap scanner for full scan
	// -6: IPv6 scan
	// -T3: Normal timing template (more thorough than T4)
	// -p-: Scan all 65535 ports
	// --open: Only show open ports
	// -Pn: Skip host discovery (treat host as online)
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithIPv6Scanning(),
		nmap.WithTimingTemplate(nmap.TimingNormal), // T3 for thoroughness
		nmap.WithPorts("1-65535"),
		nmap.WithOpenOnly(),
		nmap.WithSkipHostDiscovery(),
	}

	// Add custom binary path if specified
	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create scanner: %v", err)
		return result, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Run the scan
	startTime := time.Now()
	nmapResult, warnings, err := scanner.Run()
	duration := time.Since(startTime).Seconds()
	result.Duration = duration

	// Check for warnings
	if warnings != nil && len(*warnings) > 0 {
		fmt.Printf("Scan warnings: %v\n", *warnings)
	}

	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		return result, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse results
	if nmapResult != nil && len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					result.Ports = append(result.Ports, PortInfo{
						Port:     port.ID,
						Protocol: port.Protocol,
						State:    string(port.State.State),
						Service:  port.Service.Name,
					})
				}
			}
		}
	}

	return result, nil
}

// QuickScanPorts performs a quick scan of common ports
func (s *Scanner) QuickScanPorts(target string) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result := &ScanResult{
		Target: target,
		Ports:  make([]PortInfo, 0),
	}

	// Validate IPv6 address
	if target == "" {
		result.Error = "target address is empty"
		return result, fmt.Errorf("target address is empty")
	}

	// Scan top 1000 most common ports with thorough timing
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithIPv6Scanning(),
		nmap.WithTimingTemplate(nmap.TimingNormal), // T3 for thoroughness
		nmap.WithMostCommonPorts(1000),
		nmap.WithOpenOnly(),
		nmap.WithSkipHostDiscovery(),
	}

	// Add custom binary path if specified
	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create scanner: %v", err)
		return result, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Run the scan
	startTime := time.Now()
	nmapResult, warnings, err := scanner.Run()
	duration := time.Since(startTime).Seconds()
	result.Duration = duration

	// Check for warnings
	if warnings != nil && len(*warnings) > 0 {
		fmt.Printf("Scan warnings: %v\n", *warnings)
	}

	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		return result, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse results
	if nmapResult != nil && len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					result.Ports = append(result.Ports, PortInfo{
						Port:     port.ID,
						Protocol: port.Protocol,
						State:    string(port.State.State),
						Service:  port.Service.Name,
					})
				}
			}
		}
	}

	return result, nil
}

// ScanPortsWithProgress scans all ports with progress callback
func (s *Scanner) ScanPortsWithProgress(target string, progressCb ProgressCallback) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	result := &ScanResult{
		Target: target,
		Ports:  make([]PortInfo, 0),
	}

	// Validate IPv6 address
	if target == "" {
		result.Error = "target address is empty"
		return result, fmt.Errorf("target address is empty")
	}

	// Send initial progress
	if progressCb != nil {
		progressCb(0, "Initializing full scan...", nil)
	}

	// Create nmap scanner for full scan
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithIPv6Scanning(),
		nmap.WithTimingTemplate(nmap.TimingNormal), // T3 for thoroughness
		nmap.WithPorts("1-65535"),
		nmap.WithOpenOnly(),
		nmap.WithSkipHostDiscovery(),
	}

	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create scanner: %v", err)
		if progressCb != nil {
			progressCb(0, "Failed to initialize scanner", nil)
		}
		return result, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Send progress updates periodically during scan
	progressTicker := time.NewTicker(2 * time.Second)
	progressDone := make(chan bool)
	currentProgress := 10

	go func() {
		for {
			select {
			case <-progressTicker.C:
				if progressCb != nil && currentProgress < 90 {
					currentProgress += 10
					progressCb(currentProgress, "Scanning ports...", nil)
				}
			case <-progressDone:
				progressTicker.Stop()
				return
			}
		}
	}()

	// Run the scan
	if progressCb != nil {
		progressCb(10, "Starting scan...", nil)
	}

	startTime := time.Now()
	nmapResult, warnings, err := scanner.Run()
	duration := time.Since(startTime).Seconds()
	result.Duration = duration

	// Stop progress ticker
	close(progressDone)

	// Check for warnings
	if warnings != nil && len(*warnings) > 0 {
		fmt.Printf("[WARNING] Scan warnings: %v\n", *warnings)
	}

	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		if progressCb != nil {
			progressCb(0, "Scan failed", nil)
		}
		return result, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse results with progress updates
	if progressCb != nil {
		progressCb(90, "Processing results...", nil)
	}

	if nmapResult != nil && len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					portInfo := PortInfo{
						Port:     port.ID,
						Protocol: port.Protocol,
						State:    string(port.State.State),
						Service:  port.Service.Name,
					}
					result.Ports = append(result.Ports, portInfo)

					// Send progress for each found port
					if progressCb != nil {
						progressCb(95, fmt.Sprintf("Found port %d/%s", port.ID, port.Protocol), &portInfo)
					}
				}
			}
		}
	}

	// Send completion
	if progressCb != nil {
		progressCb(100, "Scan completed", nil)
	}

	return result, nil
}

// QuickScanPortsWithProgress performs a quick scan with progress callback
func (s *Scanner) QuickScanPortsWithProgress(target string, progressCb ProgressCallback) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result := &ScanResult{
		Target: target,
		Ports:  make([]PortInfo, 0),
	}

	// Validate IPv6 address
	if target == "" {
		result.Error = "target address is empty"
		return result, fmt.Errorf("target address is empty")
	}

	// Send initial progress
	if progressCb != nil {
		progressCb(0, "Initializing quick scan...", nil)
	}

	// Scan top 1000 most common ports with thorough timing
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithIPv6Scanning(),
		nmap.WithTimingTemplate(nmap.TimingNormal), // T3 for thoroughness
		nmap.WithMostCommonPorts(1000),
		nmap.WithOpenOnly(),
		nmap.WithSkipHostDiscovery(),
	}

	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create scanner: %v", err)
		if progressCb != nil {
			progressCb(0, "Failed to initialize scanner", nil)
		}
		return result, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Send progress updates during scan
	progressTicker := time.NewTicker(1 * time.Second)
	progressDone := make(chan bool)
	currentProgress := 10

	go func() {
		for {
			select {
			case <-progressTicker.C:
				if progressCb != nil && currentProgress < 90 {
					currentProgress += 15
					progressCb(currentProgress, "Scanning common ports...", nil)
				}
			case <-progressDone:
				progressTicker.Stop()
				return
			}
		}
	}()

	// Run the scan
	if progressCb != nil {
		progressCb(10, "Starting quick scan...", nil)
	}

	startTime := time.Now()
	nmapResult, warnings, err := scanner.Run()
	duration := time.Since(startTime).Seconds()
	result.Duration = duration

	// Stop progress ticker
	close(progressDone)

	// Check for warnings
	if warnings != nil && len(*warnings) > 0 {
		fmt.Printf("[WARNING] Quick scan warnings: %v\n", *warnings)
	}

	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		if progressCb != nil {
			progressCb(0, "Scan failed", nil)
		}
		return result, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse results with progress updates
	if progressCb != nil {
		progressCb(90, "Processing results...", nil)
	}

	if nmapResult != nil && len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					portInfo := PortInfo{
						Port:     port.ID,
						Protocol: port.Protocol,
						State:    string(port.State.State),
						Service:  port.Service.Name,
					}
					result.Ports = append(result.Ports, portInfo)

					// Send progress for each found port
					if progressCb != nil {
						progressCb(95, fmt.Sprintf("Found port %d/%s", port.ID, port.Protocol), &portInfo)
					}
				}
			}
		}
	}

	// Send completion
	if progressCb != nil {
		progressCb(100, "Scan completed", nil)
	}

	return result, nil
}

// ScanCustomPortsWithProgress scans specific ports with progress callback
// ports parameter can be: "80", "80,443", "1-1000", "22,80,443,8080-8090"
func (s *Scanner) ScanCustomPortsWithProgress(target string, ports string, progressCb ProgressCallback) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result := &ScanResult{
		Target: target,
		Ports:  make([]PortInfo, 0),
	}

	// Validate IPv6 address
	if target == "" {
		result.Error = "target address is empty"
		return result, fmt.Errorf("target address is empty")
	}

	// Validate ports parameter
	if ports == "" {
		result.Error = "ports parameter is empty"
		return result, fmt.Errorf("ports parameter is empty")
	}

	// Send initial progress
	if progressCb != nil {
		progressCb(0, "Initializing custom scan...", nil)
	}

	// Scan specified ports
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithIPv6Scanning(),
		nmap.WithTimingTemplate(nmap.TimingAggressive), // T4 for custom scans (usually fewer ports)
		nmap.WithPorts(ports),
		nmap.WithOpenOnly(),
		nmap.WithSkipHostDiscovery(),
	}

	if s.binaryPath != "" {
		options = append(options, nmap.WithBinaryPath(s.binaryPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create scanner: %v", err)
		if progressCb != nil {
			progressCb(0, "Failed to initialize scanner", nil)
		}
		return result, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Send progress updates during scan
	progressTicker := time.NewTicker(1 * time.Second)
	progressDone := make(chan bool)
	currentProgress := 10

	go func() {
		for {
			select {
			case <-progressTicker.C:
				if progressCb != nil && currentProgress < 90 {
					currentProgress += 15
					progressCb(currentProgress, "Scanning ports...", nil)
				}
			case <-progressDone:
				progressTicker.Stop()
				return
			}
		}
	}()

	// Run the scan
	if progressCb != nil {
		progressCb(10, "Starting custom scan...", nil)
	}

	startTime := time.Now()
	nmapResult, warnings, err := scanner.Run()
	duration := time.Since(startTime).Seconds()
	result.Duration = duration

	// Stop progress ticker
	close(progressDone)

	// Check for warnings
	if warnings != nil && len(*warnings) > 0 {
		fmt.Printf("Scan warnings: %v\n", *warnings)
	}

	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		if progressCb != nil {
			progressCb(0, "Scan failed", nil)
		}
		return result, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse results with progress updates
	if progressCb != nil {
		progressCb(90, "Processing results...", nil)
	}

	if nmapResult != nil && len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					portInfo := PortInfo{
						Port:     port.ID,
						Protocol: port.Protocol,
						State:    string(port.State.State),
						Service:  port.Service.Name,
					}
					result.Ports = append(result.Ports, portInfo)

					// Send progress for each found port
					if progressCb != nil {
						progressCb(95, fmt.Sprintf("Found port %d/%s", port.ID, port.Protocol), &portInfo)
					}
				}
			}
		}
	}

	// Send completion
	if progressCb != nil {
		progressCb(100, "Scan completed", nil)
	}

	return result, nil
}
