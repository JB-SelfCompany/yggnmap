package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/JB-SelfCompany/yggnmap/scanner"
	"github.com/JB-SelfCompany/yggnmap/validator"
)

// ExportFormat represents the export format type
type ExportFormat string

const (
	FormatCSV  ExportFormat = "csv"
	FormatJSON ExportFormat = "json"
	FormatPDF  ExportFormat = "pdf"
)

// ExportResult contains exported data
type ExportResult struct {
	Data        []byte
	ContentType string
	Filename    string
}

// sanitizeFilename removes potentially dangerous characters from filenames
// Prevents path traversal attacks
func sanitizeFilename(filename string) string {
	// Remove path separators and dangerous characters
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "..", "_")
	filename = strings.ReplaceAll(filename, "\x00", "")

	// Only allow alphanumeric, dash, underscore, and dot
	reg := regexp.MustCompile(`[^a-zA-Z0-9\-_\.]`)
	filename = reg.ReplaceAllString(filename, "_")

	// Limit length
	if len(filename) > 100 {
		filename = filename[:100]
	}

	return filename
}

// sanitizeForCSV sanitizes data for CSV export to prevent CSV injection
func sanitizeForCSV(data string) string {
	// Remove control characters
	data = validator.SanitizeForLog(data)

	// Prevent CSV injection by removing formula characters at the start
	if len(data) > 0 {
		firstChar := data[0]
		if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' {
			data = "'" + data // Prefix with single quote to escape
		}
	}

	return data
}

// sanitizeForPDF sanitizes data for PDF export
func sanitizeForPDF(data string) string {
	// Remove control characters and ensure valid UTF-8
	data = validator.SanitizeForLog(data)

	// Remove characters that could cause PDF rendering issues
	data = strings.ReplaceAll(data, "\x00", "")

	return data
}

// ExportToCSV exports scan results to CSV format
func ExportToCSV(result *scanner.ScanResult, clientIP string) (*ExportResult, error) {
	if result == nil {
		return nil, fmt.Errorf("scan result is nil")
	}

	// Validate and sanitize client IP for filename
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		return nil, fmt.Errorf("invalid client IP: %w", err)
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"Port", "Protocol", "State", "Service"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write port data with sanitization
	for _, port := range result.Ports {
		record := []string{
			sanitizeForCSV(strconv.Itoa(int(port.Port))),
			sanitizeForCSV(port.Protocol),
			sanitizeForCSV(port.State),
			sanitizeForCSV(port.Service),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	// Generate safe filename
	timestamp := time.Now().Format("20060102_150405")
	filename := sanitizeFilename(fmt.Sprintf("yggnmap_%s_%s.csv", clientIP, timestamp))

	return &ExportResult{
		Data:        buf.Bytes(),
		ContentType: "text/csv",
		Filename:    filename,
	}, nil
}

// ExportToJSON exports scan results to JSON format
func ExportToJSON(result *scanner.ScanResult, clientIP string) (*ExportResult, error) {
	if result == nil {
		return nil, fmt.Errorf("scan result is nil")
	}

	// Validate client IP
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		return nil, fmt.Errorf("invalid client IP: %w", err)
	}

	// Create export data structure
	exportData := map[string]interface{}{
		"target":       validator.SanitizeForLog(result.Target),
		"scan_time":    time.Now().UTC().Format(time.RFC3339),
		"duration":     result.Duration,
		"total_ports":  len(result.Ports),
		"ports":        result.Ports,
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Generate safe filename
	timestamp := time.Now().Format("20060102_150405")
	filename := sanitizeFilename(fmt.Sprintf("yggnmap_%s_%s.json", clientIP, timestamp))

	return &ExportResult{
		Data:        data,
		ContentType: "application/json",
		Filename:    filename,
	}, nil
}

// ExportToPDF exports scan results to PDF format
func ExportToPDF(result *scanner.ScanResult, clientIP string) (*ExportResult, error) {
	if result == nil {
		return nil, fmt.Errorf("scan result is nil")
	}

	// Validate client IP
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		return nil, fmt.Errorf("invalid client IP: %w", err)
	}

	// Create PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Title
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "YggNmap Scan Report")
	pdf.Ln(12)

	// Scan information
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Target: %s", sanitizeForPDF(result.Target)))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Scan Date: %s", time.Now().Format("2006-01-02 15:04:05 UTC")))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Duration: %.2f seconds", result.Duration))
	pdf.Ln(6)
	pdf.Cell(0, 8, fmt.Sprintf("Open Ports Found: %d", len(result.Ports)))
	pdf.Ln(12)

	// Table header
	pdf.SetFont("Arial", "B", 11)
	pdf.SetFillColor(102, 126, 234)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(30, 8, "Port", "1", 0, "C", true, 0, "")
	pdf.CellFormat(30, 8, "Protocol", "1", 0, "C", true, 0, "")
	pdf.CellFormat(30, 8, "State", "1", 0, "C", true, 0, "")
	pdf.CellFormat(100, 8, "Service", "1", 0, "C", true, 0, "")
	pdf.Ln(8)

	// Table data
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFillColor(248, 249, 250)

	for i, port := range result.Ports {
		fill := i%2 == 0 // Alternate row colors
		pdf.CellFormat(30, 7, sanitizeForPDF(strconv.Itoa(int(port.Port))), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(30, 7, sanitizeForPDF(port.Protocol), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(30, 7, sanitizeForPDF(port.State), "1", 0, "C", fill, 0, "")
		pdf.CellFormat(100, 7, sanitizeForPDF(port.Service), "1", 0, "L", fill, 0, "")
		pdf.Ln(7)

		// Add new page if needed
		if pdf.GetY() > 270 {
			pdf.AddPage()
			// Re-add header
			pdf.SetFont("Arial", "B", 11)
			pdf.SetFillColor(102, 126, 234)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(30, 8, "Port", "1", 0, "C", true, 0, "")
			pdf.CellFormat(30, 8, "Protocol", "1", 0, "C", true, 0, "")
			pdf.CellFormat(30, 8, "State", "1", 0, "C", true, 0, "")
			pdf.CellFormat(100, 8, "Service", "1", 0, "C", true, 0, "")
			pdf.Ln(8)
			pdf.SetFont("Arial", "", 10)
			pdf.SetTextColor(0, 0, 0)
		}
	}

	// Footer
	pdf.Ln(12)
	pdf.SetFont("Arial", "I", 9)
	pdf.SetTextColor(128, 128, 128)
	pdf.Cell(0, 6, "Generated by YggNmap - Yggdrasil Network Port Scanner")

	// Generate PDF bytes
	var buf bytes.Buffer
	err := pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	// Generate safe filename
	timestamp := time.Now().Format("20060102_150405")
	filename := sanitizeFilename(fmt.Sprintf("yggnmap_%s_%s.pdf", clientIP, timestamp))

	return &ExportResult{
		Data:        buf.Bytes(),
		ContentType: "application/pdf",
		Filename:    filename,
	}, nil
}

// Export exports scan results in the specified format
func Export(result *scanner.ScanResult, clientIP string, format ExportFormat) (*ExportResult, error) {
	// Validate format
	switch format {
	case FormatCSV:
		return ExportToCSV(result, clientIP)
	case FormatJSON:
		return ExportToJSON(result, clientIP)
	case FormatPDF:
		return ExportToPDF(result, clientIP)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}
