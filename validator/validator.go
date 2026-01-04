package validator

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidateIPv6Strict performs strict validation of IPv6 addresses to prevent injection attacks
func ValidateIPv6Strict(ipStr string) error {
	// Remove brackets if present
	ipStr = strings.Trim(ipStr, "[]")

	// Check for empty string
	if ipStr == "" {
		return fmt.Errorf("IP address is empty")
	}

	// Check length - IPv6 addresses shouldn't exceed reasonable length
	if len(ipStr) > 45 { // Max IPv6 length with zone: 39 chars + %zone
		return fmt.Errorf("IP address exceeds maximum length")
	}

	// Remove zone identifier if present (e.g., %eth0, %1)
	if idx := strings.Index(ipStr, "%"); idx != -1 {
		ipStr = ipStr[:idx]
	}

	// Check for shell metacharacters that could be used for injection
	if strings.ContainsAny(ipStr, ";|&$`\n\r()<>{}[]'\"\\") {
		return fmt.Errorf("IP address contains invalid characters")
	}

	// Verify it contains only valid IPv6 characters (hex digits and colons)
	// This regex ensures no injection attempts
	validIPv6Pattern := regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	if !validIPv6Pattern.MatchString(ipStr) {
		return fmt.Errorf("IP address contains characters outside hexadecimal and colon")
	}

	// Parse as IP to ensure it's valid IPv6
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address format")
	}

	// Ensure it's IPv6 (not IPv4)
	if ip.To16() == nil {
		return fmt.Errorf("not a valid IPv6 address")
	}

	// Additional check: ensure it's not IPv4-mapped IPv6 (::ffff:192.0.2.1)
	if ip.To4() != nil {
		return fmt.Errorf("IPv4-mapped IPv6 addresses are not allowed")
	}

	return nil
}

// ValidateYggdrasilAddress validates that an IPv6 address is a valid Yggdrasil address
// Yggdrasil uses 200::/8 for node addresses and 300::/8 for subnet prefixes
func ValidateYggdrasilAddress(ipStr string) error {
	// First perform strict IPv6 validation
	if err := ValidateIPv6Strict(ipStr); err != nil {
		return err
	}

	// Parse the IP
	ip := net.ParseIP(strings.Trim(ipStr, "[]"))
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	// Check if it's a Yggdrasil address (200::/8 or 300::/8)
	// First byte must be 0x02 (200::/8) or 0x03 (300::/8)
	firstByte := ip[0]
	if firstByte != 0x02 && firstByte != 0x03 {
		return fmt.Errorf("not a Yggdrasil address (must be in 200::/8 or 300::/8 range)")
	}

	return nil
}

// SanitizeForLog sanitizes input for logging to prevent log injection attacks
func SanitizeForLog(input string) string {
	// Remove newlines and control characters
	input = strings.ReplaceAll(input, "\n", "\\n")
	input = strings.ReplaceAll(input, "\r", "\\r")
	input = strings.ReplaceAll(input, "\t", "\\t")

	// Remove non-printable characters
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, input)
}

// ExtractClientIPv6 safely extracts IPv6 from RemoteAddr with validation
func ExtractClientIPv6(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If SplitHostPort fails, assume it's already just the host
		host = remoteAddr
	}

	// Remove zone identifier if present (e.g., %eth0)
	if idx := strings.Index(host, "%"); idx != -1 {
		host = host[:idx]
	}

	// Validate the extracted IP
	if err := ValidateIPv6Strict(host); err != nil {
		return "", fmt.Errorf("invalid client IP: %w", err)
	}

	return host, nil
}
