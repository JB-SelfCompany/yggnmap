package yggdrasil

import (
	"fmt"
	"net"
	"strings"
)

// GetYggdrasilAddresses returns all Yggdrasil IPv6 addresses found on the system
// Yggdrasil uses two prefixes:
// - 200::/8 - Individual node addresses (128-bit)
// - 300::/8 - Routed /64 subnets
func GetYggdrasilAddresses() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var yggAddresses []string

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.To16() == nil {
				continue // Not IPv6
			}

			// Check if address starts with 0x02 (200::/8) or 0x03 (300::/8)
			if ip[0] == 0x02 || ip[0] == 0x03 {
				yggAddresses = append(yggAddresses, ip.String())
			}
		}
	}

	if len(yggAddresses) == 0 {
		return nil, fmt.Errorf("no Yggdrasil addresses found (200::/8 or 300::/8)")
	}

	return yggAddresses, nil
}

// GetPrimaryYggdrasilAddress returns the first 200::/8 address found
// Falls back to 300::/8 if no 200: address exists
func GetPrimaryYggdrasilAddress() (string, error) {
	addresses, err := GetYggdrasilAddresses()
	if err != nil {
		return "", err
	}

	// Prefer 200: addresses (node addresses)
	for _, addr := range addresses {
		if strings.HasPrefix(addr, "200:") || strings.HasPrefix(addr, "2") {
			return addr, nil
		}
	}

	// Fall back to 300: addresses (subnet addresses)
	for _, addr := range addresses {
		if strings.HasPrefix(addr, "300:") || strings.HasPrefix(addr, "3") {
			return addr, nil
		}
	}

	return addresses[0], nil
}

// IsYggdrasilAddress checks if an IPv6 address is a Yggdrasil address
func IsYggdrasilAddress(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To16() == nil {
		return false
	}

	// Check if first byte is 0x02 (200::/8) or 0x03 (300::/8)
	return ip[0] == 0x02 || ip[0] == 0x03
}
