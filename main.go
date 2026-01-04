package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"yggnmap/server"
)

const (
	defaultPort       = 8080
	defaultListenAddr = "::" // Listen on all IPv6 interfaces
)

func main() {
	// Parse command-line flags
	port := flag.Int("port", defaultPort, "Port to listen on")
	listenAddr := flag.String("listen", defaultListenAddr, "IPv6 address to listen on (:: for all interfaces)")
	nmapPath := flag.String("nmap", "", "Path to nmap binary (default: search in PATH)")
	help := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Create server
	srv := server.NewServer(*listenAddr, *port, *nmapPath)

	log.Println("YggNmap - Yggdrasil Network Port Scanner Service")
	log.Println("=================================================")
	log.Printf("Configuration:")
	log.Printf("  Listen Address: %s", *listenAddr)
	log.Printf("  Port: %d", *port)
	log.Println()
	log.Println("Server Requirements:")
	log.Println("  - nmap must be installed on this server")
	log.Println()
	log.Println("Client Requirements:")
	log.Println("  - Only Yggdrasil connection needed")
	log.Println("  - No installation required")
	log.Println()
	log.Println("Security Features:")
	log.Println("  - Strict IPv6 validation")
	log.Println("  - CSRF protection")
	log.Println("  - Rate limiting with memory cleanup")
	log.Println("  - Global concurrency control")
	log.Println("  - Request size limits")
	log.Println("  - Comprehensive security logging")
	log.Println()

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-serverErrors:
		log.Printf("Failed to start server: %v", err)
		log.Println()

		// Provide helpful troubleshooting information
		if *listenAddr != defaultListenAddr {
			log.Println("Troubleshooting:")
			log.Printf("  The specified address '%s' is not available on this system.", *listenAddr)
			log.Println()
			log.Println("Possible solutions:")
			log.Println("  1. Use the default (listen on all interfaces):")
			log.Println("     ./yggnmap -port", *port)
			log.Println()
			log.Println("  2. Use your Yggdrasil node address (200::/8):")
			log.Println("     Run: yggdrasilctl getSelf")
			log.Println("     Then: ./yggnmap -listen <IPv6-address> -port", *port)
			log.Println()
			log.Println("  3. Add subnet address to interface (for 300::/8 addresses):")
			log.Println("     sudo ip -6 addr add", *listenAddr+"/64 dev tun0")
			log.Println("     Then: ./yggnmap -listen", *listenAddr, "-port", *port)
			log.Println()
			log.Println("  4. Check available IPv6 addresses:")
			log.Println("     ip -6 addr show | grep inet6")
			log.Println()
		}
		os.Exit(1)
	case sig := <-sigChan:
		log.Printf("\nReceived signal: %v", sig)
		log.Println("Initiating graceful shutdown...")

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shutdown server
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Error during shutdown: %v", err)
			os.Exit(1)
		}

		log.Println("Server stopped gracefully")
	}
}

func printHelp() {
	log.Println("YggNmap - Yggdrasil Network Port Scanner Service")
	log.Println("=================================================")
	log.Println()
	log.Println("A web service that scans open ports for Yggdrasil Network users.")
	log.Println("Users connect to your service and get their IPv6 ports scanned automatically.")
	log.Println()
	log.Println("Usage:")
	log.Println("  yggnmap [options]")
	log.Println()
	log.Println("Options:")
	flag.PrintDefaults()
	log.Println()
	log.Println("Server Requirements:")
	log.Println("  - nmap must be installed on the server")
	log.Println("  - Server must be accessible via Yggdrasil Network")
	log.Println()
	log.Println("User Requirements:")
	log.Println("  - Only Yggdrasil connection needed")
	log.Println("  - No nmap installation required")
	log.Println()
	log.Println("Examples:")
	log.Println("  yggnmap                                    # Listen on all IPv6 interfaces, port 8080")
	log.Println("  yggnmap -port 9090                         # Use custom port")
	log.Println("  yggnmap -listen 200:1234::1                # Listen on specific Yggdrasil IPv6")
	log.Println()
}
