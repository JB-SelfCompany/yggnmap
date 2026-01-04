package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"yggnmap/export"
	"yggnmap/i18n"
	"yggnmap/scanner"
	"yggnmap/validator"
	wsHub "yggnmap/websocket"
	"yggnmap/yggdrasil"
)

// Server represents the web server
type Server struct {
	scanner    *scanner.Scanner
	listenAddr string
	port       int
	httpServer *http.Server

	// Rate limiting
	scanLimiter map[string]time.Time
	limiterMu   sync.Mutex

	// Global concurrency control
	scanSemaphore chan struct{}
	maxConcurrent int

	// CSRF protection
	csrfTokens   map[string]time.Time
	csrfMu       sync.RWMutex
	csrfLifetime time.Duration

	// WebSocket hub
	wsHub *wsHub.Hub

	// Cleanup control
	shutdownChan  chan struct{}
	cleanupTicker *time.Ticker
	wsCleanupCtx  context.Context
	wsCleanupCancel context.CancelFunc
}

const (
	maxConcurrentScans = 10
	rateLimiterCleanupInterval = 5 * time.Minute
	rateLimiterEntryTTL = 1 * time.Hour
	csrfTokenLifetime = 30 * time.Minute
)

// NewServer creates a new web server
func NewServer(listenAddr string, port int, nmapPath string) *Server {
	// Initialize i18n
	i18n.Init()

	// Create WebSocket cleanup context
	wsCleanupCtx, wsCleanupCancel := context.WithCancel(context.Background())

	srv := &Server{
		scanner:         scanner.NewScanner(nmapPath),
		listenAddr:      listenAddr,
		port:            port,
		scanLimiter:     make(map[string]time.Time),
		scanSemaphore:   make(chan struct{}, maxConcurrentScans),
		maxConcurrent:   maxConcurrentScans,
		csrfTokens:      make(map[string]time.Time),
		csrfLifetime:    csrfTokenLifetime,
		shutdownChan:    make(chan struct{}),
		cleanupTicker:   time.NewTicker(rateLimiterCleanupInterval),
		wsCleanupCtx:    wsCleanupCtx,
		wsCleanupCancel: wsCleanupCancel,
	}

	// Create WebSocket hub with shared CSRF tokens
	srv.wsHub = wsHub.NewHub(srv.csrfTokens, &srv.csrfMu, srv.csrfLifetime)

	// Start background cleanup goroutines
	go srv.cleanupOldEntries()
	go srv.wsHub.CleanupInactive(srv.wsCleanupCtx)

	return srv
}

// extractClientIPv6 extracts and validates the IPv6 address from the HTTP request
// It checks proxy headers (X-Forwarded-For, X-Real-IP) first, then falls back to RemoteAddr
func extractClientIPv6(r *http.Request) (string, error) {
	var clientIP string

	// Check X-Forwarded-For header (set by reverse proxies like Caddy)
	// Format: X-Forwarded-For: client, proxy1, proxy2
	// We want the first (original client) IP
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// Take the first IP from the comma-separated list
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			clientIP = strings.TrimSpace(ips[0])
			log.Printf("[INFO] Using IP from X-Forwarded-For header")
		}
	}

	// Check X-Real-IP header (alternative header used by some proxies)
	if clientIP == "" {
		xRealIP := r.Header.Get("X-Real-IP")
		if xRealIP != "" {
			clientIP = strings.TrimSpace(xRealIP)
			log.Printf("[INFO] Using IP from X-Real-IP header")
		}
	}

	// Fallback to RemoteAddr if no proxy headers present
	if clientIP == "" {
		clientIP = r.RemoteAddr
		log.Printf("[INFO] Using IP from RemoteAddr (direct connection)")
	}

	// Extract and validate the IP
	return validator.ExtractClientIPv6(clientIP)
}

// cleanupOldEntries periodically removes old entries from rate limiter and CSRF tokens
func (s *Server) cleanupOldEntries() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.performCleanup()
		case <-s.shutdownChan:
			s.cleanupTicker.Stop()
			return
		}
	}
}

// performCleanup removes expired entries from maps
func (s *Server) performCleanup() {
	now := time.Now()

	// Clean up rate limiter
	s.limiterMu.Lock()
	for ip, lastTime := range s.scanLimiter {
		if now.Sub(lastTime) > rateLimiterEntryTTL {
			delete(s.scanLimiter, ip)
		}
	}
	rateLimiterSize := len(s.scanLimiter)
	s.limiterMu.Unlock()

	// Clean up CSRF tokens
	s.csrfMu.Lock()
	for token, createdAt := range s.csrfTokens {
		if now.Sub(createdAt) > s.csrfLifetime {
			delete(s.csrfTokens, token)
		}
	}
	csrfTokensSize := len(s.csrfTokens)
	s.csrfMu.Unlock()

	log.Printf("[CLEANUP] Rate limiter: %d entries, CSRF tokens: %d entries", rateLimiterSize, csrfTokensSize)
}

// generateCSRFToken generates a new CSRF token
func (s *Server) generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	s.csrfMu.Lock()
	s.csrfTokens[token] = time.Now()
	s.csrfMu.Unlock()

	return token, nil
}

// validateCSRFToken validates a CSRF token
func (s *Server) validateCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	s.csrfMu.RLock()
	createdAt, exists := s.csrfTokens[token]
	s.csrfMu.RUnlock()

	if !exists {
		return false
	}

	// Check if token is expired
	if time.Since(createdAt) > s.csrfLifetime {
		s.csrfMu.Lock()
		delete(s.csrfTokens, token)
		s.csrfMu.Unlock()
		return false
	}

	return true
}

// acquireScanSlot attempts to acquire a slot for scanning (global concurrency control)
func (s *Server) acquireScanSlot(ctx context.Context) error {
	select {
	case s.scanSemaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("context cancelled while waiting for scan slot")
	case <-time.After(30 * time.Second):
		return fmt.Errorf("server too busy, please try again later")
	}
}

// releaseScanSlot releases a scan slot
func (s *Server) releaseScanSlot() {
	<-s.scanSemaphore
}

// setSecurityHeaders sets comprehensive security headers
func setSecurityHeaders(w http.ResponseWriter) {
	// Prevent clickjacking
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")

	// Prevent MIME sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// XSS protection
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Referrer policy
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Permissions policy
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

// detectProxyHeaders checks for proxy headers and logs warnings
func detectProxyHeaders(r *http.Request) {
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Original-Forwarded-For",
	}

	for _, header := range proxyHeaders {
		if value := r.Header.Get(header); value != "" {
			log.Printf("[WARNING] Proxy header detected: %s - Client IP extraction may be incorrect", header)
		}
	}
}

// logSecurityEvent logs security-related events (without IP for privacy)
func logSecurityEvent(eventType, clientIP, outcome, requestID string, details map[string]interface{}) {
	log.Printf("[SECURITY] type=%s outcome=%s requestID=%s details=%v",
		eventType, outcome, requestID, details)
}

// Start starts the web server
func (s *Server) Start() error {
	// Create middleware for request size limiting
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/quick-scan", s.handleQuickScan)
	mux.HandleFunc("/api/custom-scan", s.handleCustomScan)
	mux.HandleFunc("/api/csrf-token", s.handleCSRFToken)

	// WebSocket endpoint
	mux.HandleFunc("/api/ws", s.handleWebSocket)

	// Export endpoints
	mux.HandleFunc("/api/export/csv", s.handleExportCSV)
	mux.HandleFunc("/api/export/json", s.handleExportJSON)
	mux.HandleFunc("/api/export/pdf", s.handleExportPDF)

	// i18n endpoint
	mux.HandleFunc("/api/translations", s.handleTranslations)

	// Wrap with middleware
	handler := s.limitRequestSize(mux, 1<<20) // 1MB limit

	// Detect Yggdrasil addresses
	yggAddresses, err := yggdrasil.GetYggdrasilAddresses()
	if err != nil {
		log.Printf("WARNING: Could not detect Yggdrasil addresses: %v", err)
		log.Printf("Make sure Yggdrasil is running and configured")
	}

	// Get primary Yggdrasil address for display
	primaryAddr, _ := yggdrasil.GetPrimaryYggdrasilAddress()

	// Start server
	var addr string
	if s.listenAddr == "" || s.listenAddr == "0.0.0.0" || s.listenAddr == "::" {
		addr = fmt.Sprintf(":%d", s.port)
	} else {
		addr = fmt.Sprintf("[%s]:%d", s.listenAddr, s.port)
	}

	log.Printf("Starting YggNmap server on %s", addr)
	log.Println()

	if len(yggAddresses) > 0 {
		log.Println("Detected Yggdrasil addresses:")
		for _, yggAddr := range yggAddresses {
			addrType := "node address (200::/8)"
			if strings.HasPrefix(yggAddr, "300:") || strings.HasPrefix(yggAddr, "3") {
				addrType = "subnet address (300::/8)"
			}
			log.Printf("  - %s (%s)", yggAddr, addrType)
		}
		log.Println()

		if primaryAddr != "" {
			log.Printf("PRIMARY ACCESS URL: http://[%s]:%d/", primaryAddr, s.port)
			log.Println()
		}
	}

	log.Println("Server Information:")
	log.Printf("  - Supports both 200::/8 (node) and 300::/8 (subnet) addresses")
	log.Printf("  - Automatically detects client IPv6 from HTTP request")
	log.Printf("  - Rate limiting: Quick scan (30s), Full scan (60s), Custom scan (45s)")
	log.Printf("  - Global concurrency limit: %d simultaneous scans", maxConcurrentScans)
	log.Printf("  - Security: CSRF protection, request size limits, comprehensive logging")
	log.Println()
	log.Println("Ready to accept connections!")

	// Configure HTTP server with timeouts
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 10 * time.Minute, // Scans can take a while
		IdleTimeout:  120 * time.Second,

		// Limit header size to prevent memory exhaustion
		MaxHeaderBytes: 1 << 20, // 1 MB

		// Set timeouts for reading headers
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down server gracefully...")

	// Stop cleanup goroutine
	close(s.shutdownChan)

	// Stop WebSocket cleanup
	if s.wsCleanupCancel != nil {
		s.wsCleanupCancel()
	}

	// Shutdown HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("error shutting down HTTP server: %w", err)
		}
	}

	log.Println("Server shutdown complete")
	return nil
}

// limitRequestSize middleware limits the size of incoming requests
func (s *Server) limitRequestSize(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check for proxy headers
	detectProxyHeaders(r)

	w.Write([]byte(htmlTemplate))
}

// handleCSRFToken generates and returns a new CSRF token
func (s *Server) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	token, err := s.generateCSRFToken()
	if err != nil {
		log.Printf("[ERROR] Failed to generate CSRF token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
	})
}

// InfoResponse represents the client information response
type InfoResponse struct {
	YggAddress string `json:"ygg_address"`
	ClientIP   string `json:"client_ip"`
}

// handleInfo returns information about the client's IP address
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Extract and validate client IP with strict validation
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP: %v", err)
		logSecurityEvent("ip_extraction_failed", r.RemoteAddr, "failure", "", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Additional validation for IPv6
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		log.Printf("[ERROR] Invalid IPv6 address validation failed: %v", err)
		logSecurityEvent("invalid_ipv6", clientIP, "failure", "", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Client IP detected successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InfoResponse{
		YggAddress: clientIP,
		ClientIP:   clientIP,
	})
}

// handleScan performs a full port scan on the client's IP
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if !s.validateCSRFToken(csrfToken) {
		log.Printf("[SECURITY] Invalid CSRF token for full scan request")
		logSecurityEvent("csrf_validation_failed", r.RemoteAddr, "blocked", "", map[string]interface{}{
			"scan_type": "full",
		})
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Extract and validate client IP
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP: %v", err)
		logSecurityEvent("ip_extraction_failed", r.RemoteAddr, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "full",
		})
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Strict IPv6 validation
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		log.Printf("[SECURITY] Invalid IPv6 address attempt blocked: %v", err)
		logSecurityEvent("invalid_ipv6", clientIP, "blocked", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "full",
		})
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return
	}

	// Rate limiting: allow one scan per 60 seconds per IP
	if !s.checkRateLimit(clientIP, 60*time.Second) {
		log.Printf("[RATE_LIMIT] Full scan rate limit exceeded for client")
		logSecurityEvent("rate_limit_exceeded", clientIP, "blocked", "", map[string]interface{}{
			"scan_type": "full",
			"limit": "60s",
		})
		http.Error(w, "Rate limit exceeded. Please wait 60 seconds before scanning again.", http.StatusTooManyRequests)
		return
	}

	// Acquire scan slot (global concurrency control)
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	if err := s.acquireScanSlot(ctx); err != nil {
		log.Printf("[CONCURRENCY] Failed to acquire scan slot: %v", err)
		logSecurityEvent("scan_slot_unavailable", clientIP, "rejected", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "full",
		})
		http.Error(w, "Server is currently busy. Please try again later.", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseScanSlot()

	log.Printf("[SCAN] Full scan started for client")
	logSecurityEvent("scan_started", clientIP, "success", "", map[string]interface{}{
		"scan_type": "full",
	})

	// Create progress callback for WebSocket updates
	progressCallback := func(progress int, message string, port *scanner.PortInfo) {
		update := wsHub.ProgressUpdate{
			Type:     "progress",
			Progress: progress,
			Message:  message,
			ScanType: "full",
		}

		if port != nil {
			update.Type = "port_found"
			portNum := int(port.Port)
			update.Port = &portNum
			update.Protocol = port.Protocol
			update.Service = port.Service
		}

		// Send progress to WebSocket (non-blocking)
		s.wsHub.SendProgress(clientIP, update)
	}

	// Perform scan on client's IP with progress callback
	result, err := s.scanner.ScanPortsWithProgress(clientIP, progressCallback)
	if err != nil {
		log.Printf("[ERROR] Full scan failed: %v", err)
		logSecurityEvent("scan_failed", clientIP, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "full",
		})
		// Don't expose internal error details to client
		if result != nil {
			result.Error = "Scan failed. Please try again later."
		}
	} else {
		log.Printf("[SCAN] Full scan completed - found %d open ports in %.2f seconds",
			len(result.Ports), result.Duration)
		logSecurityEvent("scan_completed", clientIP, "success", "", map[string]interface{}{
			"scan_type": "full",
			"ports_found": len(result.Ports),
			"duration": result.Duration,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleQuickScan performs a quick scan of common ports on the client's IP
func (s *Server) handleQuickScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if !s.validateCSRFToken(csrfToken) {
		log.Printf("[SECURITY] Invalid CSRF token for quick scan request")
		logSecurityEvent("csrf_validation_failed", r.RemoteAddr, "blocked", "", map[string]interface{}{
			"scan_type": "quick",
		})
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Extract and validate client IP
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP: %v", err)
		logSecurityEvent("ip_extraction_failed", r.RemoteAddr, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "quick",
		})
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Strict IPv6 validation
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		log.Printf("[SECURITY] Invalid IPv6 address attempt blocked: %v", err)
		logSecurityEvent("invalid_ipv6", clientIP, "blocked", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "quick",
		})
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return
	}

	// Rate limiting: allow one scan per 30 seconds per IP
	if !s.checkRateLimit(clientIP, 30*time.Second) {
		log.Printf("[RATE_LIMIT] Quick scan rate limit exceeded for client")
		logSecurityEvent("rate_limit_exceeded", clientIP, "blocked", "", map[string]interface{}{
			"scan_type": "quick",
			"limit": "30s",
		})
		http.Error(w, "Rate limit exceeded. Please wait 30 seconds before scanning again.", http.StatusTooManyRequests)
		return
	}

	// Acquire scan slot (global concurrency control)
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	if err := s.acquireScanSlot(ctx); err != nil {
		log.Printf("[CONCURRENCY] Failed to acquire scan slot: %v", err)
		logSecurityEvent("scan_slot_unavailable", clientIP, "rejected", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "quick",
		})
		http.Error(w, "Server is currently busy. Please try again later.", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseScanSlot()

	log.Printf("[SCAN] Quick scan started for client")
	logSecurityEvent("scan_started", clientIP, "success", "", map[string]interface{}{
		"scan_type": "quick",
	})

	// Create progress callback for WebSocket updates
	progressCallback := func(progress int, message string, port *scanner.PortInfo) {
		update := wsHub.ProgressUpdate{
			Type:     "progress",
			Progress: progress,
			Message:  message,
			ScanType: "quick",
		}

		if port != nil {
			update.Type = "port_found"
			portNum := int(port.Port)
			update.Port = &portNum
			update.Protocol = port.Protocol
			update.Service = port.Service
		}

		// Send progress to WebSocket (non-blocking)
		s.wsHub.SendProgress(clientIP, update)
	}

	// Perform quick scan on client's IP with progress callback
	result, err := s.scanner.QuickScanPortsWithProgress(clientIP, progressCallback)
	if err != nil {
		log.Printf("[ERROR] Quick scan failed: %v", err)
		logSecurityEvent("scan_failed", clientIP, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "quick",
		})
		// Don't expose internal error details to client
		if result != nil {
			result.Error = "Scan failed. Please try again later."
		}
	} else {
		log.Printf("[SCAN] Quick scan completed - found %d open ports in %.2f seconds",
			len(result.Ports), result.Duration)
		logSecurityEvent("scan_completed", clientIP, "success", "", map[string]interface{}{
			"scan_type": "quick",
			"ports_found": len(result.Ports),
			"duration": result.Duration,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CustomScanRequest represents a custom port scan request
type CustomScanRequest struct {
	Ports string `json:"ports"`
}

// handleCustomScan performs a scan of specific ports on the client's IP
func (s *Server) handleCustomScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if !s.validateCSRFToken(csrfToken) {
		log.Printf("[SECURITY] Invalid CSRF token for custom scan request")
		logSecurityEvent("csrf_validation_failed", r.RemoteAddr, "blocked", "", map[string]interface{}{
			"scan_type": "custom",
		})
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Extract and validate client IP
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP: %v", err)
		logSecurityEvent("ip_extraction_failed", r.RemoteAddr, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "custom",
		})
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Strict IPv6 validation
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		log.Printf("[SECURITY] Invalid IPv6 address attempt blocked: %v", err)
		logSecurityEvent("invalid_ipv6", clientIP, "blocked", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "custom",
		})
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return
	}

	// Parse request body to get ports
	var req CustomScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to parse custom scan request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate ports parameter
	if req.Ports == "" {
		http.Error(w, "Please specify ports to scan", http.StatusBadRequest)
		return
	}

	// Rate limiting: allow one scan per 45 seconds per IP
	if !s.checkRateLimit(clientIP, 45*time.Second) {
		log.Printf("[RATE_LIMIT] Custom scan rate limit exceeded for client")
		logSecurityEvent("rate_limit_exceeded", clientIP, "blocked", "", map[string]interface{}{
			"scan_type": "custom",
			"limit": "45s",
		})
		http.Error(w, "Rate limit exceeded. Please wait 45 seconds before scanning again.", http.StatusTooManyRequests)
		return
	}

	// Acquire scan slot (global concurrency control)
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	if err := s.acquireScanSlot(ctx); err != nil {
		log.Printf("[CONCURRENCY] Failed to acquire scan slot: %v", err)
		logSecurityEvent("scan_slot_unavailable", clientIP, "rejected", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "custom",
		})
		http.Error(w, "Server is currently busy. Please try again later.", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseScanSlot()

	log.Printf("[SCAN] Custom scan started for client (ports: %s)",
		validator.SanitizeForLog(req.Ports))
	logSecurityEvent("scan_started", clientIP, "success", "", map[string]interface{}{
		"scan_type": "custom",
		"ports":     req.Ports,
	})

	// Create progress callback for WebSocket updates
	progressCallback := func(progress int, message string, port *scanner.PortInfo) {
		update := wsHub.ProgressUpdate{
			Type:     "progress",
			Progress: progress,
			Message:  message,
			ScanType: "custom",
		}

		if port != nil {
			update.Type = "port_found"
			portNum := int(port.Port)
			update.Port = &portNum
			update.Protocol = port.Protocol
			update.Service = port.Service
		}

		// Send progress to WebSocket (non-blocking)
		s.wsHub.SendProgress(clientIP, update)
	}

	// Perform custom scan on client's IP with progress callback
	result, err := s.scanner.ScanCustomPortsWithProgress(clientIP, req.Ports, progressCallback)
	if err != nil {
		log.Printf("[ERROR] Custom scan failed: %v", err)
		logSecurityEvent("scan_failed", clientIP, "failure", "", map[string]interface{}{
			"error": err.Error(),
			"scan_type": "custom",
			"ports": req.Ports,
		})
		// Don't expose internal error details to client
		if result != nil {
			result.Error = "Scan failed. Please try again later."
		}
	} else {
		log.Printf("[SCAN] Custom scan completed - found %d open ports in %.2f seconds (ports: %s)",
			len(result.Ports), result.Duration, req.Ports)
		logSecurityEvent("scan_completed", clientIP, "success", "", map[string]interface{}{
			"scan_type": "custom",
			"ports_found": len(result.Ports),
			"duration": result.Duration,
			"ports": req.Ports,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// checkRateLimit checks if the client can perform an action based on rate limiting
func (s *Server) checkRateLimit(clientIP string, interval time.Duration) bool {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()

	lastTime, exists := s.scanLimiter[clientIP]
	now := time.Now()

	if !exists || now.Sub(lastTime) >= interval {
		s.scanLimiter[clientIP] = now
		return true
	}

	return false
}

// handleWebSocket handles WebSocket upgrade requests with security validation
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract and validate client IP
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP for WebSocket: %v", err)
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Serve WebSocket with security validation
	if err := s.wsHub.ServeWS(w, r, clientIP); err != nil {
		// Error already logged in ServeWS
		return
	}
}

// handleExportCSV exports scan results to CSV format
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	s.handleExport(w, r, export.FormatCSV)
}

// handleExportJSON exports scan results to JSON format
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	s.handleExport(w, r, export.FormatJSON)
}

// handleExportPDF exports scan results to PDF format
func (s *Server) handleExportPDF(w http.ResponseWriter, r *http.Request) {
	s.handleExport(w, r, export.FormatPDF)
}

// handleExport handles export requests with security validation
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, format export.ExportFormat) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if !s.validateCSRFToken(csrfToken) {
		log.Printf("[SECURITY] Invalid CSRF token for export request")
		logSecurityEvent("csrf_validation_failed", r.RemoteAddr, "blocked", "", map[string]interface{}{
			"action": "export",
			"format": format,
		})
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Extract and validate client IP
	clientIP, err := extractClientIPv6(r)
	if err != nil {
		log.Printf("[ERROR] Failed to extract client IP for export: %v", err)
		http.Error(w, "Failed to detect client IP address", http.StatusBadRequest)
		return
	}

	// Parse request body
	var scanResult scanner.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&scanResult); err != nil {
		log.Printf("[ERROR] Failed to parse export request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate scan result data
	if scanResult.Target == "" {
		http.Error(w, "Invalid scan result: missing target", http.StatusBadRequest)
		return
	}

	// Perform export with sanitization
	result, err := export.Export(&scanResult, clientIP, format)
	if err != nil {
		log.Printf("[ERROR] Export failed (format: %s): %v", format, err)
		logSecurityEvent("export_failed", clientIP, "failure", "", map[string]interface{}{
			"format": format,
			"error":  err.Error(),
		})
		http.Error(w, "Export failed", http.StatusInternalServerError)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", result.Filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(result.Data)))

	// Write file data
	w.Write(result.Data)

	log.Printf("[EXPORT] Exported scan results (format: %s, size: %d bytes)", format, len(result.Data))
	logSecurityEvent("export_completed", clientIP, "success", "", map[string]interface{}{
		"format": format,
		"size":   len(result.Data),
	})
}

// handleTranslations returns translations for a specific language
func (s *Server) handleTranslations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w)

	// Get language from query parameter (default: English)
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "en"
	}

	// Validate and sanitize language code
	validatedLang := i18n.ValidateLanguage(lang)

	// Get translations for the language
	translations, err := i18n.GetAllForLanguage(validatedLang)
	if err != nil {
		log.Printf("[ERROR] Failed to get translations for language %s: %v", lang, err)
		http.Error(w, "Failed to load translations", http.StatusInternalServerError)
		return
	}

	// Return translations as JSON
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(translations))
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en" id="html-root">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YggNmap - Yggdrasil Port Scanner</title>
    <style>
        :root {
            --bg-gradient-start: #667eea;
            --bg-gradient-end: #764ba2;
            --container-bg: #ffffff;
            --text-primary: #333333;
            --text-secondary: #666666;
            --text-muted: #888888;
            --accent-color: #667eea;
            --accent-light: #764ba2;
            --info-bg: #f8f9fa;
            --border-color: #eee;
            --button-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --error-bg: #f8d7da;
            --error-text: #721c24;
            --success-color: #28a745;
        }

        [data-theme="dark"] {
            --bg-gradient-start: #1a1a2e;
            --bg-gradient-end: #16213e;
            --container-bg: #0f3460;
            --text-primary: #e8e8e8;
            --text-secondary: #b8b8b8;
            --text-muted: #888888;
            --accent-color: #667eea;
            --accent-light: #764ba2;
            --info-bg: #1a2332;
            --border-color: #2a3a52;
            --button-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --error-bg: #4a1a1a;
            --error-text: #ff6b6b;
            --success-color: #51cf66;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            transition: background 0.3s ease;
        }

        .container {
            background: var(--container-bg);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 900px;
            width: 100%;
            padding: 40px;
            transition: background 0.3s ease;
        }

        .header-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .controls-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .theme-toggle, .lang-select {
            background: var(--button-bg);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }

        .theme-toggle:hover, .lang-select:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .lang-select {
            appearance: none;
            -webkit-appearance: none;
            -moz-appearance: none;
            padding-right: 30px;
            background-image: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            position: relative;
        }

        h1 {
            color: var(--accent-color);
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }

        .subtitle {
            text-align: center;
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1.1em;
        }

        .info-box {
            background: var(--info-bg);
            border-left: 4px solid var(--accent-color);
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 5px;
        }

        .info-label {
            font-weight: bold;
            color: var(--text-primary);
            margin-bottom: 5px;
        }

        .ygg-address {
            font-family: 'Courier New', monospace;
            color: var(--accent-color);
            font-size: 1.1em;
            word-break: break-all;
        }

        .about-section {
            margin-bottom: 30px;
            padding: 20px;
            background: var(--info-bg);
            border-radius: 10px;
        }

        .about-section h2 {
            color: var(--accent-light);
            margin-bottom: 10px;
            font-size: 1.3em;
        }

        .about-section p {
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 10px;
        }

        .button-group {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }

        button {
            flex: 1;
            min-width: 120px;
            background: var(--button-bg);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            font-size: 1.1em;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: bold;
        }

        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .export-buttons {
            display: none;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .export-btn {
            flex: 0 1 auto;
            min-width: 100px;
            font-size: 0.9em;
            padding: 10px 20px;
        }

        .loading {
            text-align: center;
            color: var(--accent-color);
            font-size: 1.1em;
            margin: 20px 0;
            display: none;
        }

        .spinner {
            border: 3px solid var(--border-color);
            border-top: 3px solid var(--accent-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .progress-bar-container {
            width: 100%;
            height: 20px;
            background: var(--info-bg);
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
            display: none;
        }

        .progress-bar {
            height: 100%;
            background: var(--button-bg);
            width: 0%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }

        .results {
            display: none;
        }

        .results-header {
            background: var(--accent-color);
            color: white;
            padding: 15px;
            border-radius: 10px 10px 0 0;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .results-body {
            border: 2px solid var(--accent-color);
            border-top: none;
            border-radius: 0 0 10px 10px;
            max-height: 400px;
            overflow-y: auto;
        }

        .port-item {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .port-item:last-child {
            border-bottom: none;
        }

        .port-item:hover {
            background: var(--info-bg);
        }

        .port-number {
            font-weight: bold;
            color: var(--accent-color);
            font-size: 1.2em;
        }

        .port-details {
            color: var(--text-secondary);
        }

        .no-ports {
            padding: 30px;
            text-align: center;
            color: var(--success-color);
            font-size: 1.1em;
        }

        .error {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            display: none;
        }

        .scan-info {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 10px;
            font-size: 0.9em;
        }

        .ws-status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #ccc;
            margin-left: 10px;
        }

        .ws-status.connected {
            background: var(--success-color);
        }

        .ws-status.connecting {
            background: #ffa500;
            animation: pulse 1s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        @media (max-width: 600px) {
            .container {
                padding: 20px;
            }

            h1 {
                font-size: 2em;
            }

            .button-group {
                flex-direction: column;
            }

            button {
                width: 100%;
            }

            /* Custom scan mobile styles */
            .custom-scan-container {
                flex-direction: column !important;
            }

            #custom-ports-input {
                width: 100% !important;
                margin-bottom: 10px;
                flex: none !important;
            }

            #custom-scan-btn {
                width: 100% !important;
                min-width: auto !important;
                flex: none !important;
            }

            /* Mobile header controls - unified styling */
            .header-controls {
                flex-direction: column;
                gap: 10px;
                align-items: stretch;
            }

            .controls-group {
                width: 100%;
                justify-content: space-between;
                flex-wrap: nowrap;
            }

            .theme-toggle {
                flex: 1;
                min-width: 0;
                padding: 10px 12px;
                font-size: 0.85em;
            }

            .lang-select {
                flex: 1;
                min-width: 0;
                padding: 10px 12px;
                font-size: 0.85em;
            }

            .ws-status {
                flex-shrink: 0;
                margin-left: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-controls">
            <div class="controls-group">
                <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn">
                    <span id="theme-icon">🌙</span> <span id="theme-text">Dark Mode</span>
                </button>
            </div>
            <div class="controls-group">
                <select class="lang-select" onchange="changeLanguage(this.value)" id="lang-select">
                    <option value="en">English</option>
                    <option value="ru">Русский</option>
                </select>
                <div class="ws-status" id="ws-status" title="WebSocket Status"></div>
            </div>
        </div>

        <h1 id="page-title">YggNmap</h1>
        <p class="subtitle" id="subtitle">Free Port Scanner for Yggdrasil Network</p>

        <div class="info-box">
            <div class="info-label" id="your-address-label">We will scan this IPv6 address:</div>
            <div class="ygg-address" id="ygg-address">Detecting your address...</div>
        </div>

        <div class="about-section">
            <h2 id="about-title">About This Service</h2>
            <p id="about-description">
                This is a free port scanning service for Yggdrasil Network users. We automatically detect
                your IPv6 address and scan it for open ports, helping you identify potential security
                vulnerabilities. No installation required - just click scan!
            </p>
            <p>
                <strong id="quick-scan-info-label">Quick Scan:</strong> <span id="quick-scan-info">Scans 1000 most common ports (30-60 seconds)</span><br>
                <strong id="full-scan-info-label">Full Scan:</strong> <span id="full-scan-info">Scans all 65,535 ports (5-15 minutes)</span>
            </p>
            <p style="font-size: 0.9em;" class="info-label">
                <span id="supports-info">Supports both 200::/8 (node addresses) and 300::/8 (subnet addresses)</span><br>
                <span id="rate-limit-info">Rate limits: Quick scan once per 30 seconds, Full scan once per 60 seconds</span>
            </p>
        </div>

        <div class="button-group">
            <button id="quick-scan-btn" onclick="startQuickScan()">Quick Scan</button>
            <button id="full-scan-btn" onclick="startFullScan()">Full Scan</button>
        </div>

        <div style="margin-bottom: 30px;">
            <label for="custom-ports-input" class="info-label" id="custom-scan-label" style="display: block; margin-bottom: 10px;">Scan specific ports:</label>
            <div class="custom-scan-container" style="display: flex; gap: 10px;">
                <input type="text" id="custom-ports-input" placeholder="e.g., 80,443 or 1-1000" style="flex: 1; padding: 15px; border-radius: 10px; border: 2px solid var(--border-color); background: var(--info-bg); color: var(--text-primary); font-size: 1em;">
                <button id="custom-scan-btn" onclick="startCustomScan()" style="flex: 0 0 auto; min-width: 180px;">Custom Scan</button>
            </div>
        </div>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <div id="loading-text">Scanning ports...</div>
            <div class="progress-bar-container" id="progress-container">
                <div class="progress-bar" id="progress-bar">0%</div>
            </div>
        </div>

        <div class="error" id="error"></div>

        <div class="results" id="results">
            <div class="results-header">
                <span id="results-title">Scan Results</span>
            </div>
            <div class="results-body" id="results-body"></div>
            <div class="scan-info" id="scan-info"></div>
            <div class="button-group export-buttons" id="export-buttons">
                <button class="export-btn" onclick="exportResults('csv')" id="export-csv-btn">Export CSV</button>
                <button class="export-btn" onclick="exportResults('json')" id="export-json-btn">Export JSON</button>
                <button class="export-btn" onclick="exportResults('pdf')" id="export-pdf-btn">Export PDF</button>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let csrfToken = null;
        let currentScanResult = null;
        let ws = null;
        let currentTheme = 'light';
        let currentLang = 'en';
        let translations = {};

        // Theme management
        function toggleTheme() {
            currentTheme = currentTheme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', currentTheme);
            localStorage.setItem('theme', currentTheme);
            updateThemeButton();
        }

        function updateThemeButton() {
            const themeIcon = document.getElementById('theme-icon');
            const themeText = document.getElementById('theme-text');
            if (currentTheme === 'dark') {
                themeIcon.textContent = '☀️';
                themeText.textContent = translations['light_mode'] || 'Light Mode';
            } else {
                themeIcon.textContent = '🌙';
                themeText.textContent = translations['dark_mode'] || 'Dark Mode';
            }
        }

        // Load saved theme
        function loadTheme() {
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme) {
                currentTheme = savedTheme;
                document.documentElement.setAttribute('data-theme', currentTheme);
            }
            updateThemeButton();
        }

        // Language management
        async function changeLanguage(lang) {
            currentLang = lang;
            localStorage.setItem('language', lang);
            await loadTranslations(lang);
            updateUIText();
        }

        async function loadTranslations(lang) {
            try {
                const response = await fetch('/api/translations?lang=' + lang);
                if (response.ok) {
                    translations = await response.json();
                }
            } catch (error) {
                console.error('Failed to load translations:', error);
            }
        }

        function t(key) {
            return translations[key] || key;
        }

        function updateUIText() {
            document.getElementById('subtitle').textContent = t('subtitle');
            document.getElementById('your-address-label').textContent = t('your_address');
            document.getElementById('about-title').textContent = t('about_title');
            document.getElementById('about-description').textContent = t('about_description');
            document.getElementById('quick-scan-info-label').textContent = t('quick_scan_info').split(':')[0] + ':';
            document.getElementById('quick-scan-info').textContent = t('quick_scan_info').split(':').slice(1).join(':');
            document.getElementById('full-scan-info-label').textContent = t('full_scan_info').split(':')[0] + ':';
            document.getElementById('full-scan-info').textContent = t('full_scan_info').split(':').slice(1).join(':');
            document.getElementById('supports-info').textContent = t('supports_info');
            document.getElementById('rate-limit-info').textContent = t('rate_limit_info');
            document.getElementById('quick-scan-btn').textContent = t('quick_scan_btn');
            document.getElementById('full-scan-btn').textContent = t('full_scan_btn');
            document.getElementById('custom-scan-btn').textContent = t('custom_scan_btn');
            document.getElementById('custom-scan-label').textContent = t('custom_scan_info').split(':')[0] + ':';
            document.getElementById('custom-ports-input').placeholder = t('port_input_placeholder');
            document.getElementById('export-csv-btn').textContent = t('export_csv');
            document.getElementById('export-json-btn').textContent = t('export_json');
            document.getElementById('export-pdf-btn').textContent = t('export_pdf');
            updateThemeButton();
        }

        // WebSocket management
        function connectWebSocket() {
            if (!csrfToken) {
                console.log('Cannot connect WebSocket: No CSRF token');
                return;
            }

            const wsStatus = document.getElementById('ws-status');
            wsStatus.className = 'ws-status connecting';

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/api/ws?csrf_token=' + encodeURIComponent(csrfToken);

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                console.log('WebSocket connected');
                wsStatus.className = 'ws-status connected';
            };

            ws.onmessage = function(event) {
                try {
                    const update = JSON.parse(event.data);
                    handleProgressUpdate(update);
                } catch (error) {
                    console.error('WebSocket message error:', error);
                }
            };

            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
                wsStatus.className = 'ws-status';
            };

            ws.onclose = function() {
                console.log('WebSocket disconnected');
                wsStatus.className = 'ws-status';
                // Attempt reconnection after 5 seconds
                setTimeout(connectWebSocket, 5000);
            };
        }

        function handleProgressUpdate(update) {
            const progressContainer = document.getElementById('progress-container');
            const progressBar = document.getElementById('progress-bar');
            const loadingText = document.getElementById('loading-text');

            if (update.type === 'progress') {
                progressContainer.style.display = 'block';
                progressBar.style.width = update.progress + '%';
                progressBar.textContent = update.progress + '%';
                loadingText.textContent = update.message;
            } else if (update.type === 'port_found') {
                loadingText.textContent = update.message;
            }
        }

        // Initialization
        window.addEventListener('DOMContentLoaded', async () => {
            loadTheme();

            // Load saved language
            const savedLang = localStorage.getItem('language') || 'en';
            currentLang = savedLang;
            document.getElementById('lang-select').value = savedLang;
            await loadTranslations(savedLang);
            updateUIText();

            try {
                // Fetch CSRF token
                const csrfResponse = await fetch('/api/csrf-token');
                if (!csrfResponse.ok) {
                    throw new Error('Failed to get CSRF token');
                }
                const csrfData = await csrfResponse.json();
                csrfToken = csrfData.csrf_token;
                console.log('CSRF token acquired');

                // Connect WebSocket
                connectWebSocket();

                // Fetch client IP address
                const response = await fetch('/api/info');

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(errorText || 'Failed to load address (HTTP ' + response.status + ')');
                }

                const data = await response.json();

                if (!data.ygg_address) {
                    throw new Error('Server did not return an address');
                }

                document.getElementById('ygg-address').textContent = data.ygg_address;
                console.log('Successfully loaded address:', data.ygg_address);
            } catch (error) {
                console.error('Error during initialization:', error);
                document.getElementById('ygg-address').textContent = 'Error: ' + error.message;
                document.getElementById('ygg-address').style.color = '#dc3545';
                showError(t('error_init').replace('%s', error.message));
                document.getElementById('quick-scan-btn').disabled = true;
                document.getElementById('full-scan-btn').disabled = true;
            }
        });

        async function startQuickScan() {
            await performScan('/api/quick-scan', t('scan_results_quick'));
        }

        async function startFullScan() {
            await performScan('/api/scan', t('scan_results_full'));
        }

        async function startCustomScan() {
            const portsInput = document.getElementById('custom-ports-input');
            const ports = portsInput.value.trim();

            if (!ports) {
                showError(t('error_ports_required'));
                return;
            }

            await performScan('/api/custom-scan', t('scan_results_custom'), {ports: ports});
        }

        async function performScan(endpoint, title, body = null) {
            if (!csrfToken) {
                showError(t('error_csrf'));
                return;
            }

            // Disable buttons
            document.getElementById('quick-scan-btn').disabled = true;
            document.getElementById('full-scan-btn').disabled = true;
            document.getElementById('custom-scan-btn').disabled = true;

            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('progress-container').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('error').style.display = 'none';
            document.getElementById('export-buttons').style.display = 'none';

            try {
                const headers = {'X-CSRF-Token': csrfToken};
                if (body) {
                    headers['Content-Type'] = 'application/json';
                }

                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: headers,
                    body: body ? JSON.stringify(body) : undefined
                });

                if (!response.ok) {
                    const errorText = await response.text();

                    if (response.status === 403) {
                        console.log('CSRF token expired, refreshing...');
                        const csrfResponse = await fetch('/api/csrf-token');
                        if (csrfResponse.ok) {
                            const csrfData = await csrfResponse.json();
                            csrfToken = csrfData.csrf_token;
                            throw new Error(t('error_csrf_expired'));
                        }
                    }

                    if (response.status === 429) {
                        // Rate limit exceeded - determine which scan type
                        if (endpoint === '/api/quick-scan') {
                            throw new Error(t('error_rate_limit_quick'));
                        } else if (endpoint === '/api/scan') {
                            throw new Error(t('error_rate_limit_full'));
                        } else if (endpoint === '/api/custom-scan') {
                            throw new Error(t('error_rate_limit_custom'));
                        }
                    }

                    if (response.status === 503) {
                        throw new Error(t('error_server_busy'));
                    }

                    throw new Error(errorText || 'Scan failed');
                }

                const data = await response.json();
                currentScanResult = data;
                displayResults(data, title);
            } catch (error) {
                showError(t('error_scan').replace('%s', error.message));
            } finally {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('progress-container').style.display = 'none';
                document.getElementById('quick-scan-btn').disabled = false;
                document.getElementById('full-scan-btn').disabled = false;
                document.getElementById('custom-scan-btn').disabled = false;
            }
        }

        function displayResults(data, title) {
            const resultsDiv = document.getElementById('results');
            const resultsBody = document.getElementById('results-body');
            const resultsTitle = document.getElementById('results-title');
            const scanInfo = document.getElementById('scan-info');
            const exportButtons = document.getElementById('export-buttons');

            resultsTitle.textContent = title;
            resultsBody.innerHTML = '';

            if (data.error) {
                showError(data.error);
                return;
            }

            if (data.ports && data.ports.length > 0) {
                data.ports.forEach(function(port) {
                    const portItem = document.createElement('div');
                    portItem.className = 'port-item';
                    portItem.innerHTML = '<div class="port-number">' + t('port') + ' ' + port.port + '/' + port.protocol + '</div>' +
                        '<div class="port-details">' +
                        '<strong>' + port.state + '</strong> - ' + (port.service || 'unknown') +
                        '</div>';
                    resultsBody.appendChild(portItem);
                });
            } else {
                resultsBody.innerHTML = '<div class="no-ports">' + t('no_ports_found') + '</div>';
            }

            // Always show export buttons after scan completes
            exportButtons.style.display = 'flex';

            const scanCompletedText = t('scan_completed')
                .replace('%.2f', data.duration.toFixed(2))
                .replace('%d', (data.ports ? data.ports.length : 0));
            scanInfo.textContent = scanCompletedText;
            resultsDiv.style.display = 'block';
        }

        function showError(message) {
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        async function exportResults(format) {
            if (!currentScanResult || !csrfToken) {
                showError(t('error_export').replace('%s', 'No scan results available'));
                return;
            }

            try {
                const response = await fetch('/api/export/' + format, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(currentScanResult)
                });

                if (!response.ok) {
                    throw new Error('Export failed');
                }

                // Download file
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;

                // Extract filename from Content-Disposition header
                const disposition = response.headers.get('Content-Disposition');
                let filename = 'yggnmap_export.' + format;
                if (disposition) {
                    const matches = /filename=([^;]+)/.exec(disposition);
                    if (matches && matches[1]) {
                        filename = matches[1].trim();
                    }
                }

                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } catch (error) {
                showError(t('error_export').replace('%s', error.message));
            }
        }
    </script>
</body>
</html>
`
