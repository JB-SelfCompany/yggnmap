package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/JB-SelfCompany/yggnmap/validator"
)

// ProgressUpdate represents a scan progress update message
type ProgressUpdate struct {
	Type       string  `json:"type"`        // "progress", "port_found", "completed", "error"
	Progress   int     `json:"progress"`    // 0-100
	Message    string  `json:"message"`     // Progress message (sanitized)
	Port       *int    `json:"port,omitempty"`
	Protocol   string  `json:"protocol,omitempty"`
	Service    string  `json:"service,omitempty"`
	TotalPorts int     `json:"total_ports,omitempty"`
	ScanType   string  `json:"scan_type,omitempty"`
}

// Hub manages WebSocket connections with rate limiting
type Hub struct {
	// Registered connections per client IP
	connections map[string]*Client
	connMu      sync.RWMutex

	// Rate limiting for WebSocket connections
	connectionLimiter map[string]time.Time
	limiterMu         sync.Mutex

	// CSRF tokens
	csrfTokens   map[string]time.Time
	csrfMu       *sync.RWMutex
	csrfLifetime time.Duration

	// Upgrade WebSocket connections
	upgrader websocket.Upgrader
}

// Client represents a WebSocket client connection
type Client struct {
	hub        *Hub
	conn       *websocket.Conn
	send       chan []byte
	clientIP   string
	mu         sync.Mutex
	lastActive time.Time
}

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512

	// WebSocket connection rate limit per IP
	wsConnectionInterval = 5 * time.Second

	// Maximum concurrent connections per IP
	maxConnectionsPerIP = 2
)

// NewHub creates a new WebSocket hub
func NewHub(csrfTokens map[string]time.Time, csrfMu *sync.RWMutex, csrfLifetime time.Duration) *Hub {
	return &Hub{
		connections:       make(map[string]*Client),
		connectionLimiter: make(map[string]time.Time),
		csrfTokens:        csrfTokens,
		csrfMu:            csrfMu,
		csrfLifetime:      csrfLifetime,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			// CheckOrigin: Allow connections from same origin only
			CheckOrigin: func(r *http.Request) bool {
				// In production with reverse proxy, implement proper origin checking
				// For now, we'll allow connections (since no HTTPS is by design)
				return true
			},
		},
	}
}

// checkConnectionRateLimit checks if a client can establish a new WebSocket connection
func (h *Hub) checkConnectionRateLimit(clientIP string) bool {
	h.limiterMu.Lock()
	defer h.limiterMu.Unlock()

	lastTime, exists := h.connectionLimiter[clientIP]
	now := time.Now()

	if !exists || now.Sub(lastTime) >= wsConnectionInterval {
		h.connectionLimiter[clientIP] = now
		return true
	}

	return false
}

// ValidateCSRFToken validates a CSRF token
func (h *Hub) ValidateCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	h.csrfMu.RLock()
	createdAt, exists := h.csrfTokens[token]
	h.csrfMu.RUnlock()

	if !exists {
		return false
	}

	// Check if token is expired
	if time.Since(createdAt) > h.csrfLifetime {
		h.csrfMu.Lock()
		delete(h.csrfTokens, token)
		h.csrfMu.Unlock()
		return false
	}

	return true
}

// ServeWS handles WebSocket requests with strict security validation
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, clientIP string) error {
	// Validate CSRF token from query parameter
	csrfToken := r.URL.Query().Get("csrf_token")
	if !h.ValidateCSRFToken(csrfToken) {
		log.Printf("[SECURITY] Invalid CSRF token for WebSocket")
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return fmt.Errorf("invalid CSRF token")
	}

	// Strict IPv6 validation
	if err := validator.ValidateIPv6Strict(clientIP); err != nil {
		log.Printf("[SECURITY] Invalid IPv6 for WebSocket: %v", err)
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return fmt.Errorf("invalid client IP: %w", err)
	}

	// Rate limiting for WebSocket connections
	if !h.checkConnectionRateLimit(clientIP) {
		log.Printf("[RATE_LIMIT] WebSocket connection rate limit exceeded")
		http.Error(w, "Rate limit exceeded. Please wait before reconnecting.", http.StatusTooManyRequests)
		return fmt.Errorf("rate limit exceeded")
	}

	// Check if client already has a connection
	h.connMu.RLock()
	existingClient, exists := h.connections[clientIP]
	h.connMu.RUnlock()

	if exists {
		// Close existing connection before creating new one
		existingClient.Close()
	}

	// Upgrade connection
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}

	// Create new client
	client := &Client{
		hub:        h,
		conn:       conn,
		send:       make(chan []byte, 256),
		clientIP:   clientIP,
		lastActive: time.Now(),
	}

	// Register client
	h.connMu.Lock()
	h.connections[clientIP] = client
	h.connMu.Unlock()

	log.Printf("[WEBSOCKET] Client connected")

	// Start client goroutines
	go client.writePump()
	go client.readPump()

	return nil
}

// SendProgress sends a progress update to a specific client
func (h *Hub) SendProgress(clientIP string, update ProgressUpdate) error {
	// Sanitize message to prevent XSS
	update.Message = validator.SanitizeForLog(update.Message)

	h.connMu.RLock()
	client, exists := h.connections[clientIP]
	h.connMu.RUnlock()

	if !exists {
		return fmt.Errorf("client not connected")
	}

	// Marshal update to JSON
	data, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal update: %w", err)
	}

	// Send to client (non-blocking)
	select {
	case client.send <- data:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("send timeout")
	}
}

// Close closes a client connection
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove from hub
	c.hub.connMu.Lock()
	delete(c.hub.connections, c.clientIP)
	c.hub.connMu.Unlock()

	// Close connection
	c.conn.Close()
	close(c.send)

	log.Printf("[WEBSOCKET] Client disconnected")
}

// readPump pumps messages from the WebSocket connection
func (c *Client) readPump() {
	defer c.Close()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		c.lastActive = time.Now()
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WEBSOCKET] Read error: %v", err)
			}
			break
		}

		// We don't expect messages from client, so just log and ignore
		log.Printf("[WEBSOCKET] Unexpected message: %s", validator.SanitizeForLog(string(message)))
	}
}

// writePump pumps messages to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current websocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// BroadcastToClient sends a message to a specific client by IP
func (h *Hub) BroadcastToClient(clientIP string, messageType string, data interface{}) {
	msg := map[string]interface{}{
		"type": messageType,
		"data": data,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal WebSocket message: %v", err)
		return
	}

	h.connMu.RLock()
	client, exists := h.connections[clientIP]
	h.connMu.RUnlock()

	if exists {
		select {
		case client.send <- jsonData:
		default:
			// Buffer full, close slow client
			client.Close()
		}
	}
}

// CleanupInactive removes inactive connections
func (h *Hub) CleanupInactive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			h.connMu.Lock()
			for _, client := range h.connections {
				if now.Sub(client.lastActive) > 5*time.Minute {
					log.Printf("[WEBSOCKET] Closing inactive connection")
					client.Close()
				}
			}
			h.connMu.Unlock()
		}
	}
}
