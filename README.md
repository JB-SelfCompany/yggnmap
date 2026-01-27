<div align="center">

# 🔍 YggNmap

### Yggdrasil Network Port Scanner Service

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev/)
[![Yggdrasil](https://img.shields.io/badge/Yggdrasil-Network-green)](https://yggdrasil-network.github.io/)
[![Downloads](https://img.shields.io/github/downloads/JB-SelfCompany/yggnmap/total)](https://github.com/JB-SelfCompany/yggnmap/releases)
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=JB-SelfCompany.yggnmap)](https://github.com/JB-SelfCompany/yggnmap)

**Zero-installation port scanning for Yggdrasil users**

**Languages:** 🇬🇧 English | [🇷🇺 Русский](README.ru.md)

[Quick Start](#quick-start) • [Features](#features) • [Installation](#installation) • [Documentation](#documentation)

</div>

---

## Overview

YggNmap is a free web-based port scanning service designed for the Yggdrasil Network. Users simply visit the website and their IPv6 address is automatically scanned for open ports - **no installation or configuration required**!

> [!NOTE]
> This service requires only a web browser and an active Yggdrasil connection. The server operator runs nmap, not the end users.

### Why YggNmap?

| Feature | YggNmap | Traditional Tools |
|---------|---------|-------------------|
| **Installation** | None required | Install nmap locally |
| **Configuration** | Automatic | Manual setup |
| **Supported Addresses** | 200::/7 + 300::/8 | IPv6 only |
| **Real-time Progress** | WebSocket updates | Command line only |
| **Export Results** | CSV, JSON, PDF | Manual parsing |

---

## Quick Start

### For Users

1. **Ensure Yggdrasil is running** on your machine
2. **Visit the service** at `http://[server-ipv6]:8080/`
3. **Click "Quick Scan"** or choose your scan type
4. **View results** in real-time

That's it! No nmap installation needed.

### For Server Operators

```bash
# Install dependencies
sudo apt install nmap  # Linux
brew install nmap      # macOS

# Build and run
go build -o yggnmap
./yggnmap
```

The service will automatically detect your Yggdrasil addresses and display access URLs.

---

## Features

### User Experience

<details>
<summary><b>Core Scanning Features</b></summary>

- **Automatic IP Detection** - Server detects your Yggdrasil IPv6 automatically
- **Three Scan Modes:**
  - **Quick Scan** - Top 1000 common ports (~1-3 minutes)
  - **Full Scan** - All 65,535 ports (10-30 minutes)
  - **Custom Scan** - Specific ports or ranges (user-defined)
- **Real-Time Progress** - WebSocket-powered live updates with progress bar
- **Port Discovery Notifications** - Instant alerts when open ports are found

</details>

<details>
<summary><b>Interface & Usability</b></summary>

- **Dark Mode** - Toggle between light and dark themes
- **Multi-Language Support** - English and Russian interfaces
- **Export Results** - Download scan results in CSV, JSON, or PDF formats
- **Responsive Design** - Works on desktop and mobile browsers
- **Zero Configuration** - Just visit and scan

</details>

<details>
<summary><b>Yggdrasil Network Support</b></summary>

YggNmap fully supports both Yggdrasil address types:

| Address Type | Prefix | Example | Use Case |
|--------------|--------|---------|----------|
| **Node Addresses** | 200::/7 | `200:1234:5678:9abc:def0::1` | Direct Yggdrasil nodes |
| **Subnet Addresses** | 300::/8 | `300:1234:5678:9abc::1` | Devices behind routers |

Both work identically - the service automatically detects and scans either type.

</details>

### Security & Privacy

> [!IMPORTANT]
> YggNmap implements comprehensive security measures to protect both users and server operators.

<details>
<summary><b>Security Features (Click to expand)</b></summary>

**Input Protection:**
- Strict IPv6 validation (CWE-78 prevention)
- Command injection prevention
- Log injection sanitization
- Path traversal prevention
- CSV injection prevention (formula escaping)

**Request Protection:**
- CSRF token validation (30-minute expiration)
- Multi-layer rate limiting (per-IP + global)
- Request size limits (1 MB max)
- Request timeouts (Slowloris protection)
- Global concurrency control (max 10 scans)

**Application Security:**
- HTTP security headers (CSP, X-Frame-Options, etc.)
- Memory leak prevention (auto-cleanup every 5 minutes)
- Graceful shutdown handling
- Error message sanitization
- Yggdrasil address validation (200::/7, 300::/8 only)

**Privacy Protection:**
- **Client IPs never logged** - Complete privacy preservation
- No scan results stored permanently
- No user tracking or analytics
- In-memory state only
- Auto-expiring CSRF tokens

**WebSocket Security:**
- CSRF validation for connections
- Rate limiting (5s between connections)
- Connection limits (max 2 per IP)
- Automatic cleanup (60s timeout)
- Message size limits (512 bytes)

</details>

### Rate Limits

To prevent abuse while allowing legitimate security checks:

| Scan Type | Rate Limit | Global Limit |
|-----------|------------|--------------|
| Quick Scan | 1 per 30s per IP | 10 concurrent scans |
| Full Scan | 1 per 60s per IP | 10 concurrent scans |
| Custom Scan | 1 per 45s per IP | 10 concurrent scans |

Memory cleanup runs every 5 minutes to remove old entries.

---

## Installation

### Prerequisites

**For Server Operators:**

- [Yggdrasil](https://yggdrasil-network.github.io/installation.html) - Connected to the network
- [nmap](https://nmap.org/) - Port scanning tool
- [Go 1.22+](https://go.dev/) - For building from source

**For End Users:**

- Yggdrasil connection only (no nmap needed!)

### Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd yggnmap

# Download dependencies
go mod tidy

# Build
go build -o yggnmap

# Run
./yggnmap
```

### Cross-Compile for Multiple Platforms

```bash
./build.sh
```

Binaries will be in the `dist/` directory.

### Running the Server

```bash
# Default: Listen on all IPv6 interfaces, port 8080
./yggnmap

# Custom port
./yggnmap -port 9090

# Specific Yggdrasil IPv6
./yggnmap -listen 200:1234:5678::1

# Show help
./yggnmap -help
```

**Expected Output:**

```
YggNmap - Yggdrasil Network Port Scanner Service
=================================================
Configuration:
  Listen Address: ::
  Port: 8080

Starting YggNmap server on :8080

Detected Yggdrasil addresses:
  - 200:1234:5678:9abc:def0:1122:3344:5566 (node address (200::/7))
  - 300:1234:5678:9abc::1 (subnet address (300::/8))

PRIMARY ACCESS URL: http://[200:1234:5678:9abc:def0:1122:3344:5566]:8080/

Ready to accept connections!
```

### Production Setup (Linux)

For production deployment, follow these steps to set up a dedicated user and proper directory structure:

<details>
<summary><b>Step 1: Install Dependencies</b></summary>

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap

# RHEL/CentOS/Fedora
sudo yum install nmap

# Verify installation
nmap --version
```

</details>

<details>
<summary><b>Step 2: Create Dedicated User</b></summary>

Create a system user for running the service (no login shell for security):

```bash
# Create system user without home directory and login shell
sudo useradd --system --no-create-home --shell /bin/false yggnmap

# Verify user was created
id yggnmap
# Output: uid=999(yggnmap) gid=999(yggnmap) groups=999(yggnmap)
```

</details>

<details>
<summary><b>Step 3: Create Application Directory</b></summary>

```bash
# Create application directory
sudo mkdir -p /opt/yggnmap

# Set ownership to yggnmap user
sudo chown yggnmap:yggnmap /opt/yggnmap

# Set appropriate permissions
sudo chmod 755 /opt/yggnmap

# Verify
ls -ld /opt/yggnmap
# Output: drwxr-xr-x 2 yggnmap yggnmap 4096 Jan 4 12:00 /opt/yggnmap
```

</details>

<details>
<summary><b>Step 4: Install Binary</b></summary>

```bash
# Copy the compiled binary to application directory
sudo cp yggnmap /opt/yggnmap/yggnmap

# Set ownership to yggnmap user
sudo chown yggnmap:yggnmap /opt/yggnmap/yggnmap

# Make it executable
sudo chmod 755 /opt/yggnmap/yggnmap

# Verify
ls -l /opt/yggnmap/yggnmap
# Output: -rwxr-xr-x 1 yggnmap yggnmap 12345678 Jan 4 12:00 /opt/yggnmap/yggnmap

# Test the binary
/opt/yggnmap/yggnmap -help
```

</details>

<details>
<summary><b>Step 5: Configure Firewall (Optional)</b></summary>

If you're running a firewall, allow the service port:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8080/tcp
sudo ufw status

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports

# iptables (manual)
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

</details>

<details>
<summary><b>Step 6: Create Log Directory (Optional)</b></summary>

If you want to redirect logs to a file:

```bash
# Create log directory
sudo mkdir -p /var/log/yggnmap

# Set ownership
sudo chown yggnmap:yggnmap /var/log/yggnmap

# Set permissions
sudo chmod 755 /var/log/yggnmap
```

</details>

Now proceed to set up the systemd service below.

<details>
<summary><b>Systemd Service Configuration</b></summary>

Create `/etc/systemd/system/yggnmap.service`:

```ini
[Unit]
Description=YggNmap Port Scanner Service
After=network.target yggdrasil.service
Requires=yggdrasil.service

[Service]
Type=simple
User=yggnmap
Group=yggnmap
WorkingDirectory=/opt/yggnmap

# Main service command
ExecStart=/opt/yggnmap/yggnmap -listen :: -port 8080

# Restart settings
Restart=on-failure
RestartSec=5s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/yggnmap

# Logging (optional - uncomment to enable file logging)
# StandardOutput=append:/var/log/yggnmap/yggnmap.log
# StandardError=append:/var/log/yggnmap/yggnmap.log

[Install]
WantedBy=multi-user.target
```

**Enable and start the service:**

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable yggnmap

# Start the service
sudo systemctl start yggnmap

# Check service status
sudo systemctl status yggnmap

# View logs
sudo journalctl -u yggnmap -f
# Or if file logging is enabled:
# sudo tail -f /var/log/yggnmap/yggnmap.log
```

**Useful systemd commands:**

```bash
# Stop the service
sudo systemctl stop yggnmap

# Restart the service
sudo systemctl restart yggnmap

# View full logs
sudo journalctl -u yggnmap --no-pager

# View recent logs
sudo journalctl -u yggnmap -n 50
```

</details>

### Reverse Proxy Setup (Optional)

YggNmap can be deployed behind a reverse proxy for additional features like caching or load balancing.

> [!NOTE]
> The server automatically detects and uses client IP from proxy headers (X-Forwarded-For, X-Real-IP).

<details>
<summary><b>Nginx Configuration Example</b></summary>

Create `/etc/nginx/sites-available/yggnmap`:

```nginx
server {
    listen [::]:80;
    listen 80;
    server_name yggnmap.ygg;

    # Pass real client IP to backend
    location / {
        proxy_pass http://[::1]:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Increase timeouts for long scans
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }
}
```

**Enable and restart Nginx:**

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/yggnmap /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

**Important:** When using a reverse proxy, the server will automatically detect the client's real IP from the `X-Forwarded-For` or `X-Real-IP` headers and use it for scanning and rate limiting.

</details>

<details>
<summary><b>Caddy Configuration Example (Recommended for Yggdrasil)</b></summary>

Caddy is simpler to configure and works well with IPv6:

Create `Caddyfile`:

```caddy
http://[200:1234::1]:80 {
    reverse_proxy localhost:8080 {
        # Preserve real client IP
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}

        # WebSocket support (automatic in Caddy)
    }
}
```

**Run Caddy:**

```bash
# Install Caddy
sudo apt install caddy  # Ubuntu/Debian

# Run with Caddyfile
sudo caddy run --config Caddyfile

# Or install as systemd service
sudo caddy start --config Caddyfile
```

</details>

---

## Documentation

### Architecture

```
┌─────────────┐                 ┌─────────────┐
│   Browser   │ ──── HTTP ────> │   Server    │
│  (Client)   │ <── WebSocket ─ │  (Golang)   │
└─────────────┘                 └──────┬──────┘
                                       │
                                       ▼
                                  ┌─────────┐
                                  │  nmap   │
                                  └─────────┘
```

**Data Flow:**

1. User visits website → Server detects IPv6 from request
2. JavaScript fetches CSRF token
3. User initiates scan → WebSocket connection established
4. Server validates request (CSRF, rate limits, concurrency)
5. nmap scans client's IPv6 with progress callbacks
6. Real-time updates sent via WebSocket
7. Results displayed in browser
8. Optional: Export to CSV/JSON/PDF

<details>
<summary><b>Project Structure</b></summary>

```
yggnmap/
├── main.go                 # Entry point, CLI, graceful shutdown
├── scanner/
│   └── scanner.go          # nmap wrapper with progress callbacks
├── server/
│   ├── server.go           # HTTP server, API endpoints, security
│   └── template.html       # Embedded web interface
├── websocket/
│   └── websocket.go        # WebSocket hub for real-time updates
├── export/
│   └── export.go           # Export to CSV, JSON, PDF
├── i18n/
│   └── i18n.go             # Internationalization (EN/RU)
├── validator/
│   └── validator.go        # Input validation and sanitization
├── yggdrasil/
│   └── detector.go         # Yggdrasil address detection
├── dist/                   # Compiled binaries
├── build.sh                # Cross-compilation script
├── go.mod                  # Dependencies
├── README.md               # This file (English)
└── README.ru.md            # Russian documentation
```

</details>

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/api/info` | GET | Get client IPv6 |
| `/api/csrf-token` | GET | Get CSRF token |
| `/api/quick-scan` | POST | Quick scan (top 1000 ports) |
| `/api/scan` | POST | Full scan (all 65535 ports) |
| `/api/custom-scan` | POST | Custom port scan |
| `/api/export/{format}` | GET | Export results (csv/json/pdf) |
| `/ws` | WebSocket | Real-time scan progress |

### Dependencies

```go
require (
    github.com/Ullaakut/nmap/v3       // nmap Go bindings
    github.com/gorilla/websocket      // WebSocket support
    github.com/jung-kurt/gofpdf       // PDF generation
)
```

---

## Development

### Building

```bash
# Standard build
go build -o yggnmap

# Optimized build (smaller binary)
go build -ldflags "-s -w" -o yggnmap
```

### Security Testing

```bash
# Start server
./yggnmap

# Test CSRF protection
# Open browser console - should see "CSRF token acquired"

# Test rate limiting
# Perform rapid scans - should see rate limit errors

# Test concurrency
# Open 10+ browser tabs and scan simultaneously
```

**Monitor security logs:**

```bash
tail -f yggnmap.log | grep SECURITY

# Example output (note: no client IPs logged):
# [SECURITY] type=scan_started outcome=success details=map[scan_type:quick]
# [RATE_LIMIT] Quick scan rate limit exceeded
# [WEBSOCKET] Client connected
```

---

## Troubleshooting

<details>
<summary><b>Common Server Issues</b></summary>

**"nmap not found"**
```bash
# Install nmap
sudo apt install nmap      # Ubuntu/Debian
sudo yum install nmap      # RHEL/CentOS
brew install nmap          # macOS

# Verify installation
which nmap
nmap --version
```

**"Permission denied on port 80/443"**
- Use ports > 1024 (e.g., 8080)
- Or run with appropriate permissions
- Default port 8080 works without root

**"Server not accessible"**
```bash
# Check Yggdrasil is running
yggdrasilctl getSelf

# Verify firewall
sudo ufw allow 8080/tcp

# Check server is listening
netstat -tlnp | grep 8080
```

</details>

<details>
<summary><b>Common Client Issues</b></summary>

**"Can't connect to service"**
- Ensure Yggdrasil is running: `yggdrasilctl getSelf`
- Verify server URL is correct (use brackets: `http://[ipv6]:8080`)
- Try accessing from server locally first: `http://localhost:8080`

**"Rate limit exceeded"**
- This is normal - prevents abuse
- Wait 30-60 seconds between scans
- Quick scan: 30s cooldown
- Full scan: 60s cooldown

**"No open ports found"**
- This is good! Your node is secure
- Verify services are actually running
- Check firewall rules

</details>

---

## Roadmap

### Recently Implemented

- [x] WebSocket real-time scan progress
- [x] Export results (CSV, JSON, PDF)
- [x] Dark mode theme
- [x] Multi-language support (EN/RU)
- [x] Custom port scanning
- [x] Privacy-preserving logging
- [x] Comprehensive security features

### Future Enhancements

- [ ] Additional languages (ES, ZH, DE)
- [ ] Docker container
- [ ] More export formats (HTML, XML)

---

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Run tests: `go test ./...`
5. Commit: `git commit -am 'Add feature'`
6. Push: `git push origin feature-name`
7. Submit a pull request

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Add tests for new features
- Update documentation
- Keep functions small and focused
- Handle errors explicitly

---

## License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

> [!WARNING]
> Use this tool responsibly. Only scan systems you own or have explicit permission to scan. The authors are not responsible for misuse.

---

## Acknowledgments

- **Yggdrasil Network** - [yggdrasil-network.github.io](https://yggdrasil-network.github.io/)
- **nmap** - [nmap.org](https://nmap.org/)
- **Ullaakut/nmap** - [Go nmap library](https://github.com/Ullaakut/nmap)
- **Gorilla WebSocket** - [gorilla/websocket](https://github.com/gorilla/websocket)
- **gofpdf** - [jung-kurt/gofpdf](https://github.com/jung-kurt/gofpdf)

---

## Support

For issues or questions:

- Review [Yggdrasil documentation](https://yggdrasil-network.github.io/)
- Check [existing issues](../../issues)
- Create a [new issue](../../issues/new)

---

<div align="center">

**Made with ❤️ for the Yggdrasil Network community**

[⬆ Back to Top](#-yggnmap)

</div>
