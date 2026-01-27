#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Version from internal/version/version.go
VERSION_FILE="internal/version/version.go"
if [ -f "$VERSION_FILE" ]; then
    VERSION=$(grep -oP 'var Version = "\K[^"]+' "$VERSION_FILE" 2>/dev/null || echo "dev")
else
    VERSION="dev"
fi
VERSION_PKG="github.com/JB-SelfCompany/yggnmap/internal/version"
BIN_DIR="bin"
DIST_DIR="dist"

echo -e "${GREEN}YggNmap Build Script${NC}"
echo -e "${GREEN}Version: ${VERSION}${NC}"
echo ""

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Dependencies OK${NC}"
echo ""

# Download Go dependencies
echo -e "${YELLOW}Downloading Go dependencies...${NC}"
go mod download
go mod verify
echo -e "${GREEN}✓ Go dependencies downloaded${NC}"
echo ""

# Create output directories
mkdir -p "${BIN_DIR}"
mkdir -p "${DIST_DIR}"

# Build for all platforms
echo -e "${YELLOW}Building binaries for all platforms...${NC}"
echo ""

# Linux AMD64
echo -e "${YELLOW}Building Linux AMD64...${NC}"
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-linux-amd64" .
echo -e "${GREEN}✓ Linux AMD64 built${NC}"

# Linux ARM64
echo -e "${YELLOW}Building Linux ARM64...${NC}"
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-linux-arm64" .
echo -e "${GREEN}✓ Linux ARM64 built${NC}"

# Windows AMD64
echo -e "${YELLOW}Building Windows AMD64...${NC}"
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-windows-amd64.exe" .
echo -e "${GREEN}✓ Windows AMD64 built${NC}"

# macOS AMD64
echo -e "${YELLOW}Building macOS AMD64...${NC}"
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-darwin-amd64" .
echo -e "${GREEN}✓ macOS AMD64 built${NC}"

# macOS ARM64 (Apple Silicon)
echo -e "${YELLOW}Building macOS ARM64...${NC}"
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-darwin-arm64" .
echo -e "${GREEN}✓ macOS ARM64 built${NC}"

# FreeBSD AMD64
echo -e "${YELLOW}Building FreeBSD AMD64...${NC}"
GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-X ${VERSION_PKG}.Version=${VERSION} -s -w" -o "${BIN_DIR}/yggnmap-freebsd-amd64" .
echo -e "${GREEN}✓ FreeBSD AMD64 built${NC}"

echo ""
echo -e "${YELLOW}Creating distribution archives...${NC}"

# Create archives for each platform
if command -v tar &> /dev/null; then
    # Linux AMD64
    tar -czf "${DIST_DIR}/yggnmap-${VERSION}-linux-amd64.tar.gz" -C "${BIN_DIR}" yggnmap-linux-amd64
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-linux-amd64.tar.gz${NC}"

    # Linux ARM64
    tar -czf "${DIST_DIR}/yggnmap-${VERSION}-linux-arm64.tar.gz" -C "${BIN_DIR}" yggnmap-linux-arm64
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-linux-arm64.tar.gz${NC}"

    # macOS AMD64
    tar -czf "${DIST_DIR}/yggnmap-${VERSION}-darwin-amd64.tar.gz" -C "${BIN_DIR}" yggnmap-darwin-amd64
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-darwin-amd64.tar.gz${NC}"

    # macOS ARM64
    tar -czf "${DIST_DIR}/yggnmap-${VERSION}-darwin-arm64.tar.gz" -C "${BIN_DIR}" yggnmap-darwin-arm64
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-darwin-arm64.tar.gz${NC}"

    # FreeBSD AMD64
    tar -czf "${DIST_DIR}/yggnmap-${VERSION}-freebsd-amd64.tar.gz" -C "${BIN_DIR}" yggnmap-freebsd-amd64
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-freebsd-amd64.tar.gz${NC}"
fi

if command -v zip &> /dev/null; then
    # Windows AMD64
    (cd "${BIN_DIR}" && zip -q "../${DIST_DIR}/yggnmap-${VERSION}-windows-amd64.zip" yggnmap-windows-amd64.exe)
    echo -e "${GREEN}✓ Created yggnmap-${VERSION}-windows-amd64.zip${NC}"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "Binaries location: ${YELLOW}${BIN_DIR}/${NC}"
echo -e "Archives location: ${YELLOW}${DIST_DIR}/${NC}"
echo ""
echo "Built binaries:"
ls -lh "${BIN_DIR}"/yggnmap-* 2>/dev/null | awk '{print "  - " $9 " (" $5 ")"}'
echo ""
echo "Distribution archives:"
ls -lh "${DIST_DIR}"/yggnmap-* 2>/dev/null | awk '{print "  - " $9 " (" $5 ")"}'
echo ""
