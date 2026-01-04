#!/bin/bash

# YggNmap Build Script
# This script builds binaries for multiple platforms

VERSION="1.0.0"
APP_NAME="yggnmap"

echo "Building $APP_NAME v$VERSION"
echo "=============================="
echo ""

# Create build directory
mkdir -p build

# Build for Linux (amd64)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o "build/${APP_NAME}-linux-amd64" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ Linux (amd64) build completed"
else
    echo "✗ Linux (amd64) build failed"
fi

# Build for Linux (arm64)
echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -o "build/${APP_NAME}-linux-arm64" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ Linux (arm64) build completed"
else
    echo "✗ Linux (arm64) build failed"
fi

# Build for Windows (amd64)
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o "build/${APP_NAME}-windows-amd64.exe" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ Windows (amd64) build completed"
else
    echo "✗ Windows (amd64) build failed"
fi

# Build for macOS (amd64)
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o "build/${APP_NAME}-darwin-amd64" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ macOS (amd64) build completed"
else
    echo "✗ macOS (amd64) build failed"
fi

# Build for macOS (arm64 - Apple Silicon)
echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o "build/${APP_NAME}-darwin-arm64" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ macOS (arm64) build completed"
else
    echo "✓ macOS (arm64) build failed"
fi

# Build for FreeBSD (amd64)
echo "Building for FreeBSD (amd64)..."
GOOS=freebsd GOARCH=amd64 go build -o "build/${APP_NAME}-freebsd-amd64" -ldflags "-s -w" .
if [ $? -eq 0 ]; then
    echo "✓ FreeBSD (amd64) build completed"
else
    echo "✗ FreeBSD (amd64) build failed"
fi

echo ""
echo "Build completed! Binaries are in the build/ directory"
ls -lh build/
