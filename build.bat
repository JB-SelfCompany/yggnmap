@echo off
REM YggNmap Build Script for Windows
REM This script builds binaries for multiple platforms

set VERSION=1.0.0
set APP_NAME=yggnmap

echo Building %APP_NAME% v%VERSION%
echo ==============================
echo.

REM Create build directory
if not exist build mkdir build

REM Build for Windows (amd64)
echo Building for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -o "build\%APP_NAME%-windows-amd64.exe" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] Windows (amd64) build completed
) else (
    echo [FAIL] Windows (amd64) build failed
)

REM Build for Linux (amd64)
echo Building for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -o "build\%APP_NAME%-linux-amd64" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] Linux (amd64) build completed
) else (
    echo [FAIL] Linux (amd64) build failed
)

REM Build for Linux (arm64)
echo Building for Linux (arm64)...
set GOOS=linux
set GOARCH=arm64
go build -o "build\%APP_NAME%-linux-arm64" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] Linux (arm64) build completed
) else (
    echo [FAIL] Linux (arm64) build failed
)

REM Build for macOS (amd64)
echo Building for macOS (amd64)...
set GOOS=darwin
set GOARCH=amd64
go build -o "build\%APP_NAME%-darwin-amd64" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] macOS (amd64) build completed
) else (
    echo [FAIL] macOS (amd64) build failed
)

REM Build for macOS (arm64 - Apple Silicon)
echo Building for macOS (arm64)...
set GOOS=darwin
set GOARCH=arm64
go build -o "build\%APP_NAME%-darwin-arm64" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] macOS (arm64) build completed
) else (
    echo [FAIL] macOS (arm64) build failed
)

REM Build for FreeBSD (amd64)
echo Building for FreeBSD (amd64)...
set GOOS=freebsd
set GOARCH=amd64
go build -o "build\%APP_NAME%-freebsd-amd64" -ldflags "-s -w" .
if %errorlevel% == 0 (
    echo [OK] FreeBSD (amd64) build completed
) else (
    echo [FAIL] FreeBSD (amd64) build failed
)

echo.
echo Build completed! Binaries are in the build\ directory
dir /B build\

pause
