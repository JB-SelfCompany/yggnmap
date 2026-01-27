# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-01-27

### Added

- **Modern UI Design** - Complete UI redesign with glassmorphism effects, muted color palette, and 2026 web design trends.
- **Footer** - Added footer with copyright, version display, and GitHub link.
- **Favicon** - Added SVG radar icon as favicon.
- **Centralized Version System** - Version is now defined in single source of truth (`internal/version/version.go`) and automatically used by build scripts.
- **Downloads Badge** - Added GitHub downloads counter badge to README.
- **Visitors Badge** - Added unique visitors counter badge to README.

### Changed

- **Dark Theme Default** - Dark theme is now the default appearance.
- **SVG Icons** - Replaced emoji icons with clean SVG icons for theme toggle.
- **Address Description** - Fixed address range description: now correctly shows 200::/7 (which includes 300::/8 subnet addresses).
- **Build System** - Unified cross-platform build script (`build.sh`) for Linux, Windows, macOS, and FreeBSD.
- **Output Directory** - Build artifacts now placed in `dist/` directory instead of `build/`.
- **Module Path** - Changed Go module path to `github.com/JB-SelfCompany/yggnmap`.

### Removed

- **build.bat** - Removed Windows-specific build script in favor of unified `build.sh`.
- **Emoji Icons** - Removed emoji-based icons from UI.

### Fixed

- **Import Paths** - Fixed all internal imports to use full module path.
- **Russian README Typo** - Fixed address range typo in Russian documentation.

## [1.0.0] - 2025-01-15

### Added

- **Port Scanning Service** - Web-based port scanning for Yggdrasil Network users.
- **Three Scan Modes**:
  - Quick Scan - Top 1000 common ports (1-3 minutes)
  - Full Scan - All 65,535 ports (10-30 minutes)
  - Custom Scan - User-defined ports or ranges
- **Real-time Progress** - WebSocket-powered live updates with progress bar.
- **Export Results** - Download scan results in CSV, JSON, or PDF formats.
- **Dark/Light Theme** - Toggle between dark and light themes.
- **Multi-language Support** - English and Russian interfaces.
- **Automatic IP Detection** - Server automatically detects client's Yggdrasil IPv6.
- **Security Features**:
  - CSRF token validation
  - Rate limiting (per-IP and global)
  - Input validation and sanitization
  - Privacy-preserving logging (client IPs never logged)
  - HTTP security headers
- **Yggdrasil Address Support** - Full support for 200::/7 and 300::/8 addresses.

[1.1.0]: https://github.com/JB-SelfCompany/yggnmap/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/JB-SelfCompany/yggnmap/releases/tag/1.0.0
