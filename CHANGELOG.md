# Changelog

All notable changes to MeMon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.2] - 2026-02-07

### Fixed
- Fix outdated README.md references to debug output going to stdout (now correctly documents stderr)

### Changed
- Add AI instruction to check README.md when changing code behavior (AGENTS.md)

## [1.1.1] - 2026-02-07

### Fixed
- Fix test compatibility with Python 3.11 on macOS (`test_debug_log_writes_to_stderr` used unsafe `object.__new__` pattern)

## [1.1.0] - 2026-02-07

### Added
- Comprehensive debug logging to stderr (config, state, timing, router, DNS, alert decisions)
- `_debug_log` centralized helper for consistent `[Tag] message` format
- `DNS_UDP_MAX_SIZE` constant replacing magic number
- Debug output for successful checks (router OK, DNS OK), not just failures
- `debug` parameter on `load_state()` and `save_state()` for state I/O visibility

### Changed
- Debug output now goes to stderr instead of stdout (avoids interfering with MeshMonitor JSON parsing)
- Split `main()` into `_run_auto_responder()` and `_run_timer_trigger()` mode handlers
- Consolidated `check_router_https()` and `check_router_http()` into shared `_check_router_http_request()` helper
- Extracted `_build_dns_status_list()` to eliminate duplication in report formatting
- Moved `import traceback` to module-level imports
- Improved comments: config merge, clock skew, DNS compression pointer

## [1.0.0] - 2026-02-07

### Added
- Version tracking (`__version__` variable in memon.py)
- `version` command in Auto Responder mode
- Backward compatibility rules in AGENTS.md
- Versioning policy (Semantic Versioning) in AGENTS.md
- This CHANGELOG

### Notes
- This is the first versioned release. All existing functionality is considered stable.
- Prior development history is available in the git log.
