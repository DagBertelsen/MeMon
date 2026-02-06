# MeMon - Network Health Monitor

## Project Overview

This project implements **MeMon**, a Python Auto-Responder / Time Trigger script for MeshMonitor that monitors router and DNS health. The script automatically detects its execution mode and operates in one of two ways:

- **Auto Responder Mode**: Stateless, always returns immediate network status (for manual checks)
- **Timer Trigger Mode**: Stateful, conditional alerts with failure streak tracking and backoff logic (for scheduled monitoring)

**Project Status**: Production-ready, actively maintained

## Quick Commands

```bash
# Run tests
python memon.test.py -v 2>&1

# Run script with default config
python memon.py

# Check script execution manually
./memon.py

# Check GitHub Actions status
gh run list

# Install pre-commit hooks
pre-commit install
```

## Tech Stack & Prerequisites

- **Language**: Python 3.5+
- **Dependencies**: Python standard library only (no external packages)
- **System Requirements**:
  - Network access to router and DNS servers
  - Write permissions for state file creation
- **MeshMonitor**: Running instance with Auto Responder or Time Trigger feature enabled

## Core Requirements

### MeshMonitor Compatibility
- Script must be executable (`chmod +x`)
- Output JSON to stdout with `response` or `responses` field
- Complete within 10 seconds (hard limit)
- Include `mm_meta` block at top of script:
  ```python
  #!/usr/bin/env python3
  # mm_meta:
  #   name: MeMon
  #   emoji: 🌐
  #   language: Python
  ```
- **Execution Mode Detection**: Automatically adapts based on MeshMonitor environment variables
  - Auto Responder: `MESSAGE` and/or `TRIGGER` env vars present
  - Timer Trigger: No special env vars set

### Code Standards

- **Language**: Python 3.5+ (standard library only, no external dependencies)
- **Dependencies**: Standard library modules only:
  - `urllib.request` - HTTP/HTTPS requests
  - `json` - Configuration and state file handling
  - `ssl` - TLS certificate handling
  - `time` - Timestamp operations
  - `concurrent.futures` - Parallel DNS checks
  - `socket` - Network connectivity and DNS resolution
- **Third-party libraries**: None - all operations use Python standard library
- **CLI Commands Prohibition**: **DO NOT use CLI commands** (`subprocess.run`, `subprocess.Popen`, etc.) for network operations. Use Python libraries only (e.g., `socket` for connectivity tests and DNS queries)
- **Type Hints**: Use type hints from `typing` module. Avoid Python 3.6+ only features like variable annotations
- **Documentation**: All functions must have docstrings
- **Error Handling**: Graceful handling of network errors, timeouts, and file I/O
- **Cross-platform Compatibility**:
  - Use `os.path.join()` for file paths (cross-platform)
  - Git handles CRLF/LF line ending conversion
  - Executability set on Unix-like systems (`chmod +x`)

### File Structure

- [memon.py](memon.py) - Main script
- [memon.test.py](memon.test.py) - Test suite using `unittest`
- [memon.config.example.json](memon.config.example.json) - Example configuration (copy to `memon.config.json` for use)
- `memon.config.json` - Active configuration file (not in repo, created by user)
- `memon.state.json` - State file (auto-created, not in repo)
- [README.md](README.md) - Comprehensive documentation
- [AGENTS.md](AGENTS.md) - AI instructions (single source of truth)
- [CLAUDE.md](CLAUDE.md) - Claude Code entry point (references AGENTS.md)
- [.gitignore](.gitignore) - Git ignore rules
- [.aiignore](.aiignore) - AI tool ignore rules (excludes runtime/sensitive files)

### Key Functions

Core functions implemented in [memon.py](memon.py):

**Configuration & State:**
- `load_config()` - Load and validate config with defaults
- `load_state()` - Load state file or create default (Timer Trigger only)
- `save_state()` - Write state to JSON file (Timer Trigger only)

**Mode Detection:**
- `detect_execution_mode()` - Detect Auto Responder vs Timer Trigger mode via environment variables

**Network Checks:**
- `check_router()` - Perform router check (HTTPS, HTTP, or TCP socket connection)
- `check_router_https()` - Check router via HTTPS request
- `check_router_http()` - Check router via HTTP request
- `check_router_tcp()` - Check router via TCP socket connection
- `check_dns()` - Check single DNS resolver using standard library socket
- `check_all_dns()` - Check all DNS resolvers in parallel (with timeout)

**Status & Alerting:**
- `classify_status()` - Determine status classification (Timer Trigger only)
- `format_status_report()` - Format immediate status report (Auto Responder only)
- `should_fire_down_alert()` - Check if DOWN alert should fire (Timer Trigger only)
- `should_fire_up_alert()` - Check if UP alert should fire (Timer Trigger only)
- `should_fire_partial_recovery_alert()` - Check if partial recovery alert should fire (Timer Trigger only)

**Output:**
- `replace_placeholders()` - Replace placeholders in message templates
- `emit_alert()` - Output JSON to stdout
- `main()` - Orchestrate checks and alert logic with mode branching

### Alert Logic

**Auto Responder Mode** (Stateless):
- **Always emits**: Current network status regardless of failures or streaks
- **No state operations**: Bypasses `load_state()` and `save_state()`
- **No failure tracking**: Ignores `mustFailCount` and `alertBackoffSeconds`
- **Command parsing**: Parses `MESSAGE` env var for command keyword after the trigger word:
  - `status` or `all` - Full report: router + all DNS (default behavior)
  - `router` - Router-only check
  - `dns` - DNS-only report
  - No keyword match - Help guide listing available commands
- **Output formats** (for status/all command):
  - `"Router DOWN"` - Router unreachable
  - `"Router OK"` - Router up, no DNS checks
  - `"Router OK, All DNS FAIL"` - All DNS failing
  - `"Router OK, DNS: Name1 OK, Name2 FAIL"` - Mixed status (truncates to 200 chars)

**Timer Trigger Mode** (Stateful):
- **DOWN alert fires when**: `failStreak >= mustFailCount` AND `downNotified == false` AND backoff elapsed
- **UP alert fires when**: All checks pass AND `downNotified == true`
- **Partial Recovery alert fires when**: Network partially recovers (bypasses backoff):
  - Router recovers but DNS issues remain (routerDown → ispDown/upstreamDnsDown)
  - All DNS failed → some DNS recovered (ispDown → upstreamDnsDown)
  - Some DNS recovered (upstreamDnsDown → upstreamDnsDown with fewer failures)
- Only emit JSON to stdout when alert fires, otherwise exit silently

### Configuration Schema

Configuration file (`memon.config.json`):

- `timeoutMs`: Timeout per check in milliseconds (default: 2500)
- `mustFailCount`: Consecutive failures before alerting (default: 3)
- `alertBackoffSeconds`: Minimum time between alerts (default: 900)
- `messages`: Alert message templates
  - `routerDown` - Router connectivity failure message
  - `ispDown` - All DNS resolvers failed message
  - `upstreamDnsDown` - Some DNS resolvers failed message (supports `{{failed}}` placeholder)
  - `recovery` - Network recovered message
- `routerCheck`: Router check configuration
  - `method`: Check method (`https`, `http`, or `tcp`)
  - `host`: Router hostname/IP
  - `port`: Port number (optional, defaults: 443 for https, 80 for http)
  - `insecureTls`: Allow self-signed certificates for HTTPS (boolean)
- `dnsChecks`: Array of DNS check configurations
  - `name`: Human-readable name for the DNS server
  - `server`: DNS server IP address
  - `qname`: Query name (domain to resolve)
  - `rrtype`: Resource record type (A, AAAA, etc.)

See [memon.config.example.json](memon.config.example.json) for a complete example.

### Error Handling

- Config file missing/invalid → exit with error (stderr only, no stdout)
- State file missing → create default state
- Network timeouts → respect `timeoutMs` per check, ensure total < 10s
- Clock skew → clamp `lastAlertTs` if in future
- DNS/HTTPS errors → treat as failures, continue checking
- DNS socket errors → handle gracefully, treat as DNS failure

## Development Guidelines

### When Making Changes

1. **Always run tests** when making code changes: `python memon.test.py -v 2>&1`
   - Run the test file directly (running as unittest module does not work)
   - Tests also run automatically via pre-commit hooks (if installed) and GitHub Actions on push/PR
   - Run tests locally before committing to catch issues early
2. **Maintain test coverage** - add tests for new functionality
3. **Respect MeshMonitor timeout** - ensure total execution < 10 seconds
4. **Update documentation** if configuration or behavior changes
5. **Follow existing code style** - consistent with current implementation

### Performance Expectations

- **Typical execution time**: 2-5 seconds (with network checks)
- **Maximum allowed**: 10 seconds (MeshMonitor hard limit)
- **Network timeout per check**: Configurable via `timeoutMs` (default: 2500ms)
- **Parallel DNS checks**: All DNS checks run concurrently for speed

### Code Review Checklist

- [ ] All tests pass
- [ ] No new dependencies added (use Python standard library only)
- [ ] No CLI commands used (use Python libraries only)
- [ ] Timeout protection maintained (< 10s total)
- [ ] Error handling is graceful
- [ ] Documentation updated if needed
- [ ] Type hints included for new functions
- [ ] Docstrings added for new functions

### Testing Requirements

- All functions must be tested
- Mock external dependencies (`urllib.request`, `socket`, `json`, `os.path`)
- Test router checks (HTTPS success/failure, HTTP success/failure, TCP socket connection success/failure)
- Test DNS checks (all pass, all fail, partial failure)
- Test failure streak logic (mustFailCount threshold)
- Test backoff logic (time-based suppression)
- Test recovery logic (UP after DOWN)
- Test partial recovery logic (routerDown → ispDown/upstreamDnsDown, ispDown → upstreamDnsDown, upstreamDnsDown with fewer failures)
- Test placeholder replacement in messages
- Test state file creation and updates
- Test clock skew protection
- Test timeout protection (ensure < 10s total)
- Verify no stdout output when no alert fires

### Testing Strategy

- Use `unittest.mock` to mock external dependencies
- Test both success and failure paths
- Test edge cases (empty configs, missing files, timeouts)
- Verify JSON output format matches MeshMonitor requirements
- Test state persistence across runs

### Git/GitHub Workflow

- **Commit Guidelines**:
  - Always run tests before committing: `python memon.test.py -v 2>&1`
  - Write clear, descriptive commit messages
  - Commit related changes together (logical units)
  - Do not commit generated files (see [.gitignore](.gitignore))
- **What to Commit**:
  - Source code changes ([memon.py](memon.py), [memon.test.py](memon.test.py))
  - Configuration templates ([memon.config.example.json](memon.config.example.json))
  - Documentation updates ([README.md](README.md))
  - Build/CI configuration ([.github/](.github/), [.pre-commit-config.yaml](.pre-commit-config.yaml))
  - AI instructions ([AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), [.aiignore](.aiignore))
- **What NOT to Commit**:
  - Active config files (`memon.config.json` - user-specific)
  - State files (`memon.state.json` - auto-generated, runtime-specific)
  - Python cache files (`__pycache__/`, `*.pyc`)
  - IDE/editor configuration files
  - Virtual environments
- **Commit vs Push Behavior**:
  - **Default**: All commits are to local repository only (do not push to GitHub)
  - **GitHub Push**: Only push to GitHub when explicitly requested (e.g., "push to GitHub")
  - When user says "commit" without mentioning GitHub, commit locally only
- **GitHub Integration**:
  - GitHub Actions automatically runs tests on push/PR (see [.github/workflows/test.yml](.github/workflows/test.yml))
  - Pre-commit hooks run tests locally before commits (if installed)
  - Main branch should always have passing tests
- **Branch Strategy**: Use feature branches for significant changes, merge to main after tests pass

## Deployment Notes

### MeshMonitor Installation

- Scripts should be copied to `/data/scripts/` in MeshMonitor
- Must be executable: `chmod +x /data/scripts/memon.py`
- Config file should be in same directory or path adjusted in script
- State file is auto-created and managed by script

### MeshMonitor Configuration

- Configure as Auto Responder or Time Trigger in MeshMonitor UI
- Set script path to `/data/scripts/memon.py`
- Recommended trigger interval: 1-5 minutes
- Ensure MeshMonitor can execute Python scripts

## Common Issues

- **Test failures**: Check Python version (3.5+ required), ensure no external dependencies installed
- **Import errors**: Ensure using standard library only, no external packages
- **Timeout errors**: Check network connectivity, adjust `timeoutMs` in config, ensure total execution < 10s
- **JSON output**: Verify script exits silently when no alert fires (no stdout output)
- **Permission errors**: Ensure script is executable (`chmod +x`), check write permissions for state file
- **Clock skew warnings**: System clock protection active, check system time if alerts seem delayed

## References

- MeshMonitor User Scripts: https://meshmonitor.org/user-scripts.html
- Design documentation: [docs/plans/network-monitor-auto-responder.md](docs/plans/network-monitor-auto-responder.md)

## AI Assistant Instructions

This project uses unified AI instructions:

- **AGENTS.md** (this file) - Master instruction file (single source of truth)
- **CLAUDE.md** - Claude Code entry point (references this file)

When updating project requirements, patterns, or workflows, update [AGENTS.md](AGENTS.md). Both Cursor and Claude Code will automatically read these instructions.
