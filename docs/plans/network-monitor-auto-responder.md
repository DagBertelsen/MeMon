---
name: Network Monitor Auto-Responder Script
overview: Create a Python Auto-Responder script for MeshMonitor that monitors router and DNS health, outputs JSON alerts only when notifications should fire, with configurable checks, failure streak tracking, and alert backoff logic. Includes mm_meta block, comprehensive documentation, and full MeshMonitor compatibility.
todos: []
---

# Network Monitor Auto-Responder Script

## Overview

Create a Python script (`netchecks.py`) that monitors home network health (router + DNS resolvers) and outputs MeshMonitor-compatible JSON alerts only when notifications should fire. The script uses Python standard library with minimal dependencies, implements failure streak tracking with backoff, and supports configurable router checks (HTTPS/PING) and multiple DNS checks.

## Language Choice: Python

- **Rationale**: Better support for custom DNS server queries via subprocess (`nslookup`/`dig`) or `socket` module
- **Dependencies**: Python standard library only (or minimal: `urllib3`/`requests` for HTTPS if needed, but prefer `urllib` from stdlib)
- **MeshMonitor Support**: Python is fully supported per [MeshMonitor user scripts documentation](https://meshmonitor.org/user-scripts.html)

## File Structure

- `netchecks.py` - Main script (Python, standard library preferred)
- `netchecks.config.json` - Configuration file (router checks, DNS checks, messages, timeouts)
- `netchecks.state.json` - State file (failStreak, downNotified, lastAlertTs) - created/updated by script
- `netchecks.test.py` - Test suite using Python `unittest` or `pytest`
- `README.md` - Comprehensive documentation (usage, configuration, deployment)
- **Deployment**: Scripts should be copied to `/data/scripts/` in MeshMonitor (documented in README)

## MeshMonitor Compatibility Requirements

### Script Requirements (from [MeshMonitor docs](https://meshmonitor.org/user-scripts.html))

- ✅ **Location**: Document `/data/scripts/` as deployment location (develop in project root)
- ✅ **Extension**: `.py` (supported)
- ✅ **Executable**: Must be `chmod +x` (document in README)
- ✅ **Output Format**: JSON to stdout with `response` or `responses` field
- ✅ **Timeout**: Script must complete within 10 seconds (hard limit)
- ✅ **mm_meta Block**: Include metadata block for UI display:
```python
#!/usr/bin/env python3
# mm_meta:
#   name: Network Monitor
#   emoji: 🌐
#   language: Python
```


### Output Format

**Single Response:**

```json
{
  "response": "Your response text here (max 200 chars)"
}
```

**Multiple Responses:**

```json
{
  "responses": [
    "First message (max 200 chars)",
    "Second message (max 200 chars)"
  ]
}
```

## Implementation Details

### Core Logic Flow

1. **Load config** from `netchecks.config.json` (with defaults)
2. **Load state** from `netchecks.state.json` (create if missing)
3. **Check router first**:

   - If HTTPS: use `urllib.request` or `http.client` with configurable TLS validation
   - If PING: use `subprocess` to execute system ping command
   - If router fails → classify as "router down", skip DNS checks

4. **If router OK, check all DNS resolvers**:

   - Use `subprocess` to call `nslookup` or `dig` with specific DNS server
   - Alternative: Use `socket` with custom DNS resolution (if feasible)
   - Track which resolvers fail

5. **Classify status**:

   - Router down → use `messages.routerDown`
   - All DNS failed (K == N) → use `messages.ispDown`
   - Some DNS failed (0 < K < N) → use `messages.upstreamDnsDown` with `{{failed}}` placeholder
   - All OK → potential recovery

6. **Update failure streak**:

   - Any failure → `failStreak += 1`
   - All pass → `failStreak = 0`

7. **Alert logic**:

   - **DOWN alert fires when**: `failStreak >= mustFailCount` AND `downNotified == false` AND backoff elapsed
   - **UP alert fires when**: All checks pass AND `downNotified == true`
   - Update state file after alerts

8. **Output**: Only emit JSON to stdout when alert fires, otherwise exit silently
9. **Timeout protection**: Ensure total execution time < 10 seconds (MeshMonitor hard limit)

### Key Functions

- `load_config()` - Load and validate config with defaults
- `load_state()` - Load state file or create default
- `save_state()` - Write state to JSON file
- `check_router()` - Perform router check (HTTPS or PING)
- `check_dns()` - Check single DNS resolver using subprocess
- `check_all_dns()` - Check all DNS resolvers in parallel (with timeout)
- `classify_status()` - Determine status classification
- `should_fire_down_alert()` - Check if DOWN alert should fire
- `should_fire_up_alert()` - Check if UP alert should fire
- `emit_alert()` - Output JSON to stdout
- `main()` - Orchestrate checks and alert logic with timeout protection

### Error Handling

- Config file missing/invalid → exit with error (stderr only, no stdout)
- State file missing → create default state
- Network timeouts → respect `timeoutMs` per check, ensure total < 10s
- Clock skew → clamp `lastAlertTs` if in future
- DNS/HTTPS errors → treat as failures, continue checking
- Subprocess errors → handle gracefully, treat as DNS failure

### Testing Strategy

- Mock `urllib.request`, `subprocess`, `json`, and `os.path` modules
- Test router checks (HTTPS success/failure, PING success/failure)
- Test DNS checks (all pass, all fail, partial failure)
- Test failure streak logic (mustFailCount threshold)
- Test backoff logic (time-based suppression)
- Test recovery logic (UP after DOWN)
- Test placeholder replacement in messages
- Test state file creation and updates
- Test clock skew protection
- Test timeout protection (ensure < 10s total)
- Verify no stdout output when no alert fires

## Documentation Requirements

### README.md Contents

1. **Script Overview**: What it does, use case
2. **Prerequisites**: Python version, system requirements
3. **Installation**:

   - Copy script to `/data/scripts/`
   - Make executable: `chmod +x /data/scripts/netchecks.py`
   - Copy config file to appropriate location

4. **Configuration**:

   - Detailed explanation of `netchecks.config.json` schema
   - Example configurations for different scenarios
   - Message template customization

5. **MeshMonitor Setup**:

   - How to configure Auto Responder trigger
   - Example trigger patterns
   - Script path configuration

6. **Troubleshooting**: Common issues and solutions

### Inline Documentation

- Docstrings for all functions
- Comments explaining complex logic
- Type hints (Python 3.5+ compatible)

### mm_meta Block

Include at top of script:

```python
#!/usr/bin/env python3
# mm_meta:
#   name: Network Monitor
#   emoji: 🌐
#   language: Python
```

## Configuration Schema

```json
{
  "timeoutMs": 2500,
  "mustFailCount": 3,
  "alertBackoffSeconds": 900,
  "messages": {
    "routerDown": "Router is down",
    "ispDown": "All DNS resolvers failed - ISP may be down",
    "upstreamDnsDown": "DNS resolvers failed: {{failed}}",
    "recovery": "Network connectivity restored"
  },
  "routerCheck": {
    "type": "https|ping",
    "url": "https://192.168.1.1",
    "insecureTls": false,
    "host": "192.168.1.1",
    "pingCount": 1
  },
  "dnsChecks": [
    {
      "name": "Altibox",
      "server": "8.8.8.8",
      "qname": "google.com",
      "rrtype": "A"
    }
  ]
}
```

## Example Config

Include example with:

- HTTPS router check (insecure TLS enabled for router self-signed certs)
- 2+ DNS checks (e.g., Altibox, Google, Cloudflare)
- All message templates configured
- Realistic timeout and backoff values
- Note: Total timeout should be < 10 seconds to respect MeshMonitor limit