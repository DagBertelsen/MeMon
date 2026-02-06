# MeMon Network Health Monitor

A Python Auto-Responder / Time Trigger script for MeshMonitor that monitors home network health (router and DNS resolvers) and outputs JSON alerts only when notifications should fire. Implements failure streak tracking with backoff logic to prevent alert spam.

## Script Overview

This script continuously monitors your network infrastructure:

- **Router Health**: Checks router connectivity via HTTPS, HTTP, or TCP socket connection
- **DNS Resolver Health**: Monitors multiple DNS resolvers (e.g., ISP DNS, Google, Cloudflare)
- **Smart Alerting**: Only sends alerts when:
  - Failures reach a configurable threshold (`mustFailCount`)
  - Backoff period has elapsed (prevents alert spam)
  - Network recovers after being down
  - Partial recovery occurs (router recovers but DNS issues remain, or DNS partially recovers)

The script uses failure streak tracking to distinguish between transient network hiccups and real outages, ensuring you only get notified when action is needed.

### Use Cases

- Monitor home router connectivity
- Detect ISP DNS outages
- Track upstream DNS resolver failures
- Get notified when network issues occur or resolve

## Execution Modes

The script automatically detects and operates in one of two modes based on how it's triggered in MeshMonitor:

### Auto Responder Mode (Manual Status Checks)

**Triggered when**: User sends a message matching an Auto Responder trigger pattern
**Detection**: `MESSAGE` or `TRIGGER` environment variables are present
**Behavior**:
- **Stateless operation**: No state file loading or saving
- **Always responds**: Returns current network status immediately
- **Bypasses failure tracking**: No `mustFailCount` or `alertBackoffSeconds` logic
- **Instant feedback**: Perfect for on-demand status checks

**Example Output Formats**:
- `Router DOWN` - Router is unreachable
- `Router OK` - Router up, no DNS checks configured
- `Router OK, All DNS FAIL` - Router up but all DNS servers failing
- `Router OK, DNS: Google OK, Cloudflare FAIL, Altibox OK` - Mixed status

**Supported Commands**: Include a keyword after the trigger word to request a specific report:
- `{trigger} status` - Full report (router + all DNS)
- `{trigger} router` - Router-only check
- `{trigger} dns` - DNS-only report
- `{trigger}` (no keyword) - Help guide listing available commands

**Use Case**: Send "netcheck status" to get full network status, or just "netcheck" for a list of commands.

### Timer Trigger Mode (Scheduled Monitoring)

**Triggered when**: Scheduled via cron/timer in MeshMonitor
**Detection**: `MESSAGE` and `TRIGGER` environment variables are not set
**Behavior**:
- **Stateful operation**: Loads and saves state file between runs
- **Conditional alerts**: Only emits when failure thresholds met
- **Failure tracking**: Respects `mustFailCount` streak requirements
- **Backoff logic**: Honors `alertBackoffSeconds` to prevent alert spam
- **Recovery tracking**: Detects and reports network recovery

**Use Case**: Automated monitoring every N minutes/hours with intelligent alerting.

### Mode Detection

The script automatically detects which mode to use:

```python
# MeshMonitor sets these when running Auto Responder:
MESSAGE="status check"   # The message text received
TRIGGER="netcheck"       # The trigger pattern that matched

# Timer Triggers do NOT set these variables
```

**No configuration needed** - the mode is automatically determined at runtime based on environment variables set by MeshMonitor.

## Prerequisites

- **Python**: Version 3.5 or higher (uses only standard library - no external dependencies)
- **System Requirements**:
  - Network access to router and DNS servers
- **MeshMonitor**: Running instance with Auto Responder feature enabled

## Installation

### 1. Copy Script to MeshMonitor

Copy the script to the MeshMonitor scripts directory:

```bash
cp memon.py /data/scripts/memon.py
```

### 2. Make Script Executable

```bash
chmod +x /data/scripts/memon.py
```

### 3. Install Dependencies

No external Python dependencies are required. The script uses only Python standard library modules.

### 4. Copy Configuration File

Copy the example configuration file to create your configuration:

```bash
cp memon.config.example.json /data/scripts/memon.config.json
```

**Note**: The script looks for `memon.config.json` in the current working directory. You may need to adjust the path in the script or ensure the config file is in the same directory as the script.

### 5. Edit Configuration

Edit `memon.config.json` to match your network setup (see Configuration section below).

## Configuration

The script uses `memon.config.json` for all configuration. The configuration file is required - copy `memon.config.example.json` to `memon.config.json` and customize it for your network setup.

**Note**: The configuration file must be saved as UTF-8 encoding to support non-ASCII characters and emojis in messages.

### Configuration Schema

```json
{
  "timeoutMs": 2500,
  "mustFailCount": 3,
  "alertBackoffSeconds": 900,
  "debug": false,
  "messages": {
    "routerDown": "Router is down",
    "ispDown": "All DNS resolvers failed - ISP may be down",
    "upstreamDnsDown": "DNS resolvers failed: {{failed}}",
    "recovery": "Network connectivity restored"
  },
  "routerCheck": {
    "method": "https",
    "host": "192.168.1.1",
    "port": 443,
    "insecureTls": false
  },
  "dnsChecks": [
    {
      "name": "Google DNS",
      "server": "8.8.8.8",
      "qname": "google.com",
      "rrtype": "A"
    },
    {
      "name": "Cloudflare DNS",
      "server": "1.1.1.1",
      "qname": "cloudflare.com",
      "rrtype": "A"
    }
  ]
}
```

### Configuration Fields

#### Top-Level Settings

- **`timeoutMs`** (integer, default: 2500): Timeout in milliseconds for each individual check (router and DNS). Total script execution must complete within 10 seconds (MeshMonitor hard limit).
- **`mustFailCount`** (integer, default: 3): Number of consecutive failures required before sending a DOWN alert. Prevents false positives from transient network issues. **See "Use Cases and Configuration" section below for recommended values based on your use case.**
- **`alertBackoffSeconds`** (integer, default: 900): Minimum time in seconds before the first DOWN alert can fire. Prevents alert spam when services are flapping (rapidly transitioning between up and down). Once the first DOWN alert fires, the `downNotified` flag takes over to prevent repeated alerts during extended outages. **See "Use Cases and Configuration" section below for when this parameter is relevant.**
- **`debug`** (boolean, default: false): If `true`, prints failure messages to stdout for debugging purposes. When `false` (default), only JSON alerts are printed to stdout, ensuring clean output for MeshMonitor. Failure messages include router check failures and DNS check failures with error details.

#### Messages

Customize alert messages for different failure scenarios:

- **`routerDown`**: Message sent when router check fails
- **`ispDown`**: Message sent when all DNS resolvers fail (suggests ISP outage)
- **`upstreamDnsDown`**: Message sent when some (but not all) DNS resolvers fail. Use `{{failed}}` placeholder to list failed resolvers.
- **`recovery`**: Message sent when network recovers after being down

**Message Length**: Messages are automatically truncated to 200 characters per MeshMonitor requirements.

**UTF-8 Support**: The script fully supports UTF-8 encoding in configuration files and message output. You can use non-ASCII characters (e.g., accented characters like é, ñ, ü) and emojis (🚨, ⚠️, ✅) in your alert messages. The configuration file is read with UTF-8 encoding, and JSON output preserves these characters without escaping.

#### Router Check

Configure how the script checks router connectivity:

- **`method`** (string, default: `"https"`): Connection method to use
  - `"https"`: Uses HTTPS request to check router connectivity (default port: 443)
  - `"http"`: Uses HTTP request to check router connectivity (default port: 80)
  - `"tcp"`: Uses TCP socket connection test (default port: 80). Does not require root privileges, unlike ICMP ping.
- **`host`** (string, required): Router hostname or IP address (no protocol prefix)
  - Examples: `"192.168.1.1"`, `"router.local"`
- **`port`** (integer, optional): Port number to connect to
  - Defaults based on method:
    - `https`: defaults to 443
    - `http`: defaults to 80
    - `tcp`: defaults to 80
  - Can be specified for custom ports (e.g., `8080`, `8443`)
- **`insecureTls`** (boolean, default: false): If `true`, disables TLS certificate validation (useful for routers with self-signed certificates). Only used when `method` is `"https"`.

#### DNS Checks

Array of DNS resolver checks to perform:

- **`name`** (string, required): Friendly name for this DNS resolver (used in alerts)
- **`server`** (string, required): DNS server IP address
- **`qname`** (string, required): Domain name to query (e.g., `"google.com"`)
- **`rrtype`** (string, default: "A"): DNS record type to query (`"A"` for IPv4, `"AAAA"` for IPv6)

### Use Cases and Configuration

The script can be used in two different ways with MeshMonitor, and the configuration should be adjusted accordingly:

#### Auto Responder (Manual Triggering)

When the script is triggered manually via messages (using MeshMonitor's Auto Responder feature), users control when checks happen:

- **`mustFailCount`**: Should be set to **`1`** for immediate feedback. Since the check is manually triggered, you want to know the current status right away without waiting for multiple consecutive failures.
- **`alertBackoffSeconds`**: Has little relevance since checks are manually triggered. You can set this to `0` or a minimal value (e.g., `60` seconds) as spam prevention isn't needed when you control when checks run.

**Recommended Configuration for Auto Responder:**
```json
{
  "mustFailCount": 1,
  "alertBackoffSeconds": 0
}
```

#### Timer Triggers (Automated Scheduling)

When the script runs automatically on a schedule (using MeshMonitor's [Timer Triggers](https://meshmonitor.org/features/automation#timer-triggers) feature), these parameters are essential to prevent alert spam and network flooding:

- **`mustFailCount`**: Should be set to **`3`** (or higher) to prevent false positives from transient network issues. Automated runs can catch temporary hiccups that don't warrant alerts.
- **`alertBackoffSeconds`**: Should be used (e.g., `900` seconds / 15 minutes) to prevent alert spam when services are flapping. This is critical for automated runs to avoid flooding the mesh network with repeated alerts.

**Recommended Configuration for Timer Triggers:**
```json
{
  "mustFailCount": 3,
  "alertBackoffSeconds": 900
}
```

### Example Configurations

#### Auto Responder Configuration (Manual Triggering)

Recommended configuration when using the script with MeshMonitor's Auto Responder feature:

```json
{
  "timeoutMs": 2500,
  "mustFailCount": 1,
  "alertBackoffSeconds": 0,
  "debug": false,
  "messages": {
    "routerDown": "Router is down",
    "ispDown": "All DNS resolvers failed - ISP may be down",
    "upstreamDnsDown": "DNS resolvers failed: {{failed}}",
    "recovery": "Network connectivity restored"
  },
  "routerCheck": {
    "method": "https",
    "host": "192.168.1.1",
    "port": 443,
    "insecureTls": true
  },
  "dnsChecks": [
    {
      "name": "Google DNS",
      "server": "8.8.8.8",
      "qname": "google.com",
      "rrtype": "A"
    },
    {
      "name": "Cloudflare DNS",
      "server": "1.1.1.1",
      "qname": "cloudflare.com",
      "rrtype": "A"
    }
  ]
}
```

#### Timer Triggers Configuration (Automated Scheduling)

Recommended configuration when using the script with MeshMonitor's Timer Triggers feature:

```json
{
  "timeoutMs": 2500,
  "mustFailCount": 3,
  "alertBackoffSeconds": 900,
  "debug": false,
  "messages": {
    "routerDown": "Router is down",
    "ispDown": "All DNS resolvers failed - ISP may be down",
    "upstreamDnsDown": "DNS resolvers failed: {{failed}}",
    "recovery": "Network connectivity restored"
  },
  "routerCheck": {
    "method": "https",
    "host": "192.168.1.1",
    "port": 443,
    "insecureTls": true
  },
  "dnsChecks": [
    {
      "name": "ISP DNS",
      "server": "8.8.8.8",
      "qname": "google.com",
      "rrtype": "A"
    },
    {
      "name": "Google DNS",
      "server": "8.8.8.8",
      "qname": "google.com",
      "rrtype": "A"
    },
    {
      "name": "Cloudflare DNS",
      "server": "1.1.1.1",
      "qname": "cloudflare.com",
      "rrtype": "A"
    }
  ]
}
```

#### TCP Socket Connection Router Check

```json
{
  "routerCheck": {
    "method": "tcp",
    "host": "192.168.1.1",
    "port": 80
  }
}
```

#### HTTP Router Check

```json
{
  "routerCheck": {
    "method": "http",
    "host": "192.168.1.1",
    "port": 80
  }
}
```

**Note**: The `"tcp"` method uses TCP socket connection instead of ICMP ping, so it doesn't require root privileges.

#### Aggressive Monitoring (Faster Alerts - Timer Triggers Only)

For Timer Triggers when you want faster alerts (use with caution to avoid spam):

```json
{
  "timeoutMs": 2000,
  "mustFailCount": 2,
  "alertBackoffSeconds": 300
}
```

#### Conservative Monitoring (Fewer False Positives - Timer Triggers Only)

For Timer Triggers when you want to minimize false positives:

```json
{
  "timeoutMs": 3000,
  "mustFailCount": 5,
  "alertBackoffSeconds": 1800
}
```

**Note**: These aggressive and conservative configurations are only recommended for Timer Triggers. For Auto Responder, always use `mustFailCount: 1` and `alertBackoffSeconds: 0`.

## MeshMonitor Setup

The script can be configured in MeshMonitor in two ways: as an **Auto Responder** (manual triggering) or as a **Timer Trigger** (automated scheduling). Choose the method that best fits your needs.

### Option 1: Auto Responder (Manual Triggering)

Use this method when you want to manually trigger network checks by sending messages to your MeshMonitor node.

#### 1. Configure Auto Responder Trigger

1. Navigate to **Settings → Automation → Auto Responder** in MeshMonitor
2. Click **"Add Trigger"**
3. Configure the trigger:
   - **Trigger**: Enter comma-separated patterns: `memon, memon {argument}`
   - **Type**: Select **"Script Ex"**
   - **Response**: Select your `memon.py` script
   - **Channel**: Select the channel to listen on (e.g., "Direct Messages")
4. **Important**: MeshMonitor uses exact matching for triggers. You need **two comma-separated patterns** to support both the bare trigger word and subcommands:
   - `memon` - Matches the trigger word alone (returns help)
   - `memon {argument}` - Matches the trigger word followed by any argument (e.g., `memon status`, `memon router`, `memon dns`)

#### 2. Example Trigger Configuration

Trigger field value: `memon, memon {argument}`

| Pattern | Matches | Response |
|---|---|---|
| `memon` | `memon` (exact) | Help: lists available commands |
| `memon {argument}` | `memon status`, `memon router`, `memon dns` | Requested report |

#### 3. Configuration for Auto Responder

When using Auto Responder, configure your `memon.config.json` with:
- **`mustFailCount`**: Set to `1` for immediate feedback
- **`alertBackoffSeconds`**: Set to `0` or minimal value (e.g., `60`)

See the "Use Cases and Configuration" section above for details.

#### 4. Testing the Trigger

1. Send a message matching your trigger pattern to your MeshMonitor node (e.g., `memon` or `memon status`)
2. The script will run and return current network status
3. You'll always receive a response: a status report or a help message listing available commands

### Option 2: Timer Triggers (Automated Scheduling)

Use this method when you want the script to run automatically on a schedule. This is ideal for continuous monitoring.

#### 1. Configure Timer Trigger

1. Navigate to **Settings → Automation → Timer Triggers** (or **Timed Events**) in MeshMonitor
2. Click **"Add Timer"** or **"Add"**
3. Configure the timer:
   - **Name**: Descriptive name (e.g., "Network Health Check")
   - **Schedule**: Cron expression defining when to run (e.g., `0 */6 * * *` for every 6 hours)
   - **Script**: Select or enter `/data/scripts/memon.py`
   - **Channel**: Select the channel to send alerts to (typically Primary channel, index 0)
4. Click **"Save"** to persist your changes

#### 2. Example Cron Schedules

- **Every 6 hours**: `0 */6 * * *` - Runs at 12:00 AM, 6:00 AM, 12:00 PM, 6:00 PM
- **Every hour**: `0 * * * *` - Runs at the top of every hour
- **Daily at 9 AM**: `0 9 * * *` - Runs once per day at 9:00 AM
- **Every 15 minutes**: `*/15 * * * *` - Runs every 15 minutes (use with caution)

For help building cron expressions, use [crontab.guru](https://crontab.guru/).

#### 3. Configuration for Timer Triggers

When using Timer Triggers, configure your `memon.config.json` with:
- **`mustFailCount`**: Set to `3` (or higher) to prevent false positives
- **`alertBackoffSeconds`**: Set to `900` (15 minutes) or higher to prevent alert spam

These parameters are essential for automated runs to prevent network flooding. See the "Use Cases and Configuration" section above for details.

#### 4. Monitoring Timer Execution

- Check MeshMonitor logs to verify timer execution: `docker logs meshmonitor`
- Timer status (last run, last result) is displayed in the Timer Triggers interface
- Ensure the script completes within 10 seconds (MeshMonitor hard limit)

### Script Path Configuration

The script path in MeshMonitor should be:
```
/data/scripts/memon.py
```

**Important**: Ensure the script has execute permissions (`chmod +x`) and the configuration file is accessible from the script's working directory.

### Related Documentation

- [MeshMonitor Auto Responder Documentation](https://meshmonitor.org/features/automation#auto-responder)
- [MeshMonitor Timer Triggers Documentation](https://meshmonitor.org/features/automation#timer-triggers)

## How It Works

### Execution Flow

1. **Load Configuration**: Reads `memon.config.json` (or uses defaults)
2. **Detect Execution Mode**: Checks for `MESSAGE`/`TRIGGER` environment variables
   - If present → **Auto Responder Mode** (stateless)
   - If absent → **Timer Trigger Mode** (stateful)
3. **Check Router**: Performs router check (HTTPS, HTTP, or TCP socket connection)
   - If router fails → Classify as "router down", skip DNS checks
4. **Check DNS** (if router OK): Checks all configured DNS resolvers in parallel using standard library socket

**Auto Responder Mode** (steps 5-6):
5. **Format Status Report**: Creates message with current router and DNS status
6. **Output**: Always emits JSON status report to stdout, then exits (no state operations)

**Timer Trigger Mode** (steps 5-9):
5. **Load State**: Reads `memon.state.json` (creates default if missing)
6. **Classify Status**: Determines failure type (router down, all DNS failed, some DNS failed, or all OK)
7. **Update Failure Streak**: Increments on failure, resets on success
8. **Evaluate Alerts**:
   - **DOWN alert fires when**: `failStreak >= mustFailCount` AND `downNotified == false` AND backoff elapsed
     - Once `downNotified` is set to `true`, no further DOWN alerts will fire until full recovery, regardless of backoff period
     - The backoff period (`alertBackoffSeconds`) only matters for the first alert; it prevents rapid-fire alerts when services are flapping
   - **UP alert fires when**: All checks pass AND `downNotified == true`
     - Resets `downNotified` to `false`, allowing future DOWN alerts if issues recur
   - **Partial Recovery alert fires when**: Network partially recovers (bypasses backoff):
     - Router recovers but DNS issues remain (routerDown → ispDown/upstreamDnsDown)
     - All DNS failed → some DNS recovered (ispDown → upstreamDnsDown)
     - Some DNS recovered (upstreamDnsDown → upstreamDnsDown with fewer failures)
9. **Output & Save State**: Emits JSON to stdout only when alert fires (otherwise exits silently), saves updated state. When `debug=true`, failure messages are also printed to stdout for troubleshooting.

### State Management

The script maintains state in `memon.state.json`:

- **`failStreak`**: Current consecutive failure count
- **`downNotified`**: Whether a DOWN alert was already sent
  - Once set to `true`, this flag prevents all future DOWN alerts from firing until full recovery
  - Only resets to `false` when all checks pass (full recovery)
  - This ensures you receive one alert per outage, not repeated alerts every 15 minutes during extended outages
- **`lastAlertTs`**: Timestamp of last alert (for backoff calculation)
  - Used to enforce `alertBackoffSeconds` before the first DOWN alert fires
  - Once `downNotified` is `true`, backoff is no longer checked for DOWN alerts
- **`lastStatus`**: Previous status classification (for partial recovery detection)
- **`lastFailedDns`**: List of DNS resolver names that failed previously (for partial recovery detection)

State is updated after each alert and persists between script runs. The script includes clock skew protection to handle system clock changes.

### Timeout Protection

The script ensures total execution time stays under 10 seconds (MeshMonitor hard limit):

- Individual checks respect `timeoutMs` per check
- DNS checks run in parallel with overall timeout protection
- Script includes a 0.5 second safety margin to ensure completion before MeshMonitor timeout
- Script exits gracefully if time runs out

### Partial Recovery Alerts

The script detects and alerts on partial recovery scenarios, providing more granular status updates:

- **Router Recovery with DNS Issues**: When router recovers but DNS problems persist, you'll get an alert indicating the current DNS status (all failed or partially failed)
- **DNS Partial Recovery**: When all DNS resolvers were failing and some recover, you'll be notified of the improved (but still degraded) status
- **Progressive DNS Recovery**: When some DNS resolvers recover (fewer failures than before), you'll get an update

Partial recovery alerts bypass the backoff period, ensuring you're immediately notified of status improvements even during extended outages.

### Alert Suppression Logic

The script uses a two-stage alert suppression mechanism to prevent alert spam while ensuring you're notified of real issues:

#### Why We Have This Mechanism

Network services can "flap" - rapidly transitioning between up and down states due to transient issues, network congestion, or intermittent connectivity problems. Without suppression logic, you would receive an alert every time the script runs during a flapping period, resulting in alert spam.

#### Two-Stage Suppression

1. **Backoff Period (`alertBackoffSeconds`)**: Prevents rapid-fire alerts when services are flapping
   - Before the first DOWN alert fires, the script checks if `alertBackoffSeconds` (default: 900 seconds / 15 minutes) has elapsed since the last alert
   - This prevents alerting on every single failure during flapping periods
   - Only applies when `downNotified == false` (before first alert)

2. **`downNotified` Flag**: Prevents repeated alerts during extended outages
   - Once a DOWN alert fires, `downNotified` is set to `true`
   - While `downNotified == true`, **no further DOWN alerts will fire**, regardless of backoff period
   - This ensures you receive one alert per outage, not repeated alerts every 15 minutes
   - Only resets to `false` when all checks pass (full recovery)

#### Example Scenarios

**Scenario 1: Flapping Service (Up/Down Repeatedly)**
- Service fails 3 times → First DOWN alert fires (after backoff elapsed)
- Service recovers briefly, then fails again → No alert (backoff prevents it)
- Service fails 3 more times → Still no alert (`downNotified` is `true`)
- Service fully recovers → UP alert fires, `downNotified` resets to `false`

**Scenario 2: Extended Outage**
- Service fails 3 times → First DOWN alert fires
- Service remains down for hours → No repeated alerts (`downNotified` blocks them)
- Service recovers → UP alert fires, `downNotified` resets to `false`

**Scenario 3: Partial Recovery**
- All DNS fails → DOWN alert fires, `downNotified = true`
- Some DNS recovers → Partial recovery alert fires (bypasses backoff and `downNotified`)
- Full recovery → UP alert fires, `downNotified` resets to `false`

## Troubleshooting

### Script Doesn't Run

**Problem**: Script not executing when trigger is sent.

**Solutions**:
- Verify script has execute permissions: `chmod +x /data/scripts/memon.py`
- Check script path in MeshMonitor trigger configuration
- Verify Python is available: `python3 --version`
- Check MeshMonitor logs for execution errors

### No Alerts Received

**Problem**: Network issues occur but no alerts are sent.

**Possible Causes**:
- Failure streak hasn't reached `mustFailCount` threshold
- Backoff period hasn't elapsed since last alert (only applies before first DOWN alert when `downNotified == false`)
- `downNotified` is `true` (prevents all subsequent DOWN alerts until full recovery)
- Script is exiting before checks complete (timeout)

**Solutions**:
- Check `memon.state.json` to see current `failStreak` and `downNotified` values
- If `downNotified` is `true`, you won't receive more DOWN alerts until full recovery
- Reduce `mustFailCount` for faster alerts (but more false positives)
- Reduce `alertBackoffSeconds` for faster first alert (only affects timing of first alert)
- Increase `timeoutMs` if checks are timing out too quickly
- Enable `"debug": true` in configuration to see detailed failure messages in stdout (useful for troubleshooting, but note this will interfere with MeshMonitor's JSON parsing)

### False Positive Alerts

**Problem**: Receiving alerts when network is actually working.

**Solutions**:
- Increase `mustFailCount` to require more consecutive failures
- Increase `timeoutMs` to allow more time for slow responses
- Verify router URL/host and DNS server addresses are correct
- Check if router requires authentication (HTTPS check may fail)

### DNS Checks Always Fail

**Problem**: DNS checks consistently fail even when network is working.

**Possible Causes**:
- DNS server addresses are incorrect
- Firewall blocking DNS queries
- Network connectivity issues

**Solutions**:
- Verify DNS server IP addresses in configuration
- Try different DNS servers (e.g., 1.1.1.1, 8.8.8.8)
- Check firewall rules allow DNS queries (UDP port 53)
- Test DNS manually using `nslookup` or `dig`: `nslookup google.com 8.8.8.8`

### Router Check Fails with HTTPS

**Problem**: HTTPS router check fails even when router is accessible.

**Possible Causes**:
- Router uses self-signed certificate
- Router requires authentication
- Router doesn't support HTTPS

**Solutions**:
- Set `"insecureTls": true` in router check configuration
- Try TCP socket connection check instead: `"method": "tcp"` (does not require root privileges)
- Try HTTP instead of HTTPS: `"method": "http"`
- Verify router host is correct and accessible from browser
- For TCP socket connection, ensure the router accepts connections on the specified port (default: 80)

**Note**: The `"tcp"` method uses TCP socket connection, not ICMP ping, so it doesn't require root privileges or the `ping` command.

### Script Times Out

**Problem**: Script exceeds 10-second MeshMonitor timeout.

**Solutions**:
- Reduce `timeoutMs` for individual checks
- Reduce number of DNS checks
- Check system performance (high CPU/memory usage can slow checks)

### Configuration File Not Found

**Problem**: Script can't find `memon.config.json`.

**Solutions**:
- Ensure config file is in the same directory as the script
- Or modify script to use absolute path to config file
- Script will use defaults if config file is missing (but this may not be desired)

### State File Issues

**Problem**: State file becomes corrupted or shows incorrect values.

**Solutions**:
- Delete `memon.state.json` to reset state (script will create new default state)
- Check file permissions: script needs read/write access
- Verify JSON syntax is valid if manually editing state file

## Advanced Usage

### Debug Mode

Enable debug mode to see detailed failure messages for troubleshooting:

```json
{
  "debug": true
}
```

When `debug=true`, the script prints failure messages to stdout, including:
- Router check failures with connection details
- DNS check failures with error messages and timeouts

**Important**: Debug mode should only be used for troubleshooting. When enabled, the failure messages printed to stdout will interfere with MeshMonitor's JSON parsing. Always set `"debug": false` for production use to ensure clean JSON-only output.

### Custom Message Templates

Use placeholders in messages for dynamic content:

```json
{
  "messages": {
    "upstreamDnsDown": "DNS issue: {{failed}} are unreachable"
  }
}
```

The `{{failed}}` placeholder is replaced with a comma-separated list of failed DNS resolver names.

### UTF-8 and International Characters

The script fully supports UTF-8 encoding, allowing you to use:

- **Non-ASCII characters**: Accented characters (é, ñ, ü, etc.) and other Unicode characters
- **Emojis**: 🚨, ⚠️, ✅, ❌, 📡, etc.

Example configuration with UTF-8 characters:

```json
{
  "messages": {
    "routerDown": "Router is down 🚨",
    "ispDown": "All DNS resolvers failed - ISP may be down ⚠️",
    "recovery": "Network connectivity restored ✅"
  }
}
```

The configuration file must be saved as UTF-8 encoding. JSON output preserves these characters directly without escaping (e.g., `\u00e6`).

### Monitoring Multiple Networks

To monitor multiple networks, create separate script instances:

1. Copy script to different names: `memon-home.py`, `memon-office.py`
2. Create separate config files: `memon-home.config.json`, `memon-office.config.json`
3. Create separate state files (script auto-creates based on config path)
4. Configure separate MeshMonitor triggers for each

### Integration with Other Scripts

The script outputs standard JSON that can be consumed by other tools:

```json
{
  "response": "Router is down"
}
```

You can pipe script output to other processes or log it for analysis.

## License

This script is provided as-is for use with MeshMonitor. See MeshMonitor project license for details.

## Development & Testing

### Running Tests

The project includes a comprehensive test suite using Python's `unittest` framework.

**Run all tests:**
```bash
python memon.test.py
```

**Run tests with verbose output:**
```bash
python memon.test.py -v
```

**Alternative (using unittest discovery):**
```bash
python -m unittest discover -s . -p "*.test.py"
```

### Automated Testing

This project includes automated testing that runs on every commit:

- **GitHub Actions**: Tests run automatically on push and pull requests across multiple Python versions (3.8-3.12) and operating systems (Ubuntu, Windows, macOS)
- **Pre-commit Hooks**: Local tests run before each commit (optional, install with `pip install pre-commit && pre-commit install`)

### Test Coverage

The test suite covers:
- Configuration loading and validation
- State file management
- Router checks (HTTPS, HTTP, and TCP)
- DNS resolver checks
- Status classification
- Alert firing logic (DOWN and UP alerts)
- Failure streak tracking
- Backoff logic
- Placeholder replacement
- Timeout protection
- Error handling

### Contributing

Found a bug or have a feature request? Please file an issue on the [MeMon GitHub repository](https://github.com/DagBertelsen/MeMon).

**Before submitting changes:**
1. Run the test suite: `python memon.test.py -v`
2. Ensure all tests pass
3. Verify script syntax: `python -m py_compile memon.py`
4. Check that the `mm_meta` block is present in `memon.py`

## See Also

- [MeshMonitor User Scripts Documentation](https://meshmonitor.org/user-scripts.html)
- [MeshMonitor Auto Responder Guide](https://meshmonitor.org/docs/automation/auto-responder.html)
- [MeshMonitor Scripting Guide](https://meshmonitor.org/docs/development/scripting.html)
