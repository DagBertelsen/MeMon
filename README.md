# memon Auto-Responder Script

A Python Auto-Responder script for MeshMonitor that monitors home network health (router and DNS resolvers) and outputs JSON alerts only when notifications should fire. Implements failure streak tracking with backoff logic to prevent alert spam.

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

Copy the configuration file to an appropriate location (e.g., `/data/scripts/`):

```bash
cp memon.config.json /data/scripts/memon.config.json
```

**Note**: The script looks for `memon.config.json` in the current working directory. You may need to adjust the path in the script or ensure the config file is in the same directory as the script.

### 5. Edit Configuration

Edit `memon.config.json` to match your network setup (see Configuration section below).

## Configuration

The script uses `memon.config.json` for all configuration. If the file doesn't exist, default values are used.

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
    "method": "https|http|tcp",
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
    }
  ]
}
```

### Configuration Fields

#### Top-Level Settings

- **`timeoutMs`** (integer, default: 2500): Timeout in milliseconds for each individual check (router and DNS). Total script execution must complete within 10 seconds (MeshMonitor hard limit).
- **`mustFailCount`** (integer, default: 3): Number of consecutive failures required before sending a DOWN alert. Prevents false positives from transient network issues.
- **`alertBackoffSeconds`** (integer, default: 900): Minimum time in seconds between alerts. Prevents alert spam during extended outages.
- **`debug`** (boolean, default: false): If `true`, prints failure messages to stdout for debugging purposes. When `false` (default), only JSON alerts are printed to stdout, ensuring clean output for MeshMonitor. Failure messages include router check failures and DNS check failures with error details.

#### Messages

Customize alert messages for different failure scenarios:

- **`routerDown`**: Message sent when router check fails
- **`ispDown`**: Message sent when all DNS resolvers fail (suggests ISP outage)
- **`upstreamDnsDown`**: Message sent when some (but not all) DNS resolvers fail. Use `{{failed}}` placeholder to list failed resolvers.
- **`recovery`**: Message sent when network recovers after being down

**Message Length**: Messages are automatically truncated to 200 characters per MeshMonitor requirements.

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

### Example Configurations

#### HTTPS Router with Multiple DNS Checks

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

#### Aggressive Monitoring (Faster Alerts)

```json
{
  "timeoutMs": 2000,
  "mustFailCount": 2,
  "alertBackoffSeconds": 300
}
```

#### Conservative Monitoring (Fewer False Positives)

```json
{
  "timeoutMs": 3000,
  "mustFailCount": 5,
  "alertBackoffSeconds": 1800
}
```

## MeshMonitor Setup

### 1. Configure Auto Responder Trigger

1. Navigate to **Settings → Automation → Auto Responder** in MeshMonitor
2. Click **"Add Trigger"**
3. Configure the trigger:
   - **Trigger Pattern**: Use a pattern that matches when you want to check network status. Examples:
     - `netcheck` - Simple command trigger
     - `check network` - Phrase trigger
     - `status` - Short status check
   - **Response Type**: Select **"Script"**
   - **Script Path**: Enter `/data/scripts/memon.py`

### 2. Example Trigger Patterns

- **Simple Command**: `netcheck` - Send "netcheck" to trigger
- **Question Format**: `network status` - Natural language trigger
- **Periodic Check**: Use MeshMonitor's scheduled triggers (if available) to run periodically

### 3. Script Path Configuration

The script path in MeshMonitor should be:
```
/data/scripts/memon.py
```

**Important**: Ensure the script has execute permissions (`chmod +x`) and the configuration file is accessible from the script's working directory.

### 4. Testing the Trigger

1. Send a message matching your trigger pattern to your MeshMonitor node
2. The script will run and check network status
3. If conditions are met (failures exceed threshold, backoff elapsed), you'll receive an alert
4. Otherwise, the script exits silently (no response)

## How It Works

### Execution Flow

1. **Load Configuration**: Reads `memon.config.json` (or uses defaults)
2. **Load State**: Reads `memon.state.json` (creates default if missing)
3. **Check Router**: Performs router check (HTTPS or TCP socket connection)
   - If router fails → Classify as "router down", skip DNS checks
4. **Check DNS** (if router OK): Checks all configured DNS resolvers in parallel using standard library socket
5. **Classify Status**: Determines failure type (router down, all DNS failed, some DNS failed, or all OK)
6. **Update Failure Streak**: Increments on failure, resets on success
7. **Evaluate Alerts**:
   - **DOWN alert fires when**: `failStreak >= mustFailCount` AND `downNotified == false` AND backoff elapsed
   - **UP alert fires when**: All checks pass AND `downNotified == true`
   - **Partial Recovery alert fires when**: Network partially recovers (bypasses backoff):
     - Router recovers but DNS issues remain (routerDown → ispDown/upstreamDnsDown)
     - All DNS failed → some DNS recovered (ispDown → upstreamDnsDown)
     - Some DNS recovered (upstreamDnsDown → upstreamDnsDown with fewer failures)
8. **Output**: Emits JSON to stdout only when alert fires, otherwise exits silently. When `debug=true`, failure messages are also printed to stdout for troubleshooting.

### State Management

The script maintains state in `memon.state.json`:

- **`failStreak`**: Current consecutive failure count
- **`downNotified`**: Whether a DOWN alert was already sent
- **`lastAlertTs`**: Timestamp of last alert (for backoff calculation)
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
- Backoff period hasn't elapsed since last alert (doesn't apply to partial recovery alerts)
- Script is exiting before checks complete (timeout)

**Solutions**:
- Check `memon.state.json` to see current `failStreak` value
- Reduce `mustFailCount` for faster alerts (but more false positives)
- Reduce `alertBackoffSeconds` for more frequent alerts
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

- **GitHub Actions**: Tests run automatically on push and pull requests across multiple Python versions (3.7-3.12) and operating systems (Ubuntu, Windows, macOS)
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

Found a bug or have a feature request? Please file an issue on the MeshMonitor GitHub repository.

**Before submitting changes:**
1. Run the test suite: `python memon.test.py -v`
2. Ensure all tests pass
3. Verify script syntax: `python -m py_compile memon.py`
4. Check that the `mm_meta` block is present in `memon.py`

## See Also

- [MeshMonitor User Scripts Documentation](https://meshmonitor.org/user-scripts.html)
- [MeshMonitor Auto Responder Guide](https://meshmonitor.org/docs/automation/auto-responder.html)
- [MeshMonitor Scripting Guide](https://meshmonitor.org/docs/development/scripting.html)
