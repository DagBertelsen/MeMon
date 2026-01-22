#!/usr/bin/env python3
# mm_meta:
#   name: memon
#   emoji: 🌐
#   language: Python

"""
memon Auto-Responder Script for MeshMonitor

Monitors router and DNS health, outputs JSON alerts only when notifications should fire.
Implements failure streak tracking with backoff logic.
"""

import json
import os
import sys
import socket
import time
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
except ImportError as e:
    print(f"Error: Required library 'dnspython' is not installed. Install it with: pip install dnspython", file=sys.stderr)
    print(f"ImportError details: {e}", file=sys.stderr)
    sys.exit(1)


# Default configuration values
DEFAULT_CONFIG = {
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
        "method": "https",
        "host": "192.168.1.1",
        "port": 443,
        "insecureTls": False
    },
    "dnsChecks": []
}

# Default state values
DEFAULT_STATE = {
    "failStreak": 0,
    "downNotified": False,
    "lastAlertTs": 0,
    "lastStatus": None,
    "lastFailedDns": []
}

# MeshMonitor hard timeout limit (seconds)
MESHMONITOR_TIMEOUT = 10

# Safety margin for timeout calculations (seconds)
TIMEOUT_SAFETY_MARGIN = 0.5

# Maximum alert message length (characters)
MAX_MESSAGE_LENGTH = 200


def _get_script_dir() -> str:
    """
    Get the directory where this script is located.
    
    Returns:
        Absolute path to the script's directory
    """
    return os.path.dirname(os.path.abspath(__file__))


# Script directory for resolving relative paths
SCRIPT_DIR = _get_script_dir()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and validate configuration file with defaults.
    
    Args:
        config_path: Path to configuration JSON file. If None, uses script-relative path.
        
    Returns:
        Configuration dictionary with defaults applied
        
    Raises:
        SystemExit: If config file is missing or invalid (exits with stderr only)
    """
    # Resolve config path relative to script directory if not provided
    if config_path is None:
        config_path = os.path.join(SCRIPT_DIR, "memon.config.json")
    
    # Check if config file exists
    if not os.path.exists(config_path):
        print(f"Error: Missing config file {config_path} (ensure memon.config.json exists in the script directory)", file=sys.stderr)
        sys.exit(1)
    
    config = DEFAULT_CONFIG.copy()
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            # Deep merge defaults with user config
            config.update(user_config)
            if "messages" in user_config:
                config["messages"].update(user_config["messages"])
            if "routerCheck" in user_config:
                config["routerCheck"].update(user_config["routerCheck"])
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading config file {config_path}: {e}", file=sys.stderr)
        sys.exit(1)
    
    return config


def load_state(state_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load state file or create default state if missing.
    
    Args:
        state_path: Path to state JSON file. If None, uses script-relative path.
        
    Returns:
        State dictionary with defaults applied
    """
    # Resolve state path relative to script directory if not provided
    if state_path is None:
        state_path = os.path.join(SCRIPT_DIR, "memon.state.json")
    
    state = DEFAULT_STATE.copy()
    
    if os.path.exists(state_path):
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                user_state = json.load(f)
                state.update(user_state)
                
                # Clamp lastAlertTs if in future (clock skew protection)
                current_time = int(time.time())
                if state.get("lastAlertTs", 0) > current_time:
                    state["lastAlertTs"] = current_time
        except (json.JSONDecodeError, IOError):
            # If state file is corrupted, use defaults
            pass
    
    return state


def save_state(state: Dict[str, Any], state_path: Optional[str] = None) -> None:
    """
    Write state to JSON file.
    
    Args:
        state: State dictionary to save
        state_path: Path to state JSON file. If None, uses script-relative path.
        
    Raises:
        SystemExit: If state file cannot be written (exits with stderr only)
    """
    # Resolve state path relative to script directory if not provided
    if state_path is None:
        state_path = os.path.join(SCRIPT_DIR, "memon.state.json")
    
    try:
        with open(state_path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
    except IOError as e:
        print(f"Error saving state file {state_path}: {e}", file=sys.stderr)
        sys.exit(1)


def check_router_https(url: str, insecure_tls: bool, timeout_ms: int) -> bool:
    """
    Check router via HTTPS request.
    
    Args:
        url: HTTPS URL to check
        insecure_tls: If True, disable TLS certificate validation
        timeout_ms: Request timeout in milliseconds
        
    Returns:
        True if router responds successfully, False otherwise
    """
    try:
        # Create SSL context
        ssl_context = ssl.create_default_context()
        if insecure_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create request with timeout
        req = urllib.request.Request(url)
        timeout_sec = timeout_ms / 1000.0
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=timeout_sec) as response:
            # Any 2xx or 3xx response is considered success
            return 200 <= response.getcode() < 400
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ssl.SSLError):
        return False
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False


def check_router_http(url: str, timeout_ms: int) -> bool:
    """
    Check router via HTTP request.
    
    Args:
        url: HTTP URL to check
        timeout_ms: Request timeout in milliseconds
        
    Returns:
        True if router responds successfully, False otherwise
    """
    try:
        # Create request with timeout
        req = urllib.request.Request(url)
        timeout_sec = timeout_ms / 1000.0
        
        with urllib.request.urlopen(req, timeout=timeout_sec) as response:
            # Any 2xx or 3xx response is considered success
            return 200 <= response.getcode() < 400
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False


def check_router_tcp(host: str, timeout_ms: int, port: int = 80) -> bool:
    """
    Check router via TCP socket connection test.
    
    Uses TCP socket connection instead of ICMP ping to avoid requiring root privileges.
    Tests connectivity by attempting to establish a TCP connection to the router.
    
    Args:
        host: Hostname or IP address to test
        timeout_ms: Timeout in milliseconds per connection attempt
        port: TCP port to connect to (default: 80)
        
    Returns:
        True if TCP connection succeeds, False otherwise
    """
    try:
        timeout_sec = timeout_ms / 1000.0
        
        # Attempt TCP connection
        sock = socket.create_connection((host, port), timeout=timeout_sec)
        sock.close()
        return True
    except (socket.timeout, socket.error, OSError, ValueError):
        return False
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False


def check_router(router_check: Dict[str, Any], timeout_ms: int) -> bool:
    """
    Perform router check (HTTPS, HTTP, or TCP socket connection).
    
    Args:
        router_check: Router check configuration
        timeout_ms: Timeout in milliseconds
        
    Returns:
        True if router check passes, False otherwise
    """
    method = router_check.get("method", "https").lower()
    host = router_check.get("host", "192.168.1.1")
    port = router_check.get("port")  # None if not specified
    
    if method == "tcp":
        if port is None:
            port = 80
        return check_router_tcp(host, timeout_ms, port)
    elif method == "http":
        if port is None:
            port = 80
        url = f"http://{host}:{port}"
        return check_router_http(url, timeout_ms)
    else:  # https (default)
        if port is None:
            port = 443
        url = f"https://{host}:{port}"
        insecure_tls = router_check.get("insecureTls", False)
        return check_router_https(url, insecure_tls, timeout_ms)


def check_dns(server: str, qname: str, rrtype: str, timeout_ms: int) -> Tuple[bool, str]:
    """
    Check single DNS resolver using dnspython library.
    
    Args:
        server: DNS server IP address
        qname: Query name (domain to resolve)
        rrtype: Record type (A or AAAA)
        timeout_ms: Timeout in milliseconds
        
    Returns:
        Tuple of (success: bool, name: str for error reporting)
    """
    try:
        timeout_sec = timeout_ms / 1000.0
        
        # Create resolver with custom nameserver
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = timeout_sec
        resolver.lifetime = timeout_sec
        
        # Convert rrtype string to dns.rdatatype
        rrtype_enum = dns.rdatatype.from_text(rrtype.upper())
        
        # Query DNS
        resolver.resolve(qname, rrtype_enum, lifetime=timeout_sec)
        return True, ""
    except (dns.exception.DNSException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
            dns.exception.Timeout, OSError, ValueError):
        return False, ""
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False, ""


def check_all_dns(dns_checks: List[Dict[str, Any]], timeout_ms: int, max_total_time: float) -> Tuple[List[str], List[str]]:
    """
    Check all DNS resolvers in parallel (with timeout protection).
    
    Args:
        dns_checks: List of DNS check configurations
        timeout_ms: Timeout per DNS check in milliseconds
        max_total_time: Maximum total time allowed (seconds)
        
    Returns:
        Tuple of (failed_names: List[str], all_names: List[str])
    """
    if not dns_checks:
        return [], []
    
    failed_names = []
    all_names = [check.get("name", f"DNS-{i}") for i, check in enumerate(dns_checks)]
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor for parallel DNS checks
    with ThreadPoolExecutor(max_workers=len(dns_checks)) as executor:
        futures = {}
        for check in dns_checks:
            server = check.get("server", "8.8.8.8")
            qname = check.get("qname", "google.com")
            rrtype = check.get("rrtype", "A")
            name = check.get("name", "Unknown")
            
            future = executor.submit(check_dns, server, qname, rrtype, timeout_ms)
            futures[future] = name
        
        # Wait for all with overall timeout protection
        for future in futures:
            elapsed = time.time() - start_time
            remaining_time = max_total_time - elapsed
            if remaining_time <= 0:
                # Out of time, mark remaining as failed
                failed_names.append(futures[future])
                continue
            
            try:
                success, _ = future.result(timeout=min(remaining_time, timeout_ms / 1000.0 + 0.5))
                if not success:
                    failed_names.append(futures[future])
            except (FutureTimeoutError, Exception):
                failed_names.append(futures[future])
    
    return failed_names, all_names


def classify_status(router_ok: bool, failed_dns: List[str], all_dns: List[str]) -> Optional[str]:
    """
    Determine status classification.
    
    Args:
        router_ok: Whether router check passed
        failed_dns: List of failed DNS resolver names
        all_dns: List of all DNS resolver names
        
    Returns:
        Status classification string or None if all OK
    """
    if not router_ok:
        return "routerDown"
    
    if not all_dns:
        return None  # No DNS checks configured, all OK
    
    num_failed = len(failed_dns)
    num_total = len(all_dns)
    
    if num_failed == num_total:
        return "ispDown"
    elif num_failed > 0:
        return "upstreamDnsDown"
    else:
        return None  # All OK


def should_fire_down_alert(fail_streak: int, must_fail_count: int, down_notified: bool,
                           last_alert_ts: int, backoff_seconds: int, current_time: int) -> bool:
    """
    Check if DOWN alert should fire.
    
    Args:
        fail_streak: Current failure streak count
        must_fail_count: Required failures before alerting
        down_notified: Whether down alert was already sent
        last_alert_ts: Timestamp of last alert
        backoff_seconds: Backoff period in seconds
        current_time: Current timestamp (to avoid multiple time.time() calls)
        
    Returns:
        True if DOWN alert should fire
    """
    if fail_streak < must_fail_count:
        return False
    
    if down_notified:
        return False
    
    # Check backoff
    time_since_last = current_time - last_alert_ts
    if time_since_last < backoff_seconds:
        return False
    
    return True


def should_fire_up_alert(all_ok: bool, down_notified: bool) -> bool:
    """
    Check if UP alert should fire.
    
    Args:
        all_ok: Whether all checks passed
        down_notified: Whether down alert was previously sent
        
    Returns:
        True if UP alert should fire
    """
    return all_ok and down_notified


def should_fire_partial_recovery_alert(last_status: Optional[str], current_status: Optional[str],
                                       down_notified: bool, last_failed_dns: List[str],
                                       current_failed_dns: List[str]) -> bool:
    """
    Check if partial recovery alert should fire.
    
    Handles scenarios:
    1. routerDown → ispDown (router recovered, all DNS failed)
    2. routerDown → upstreamDnsDown (router recovered, some DNS failed)
    3. ispDown → upstreamDnsDown (all DNS failed → some DNS recovered)
    4. upstreamDnsDown → upstreamDnsDown with fewer failures (some DNS recovered)
    
    Recovery notifications bypass backoff period.
    
    Args:
        last_status: Previous status classification
        current_status: Current status classification
        down_notified: Whether down alert was previously sent
        last_failed_dns: List of DNS resolver names that failed previously
        current_failed_dns: List of DNS resolver names that are currently failing
        
    Returns:
        True if partial recovery alert should fire
    """
    if not down_notified:
        return False
    
    # Scenario 1 & 2: routerDown → ispDown or upstreamDnsDown
    if last_status == "routerDown":
        if current_status == "ispDown" or current_status == "upstreamDnsDown":
            return True
    
    if current_status != "upstreamDnsDown":
        return False
    
    # Scenario 3: ispDown → upstreamDnsDown
    if last_status == "ispDown":
        return True
    
    # Scenario 4: upstreamDnsDown → upstreamDnsDown with fewer failures
    if last_status == "upstreamDnsDown":
        # Check if fewer DNS are failing now than before
        if len(current_failed_dns) < len(last_failed_dns):
            return True
    
    return False


def emit_alert(message: str) -> None:
    """
    Output JSON alert to stdout.
    
    Args:
        message: Alert message (max length per MeshMonitor requirement)
    """
    # Truncate to max length per MeshMonitor requirement
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH - 3] + "..."
    
    output = {"response": message}
    print(json.dumps(output))
    sys.stdout.flush()


def replace_placeholders(template: str, failed_names: List[str]) -> str:
    """
    Replace placeholders in message template.
    
    Args:
        template: Message template with {{failed}} placeholder
        failed_names: List of failed DNS resolver names
        
    Returns:
        Message with placeholders replaced
    """
    if "{{failed}}" in template:
        failed_str = ", ".join(failed_names)
        return template.replace("{{failed}}", failed_str)
    
    return template


def _format_alert_message(status: Optional[str], messages: Dict[str, str], failed_dns: List[str]) -> str:
    """
    Format alert message based on status and failed DNS resolvers.
    
    Args:
        status: Current status classification
        messages: Message templates dictionary
        failed_dns: List of failed DNS resolver names
        
    Returns:
        Formatted alert message
    """
    if status == "routerDown":
        return messages.get("routerDown", "Router is down")
    elif status == "ispDown":
        return messages.get("ispDown", "All DNS resolvers failed - ISP may be down")
    elif status == "upstreamDnsDown":
        template = messages.get("upstreamDnsDown", "DNS resolvers failed: {{failed}}")
        return replace_placeholders(template, failed_dns)
    else:
        return "Network issue detected"


def _update_state(state: Dict[str, Any], fail_streak: int, down_notified: bool,
                  last_alert_ts: int, status: Optional[str], failed_dns: List[str]) -> None:
    """
    Update state dictionary with current values.
    
    Args:
        state: State dictionary to update
        fail_streak: Current failure streak count
        down_notified: Whether down alert was sent
        last_alert_ts: Timestamp of last alert
        status: Current status classification
        failed_dns: List of failed DNS resolver names
    """
    state["failStreak"] = fail_streak
    state["downNotified"] = down_notified
    state["lastAlertTs"] = last_alert_ts
    state["lastStatus"] = status
    state["lastFailedDns"] = failed_dns


def main() -> None:
    """
    Main function: orchestrate checks and alert logic with timeout protection.
    """
    start_time = time.time()
    # Cache current time to avoid multiple system calls and ensure consistency
    current_time = int(time.time())
    
    # Load configuration
    config = load_config()
    timeout_ms = config.get("timeoutMs", 2500)
    must_fail_count = config.get("mustFailCount", 3)
    backoff_seconds = config.get("alertBackoffSeconds", 900)
    messages = config.get("messages", {})
    router_check = config.get("routerCheck", {})
    dns_checks = config.get("dnsChecks", [])
    
    # Load state
    state = load_state()
    fail_streak = state.get("failStreak", 0)
    down_notified = state.get("downNotified", False)
    last_alert_ts = state.get("lastAlertTs", 0)
    last_status = state.get("lastStatus", None)
    last_failed_dns = state.get("lastFailedDns", [])
    
    # Calculate remaining time (ensure we finish before MeshMonitor timeout)
    elapsed = time.time() - start_time
    remaining_time = MESHMONITOR_TIMEOUT - elapsed - TIMEOUT_SAFETY_MARGIN
    if remaining_time <= 0:
        # Already out of time, exit silently
        return
    
    # Check router first
    router_ok = check_router(router_check, timeout_ms)
    
    # If router is down, skip DNS checks
    failed_dns = []
    all_dns = []
    if router_ok:
        # Check DNS with remaining time
        elapsed = time.time() - start_time
        remaining_time = MESHMONITOR_TIMEOUT - elapsed - TIMEOUT_SAFETY_MARGIN
        if remaining_time > 0:
            failed_dns, all_dns = check_all_dns(dns_checks, timeout_ms, remaining_time)
    
    # Classify status
    status = classify_status(router_ok, failed_dns, all_dns)
    all_ok = (status is None)
    
    # Update failure streak
    if all_ok:
        fail_streak = 0
    else:
        fail_streak += 1
    
    # Determine if alerts should fire
    fire_down = should_fire_down_alert(fail_streak, must_fail_count, down_notified,
                                       last_alert_ts, backoff_seconds, current_time)
    fire_up = should_fire_up_alert(all_ok, down_notified)
    fire_partial_recovery = should_fire_partial_recovery_alert(last_status, status, down_notified,
                                                                last_failed_dns, failed_dns)
    
    # Emit alerts and update state
    if fire_down:
        message = _format_alert_message(status, messages, failed_dns)
        emit_alert(message)
        down_notified = True
        last_alert_ts = current_time
    
    elif fire_up:
        message = messages.get("recovery", "Network connectivity restored")
        emit_alert(message)
        down_notified = False
        last_alert_ts = current_time
    
    elif fire_partial_recovery:
        # Partial recovery: routerDown → ispDown/upstreamDnsDown, or ispDown → upstreamDnsDown
        message = _format_alert_message(status, messages, failed_dns)
        emit_alert(message)
        last_alert_ts = current_time
    
    # Save updated state
    _update_state(state, fail_streak, down_notified, last_alert_ts, status, failed_dns)
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: Unexpected error in main(): {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
