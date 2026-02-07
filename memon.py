#!/usr/bin/env python3
# mm_meta:
#   name: MeMon
#   emoji: 🌐
#   language: Python

__version__ = "1.1.3"

"""
MeMon Network Health Monitor for MeshMonitor

Monitors router and DNS health, outputs JSON alerts only when notifications should fire.
Implements failure streak tracking with backoff logic.
"""

import json
import os
import sys
import socket
import struct
import time
import traceback
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError


# Configure stdout/stderr for UTF-8 support
if hasattr(sys.stdout, 'reconfigure') and sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass  # Fallback gracefully if reconfigure fails
if hasattr(sys.stderr, 'reconfigure') and sys.stderr.encoding != 'utf-8':
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass  # Fallback gracefully if reconfigure fails


# Default configuration values
DEFAULT_CONFIG = {
    "timeoutMs": 2500,
    "mustFailCount": 3,
    "alertBackoffSeconds": 900,
    "debug": False,
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

# Default port numbers
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DEFAULT_DNS_PORT = 53

# Maximum UDP DNS response size (RFC 1035 standard, without EDNS)
DNS_UDP_MAX_SIZE = 512


def _get_script_dir() -> str:
    """
    Get the directory where this script is located.
    
    Returns:
        Absolute path to the script's directory
    """
    return os.path.dirname(os.path.abspath(__file__))


# Script directory for resolving relative paths
SCRIPT_DIR = _get_script_dir()


def _debug_log(tag: str, message: str, debug: bool) -> None:
    """Print a debug message to stderr if debug mode is enabled."""
    if debug:
        print(f"[{tag}] {message}", file=sys.stderr)


def _ms_to_seconds(ms: int) -> float:
    """
    Convert milliseconds to seconds.
    
    Args:
        ms: Time in milliseconds
        
    Returns:
        Time in seconds as float
    """
    return ms / 1000.0


def _get_default_port(method: str) -> int:
    """
    Get default port number for router check method.

    Args:
        method: Router check method ("https", "http", or "tcp")

    Returns:
        Default port number for the method
    """
    method_lower = method.lower()
    if method_lower == "https":
        return DEFAULT_HTTPS_PORT
    elif method_lower == "http" or method_lower == "tcp":
        return DEFAULT_HTTP_PORT
    else:
        return DEFAULT_HTTPS_PORT  # Default to HTTPS port


def detect_execution_mode() -> str:
    """
    Detect execution mode based on environment variables.

    MeshMonitor sets MESSAGE and/or TRIGGER environment variables when
    running in Auto Responder mode (user-triggered). Timer Trigger mode
    (scheduled) does not set these variables.

    Returns:
        "auto_responder" if MESSAGE or TRIGGER env vars are present
        "timer_trigger" if neither env var is present
    """
    if os.environ.get("MESSAGE") or os.environ.get("TRIGGER"):
        return "auto_responder"
    return "timer_trigger"


def parse_auto_responder_command(message: str) -> str:
    """
    Parse a command keyword from the Auto Responder MESSAGE text.

    Scans the lowercased message for recognized command keywords.
    Returns the first match found. If no keyword is recognized or
    the message is empty, returns "help".

    Args:
        message: The raw MESSAGE environment variable value

    Returns:
        Command string: "status", "router", "dns", "version", or "help"
    """
    if not message or not message.strip():
        return "help"

    text = message.lower()

    if "status" in text or "all" in text:
        return "status"
    if "router" in text:
        return "router"
    if "dns" in text:
        return "dns"
    if "version" in text:
        return "version"

    return "help"


def _get_dns_display_name(check: Dict[str, Any], index: int) -> str:
    """
    Extract display name from DNS check config or generate fallback.

    Args:
        check: DNS check configuration dictionary
        index: Zero-based index for fallback naming

    Returns:
        Display name for the DNS server
    """
    return check.get("name", f"DNS-{index}")


def _log_router_failure(method: str, host: str, port: int, reason: str, debug: bool) -> None:
    """
    Log router check failure message if debug mode is enabled.

    Args:
        method: Router check method
        host: Router hostname or IP
        port: Port number
        reason: Failure reason
        debug: If True, print debug message
    """
    _debug_log("Router", f"FAIL: {method} {host}:{port} - {reason}", debug)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and validate configuration file with defaults.
    
    Args:
        config_path: Path to configuration JSON file. If None, uses script-relative path.
        
    Returns:
        Configuration dictionary with defaults applied
        
    Raises:
        FileNotFoundError: If config file is missing
        ValueError: If config file is invalid
    """
    # Resolve config path relative to script directory if not provided
    if config_path is None:
        config_path = os.path.join(SCRIPT_DIR, "memon.config.json")
    
    # Check if config file exists
    if not os.path.exists(config_path):
        raise FileNotFoundError("Missing memon.config.json (copy memon.config.example.json to memon.config.json)")
    
    config = DEFAULT_CONFIG.copy()
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            # Merge user config over defaults (shallow for top-level, deep for nested dicts)
            config.update(user_config)
            if "messages" in user_config:
                config["messages"].update(user_config["messages"])
            if "routerCheck" in user_config:
                config["routerCheck"].update(user_config["routerCheck"])
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading config file {config_path}: {e}", file=sys.stderr)
        sys.exit(1)
    
    return config


def load_state(state_path: Optional[str] = None, debug: bool = False) -> Dict[str, Any]:
    """
    Load state file or create default state if missing.

    Args:
        state_path: Path to state JSON file. If None, uses script-relative path.
        debug: If True, print debug messages to stderr.

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

                # Clamp lastAlertTs if in future (prevents infinite backoff if clock jumped forward then corrected)
                current_time = int(time.time())
                old_ts = state.get("lastAlertTs", 0)
                if old_ts > current_time:
                    state["lastAlertTs"] = current_time
                    _debug_log("State", f"Clock skew detected, clamped lastAlertTs from {old_ts} to {current_time}", debug)
        except (json.JSONDecodeError, IOError):
            # If state file is corrupted, use defaults
            _debug_log("State", "State file corrupted, using defaults", debug)

    _debug_log("State", f"Loaded: failStreak={state['failStreak']}, downNotified={state['downNotified']}, lastAlertTs={state['lastAlertTs']}", debug)
    return state


def save_state(state: Dict[str, Any], state_path: Optional[str] = None, debug: bool = False) -> None:
    """
    Write state to JSON file.

    Args:
        state: State dictionary to save
        state_path: Path to state JSON file. If None, uses script-relative path.
        debug: If True, print debug messages to stderr.

    Raises:
        SystemExit: If state file cannot be written (exits with stderr only)
    """
    # Resolve state path relative to script directory if not provided
    if state_path is None:
        state_path = os.path.join(SCRIPT_DIR, "memon.state.json")

    try:
        with open(state_path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
        _debug_log("State", f"Saved: failStreak={state.get('failStreak')}, downNotified={state.get('downNotified')}", debug)
    except IOError as e:
        print(f"Error saving state file {state_path}: {e}", file=sys.stderr)
        sys.exit(1)


def _check_router_http_request(url: str, timeout_ms: int, ssl_context: Any = None) -> bool:
    """
    Perform HTTP/HTTPS request to check router connectivity.

    Args:
        url: URL to check
        timeout_ms: Request timeout in milliseconds
        ssl_context: SSL context for HTTPS requests, or None for HTTP

    Returns:
        True if router responds with 2xx/3xx, False otherwise
    """
    try:
        req = urllib.request.Request(url)
        timeout_sec = _ms_to_seconds(timeout_ms)
        kwargs = {"timeout": timeout_sec}
        if ssl_context is not None:
            kwargs["context"] = ssl_context
        with urllib.request.urlopen(req, **kwargs) as response:
            # Any 2xx or 3xx response is considered success
            return 200 <= response.getcode() < 400
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ssl.SSLError):
        return False
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False


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
    ssl_context = ssl.create_default_context()
    if insecure_tls:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return _check_router_http_request(url, timeout_ms, ssl_context)


def check_router_http(url: str, timeout_ms: int) -> bool:
    """
    Check router via HTTP request.

    Args:
        url: HTTP URL to check
        timeout_ms: Request timeout in milliseconds

    Returns:
        True if router responds successfully, False otherwise
    """
    return _check_router_http_request(url, timeout_ms)


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
        timeout_sec = _ms_to_seconds(timeout_ms)
        
        # Attempt TCP connection
        sock = socket.create_connection((host, port), timeout=timeout_sec)
        sock.close()
        return True
    except (socket.timeout, socket.error, OSError, ValueError):
        return False
    # Catch any other unexpected exceptions to prevent script crash
    except Exception:
        return False


def check_router(router_check: Dict[str, Any], timeout_ms: int, debug: bool = False) -> bool:
    """
    Perform router check (HTTPS, HTTP, or TCP socket connection).
    
    Args:
        router_check: Router check configuration
        timeout_ms: Timeout in milliseconds
        debug: If True, print debug messages to stderr
        
    Returns:
        True if router check passes, False otherwise
    """
    method = router_check.get("method", "https").lower()
    host = router_check.get("host", "192.168.1.1")
    port = router_check.get("port")  # None if not specified
    
    # Use default port if not specified
    if port is None:
        port = _get_default_port(method)
    
    if method == "tcp":
        result = check_router_tcp(host, timeout_ms, port)
    elif method == "http":
        url = f"http://{host}:{port}"
        result = check_router_http(url, timeout_ms)
    else:  # https (default)
        url = f"https://{host}:{port}"
        insecure_tls = router_check.get("insecureTls", False)
        result = check_router_https(url, insecure_tls, timeout_ms)

    if result:
        _debug_log("Router", f"OK: {method} {host}:{port}", debug)
    else:
        _log_router_failure(method, host, port, f"{method.upper()} check failed", debug)
    return result


def _encode_domain_name(domain: str) -> bytes:
    """
    Encode domain name for DNS packet (length-prefixed labels, null-terminated).
    
    Args:
        domain: Domain name (e.g., "google.com")
        
    Returns:
        Encoded domain name as bytes
    """
    encoded = b""
    for label in domain.split("."):
        if label:
            encoded += struct.pack("B", len(label)) + label.encode("ascii")
    encoded += b"\x00"  # Null terminator
    return encoded


def _build_dns_query(qname: str, rrtype: str) -> bytes:
    """
    Build DNS query packet.
    
    Args:
        qname: Query name (domain to resolve)
        rrtype: Record type (A or AAAA)
        
    Returns:
        DNS query packet as bytes
    """
    # Generate random transaction ID
    import random
    transaction_id = random.randint(0, 65535)
    
    # DNS header (12 bytes)
    # ID (2 bytes), Flags (2 bytes), QDCOUNT (2 bytes), ANCOUNT (2 bytes),
    # NSCOUNT (2 bytes), ARCOUNT (2 bytes)
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1  # One question
    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)
    
    # Question section
    qname_encoded = _encode_domain_name(qname)
    
    # QTYPE: A=1, AAAA=28
    if rrtype.upper() == "AAAA":
        qtype = 28
    else:  # Default to A
        qtype = 1
    
    qclass = 1  # IN (Internet)
    question = struct.pack("!HH", qtype, qclass)
    
    return header + qname_encoded + question


def _parse_dns_response(data: bytes, expected_rrtype: str) -> Tuple[bool, str]:
    """
    Parse DNS response packet and verify it contains expected record type.
    
    Args:
        data: DNS response packet bytes
        expected_rrtype: Expected record type (A or AAAA)
        
    Returns:
        Tuple of (success: bool, error_message: str)
    """
    if len(data) < 12:
        return False, "Response too short (less than 12 bytes)"
    
    try:
        # Parse header
        header = struct.unpack("!HHHHHH", data[0:12])
        flags = header[1]
        qdcount = header[2]
        ancount = header[3]
        
        # Check response code (bits 0-3 of flags byte 2)
        rcode = flags & 0x000F
        if rcode != 0:  # NOERROR = 0, NXDOMAIN = 3, etc.
            rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
            rcode_name = rcode_names.get(rcode, f"RCODE{rcode}")
            return False, f"DNS response error: {rcode_name}"
        
        # Check if we have answers
        if ancount == 0:
            return False, "No answers in DNS response"
        
        # Skip question section to find answer section
        offset = 12
        # Skip QNAME
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:  # Compression pointer (RFC 1035 4.1.4) - name continues at pointed-to offset
                offset += 2
                break
            else:
                label_len = data[offset]
                if label_len == 0:
                    break
                if offset + 1 + label_len > len(data):
                    return False, "Invalid QNAME: label extends beyond packet"
                offset += 1 + label_len
        if offset < len(data) and data[offset] == 0:
            offset += 1  # Skip null terminator
        
        # Skip QTYPE and QCLASS (4 bytes)
        if offset + 4 > len(data):
            return False, "Invalid question section: QTYPE/QCLASS missing"
        offset += 4
        
        # Parse answer section
        expected_type = 28 if expected_rrtype.upper() == "AAAA" else 1
        found_match = False
        
        for _ in range(ancount):
            if offset >= len(data):
                return False, "Answer section extends beyond packet"
            
            # Skip NAME (may be compressed)
            if offset < len(data) and data[offset] & 0xC0 == 0xC0:
                offset += 2  # Compression pointer
            else:
                # Skip uncompressed name
                while offset < len(data) and data[offset] != 0:
                    label_len = data[offset]
                    if label_len == 0:
                        break
                    if offset + 1 + label_len > len(data):
                        return False, "Invalid answer NAME: label extends beyond packet"
                    offset += 1 + label_len
                if offset < len(data):
                    offset += 1  # Skip null terminator
            
            if offset + 10 > len(data):
                return False, "Answer record header incomplete"
            
            # Parse answer record: TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
            answer_header = struct.unpack("!HHIH", data[offset:offset+10])
            answer_type = answer_header[0]
            rdlength = answer_header[3]  # RDLENGTH is the 4th element (index 3)
            offset += 10
            
            # Check if this answer matches expected type
            if answer_type == expected_type:
                # Verify RDATA length matches expected type
                if expected_type == 1:  # A record
                    if rdlength == 4:  # IPv4 is 4 bytes
                        found_match = True
                        break
                elif expected_type == 28:  # AAAA record
                    if rdlength == 16:  # IPv6 is 16 bytes
                        found_match = True
                        break
            
            # Skip RDATA
            if offset + rdlength > len(data):
                return False, "Answer RDATA extends beyond packet"
            offset += rdlength
        
        if not found_match:
            return False, f"No {expected_rrtype} record found in response"
        
        return True, ""
    except (struct.error, IndexError) as e:
        return False, f"DNS parsing error: {str(e)}"


def check_dns(server: str, qname: str, rrtype: str, timeout_ms: int) -> Tuple[bool, str]:
    """
    Check single DNS resolver using standard library socket.
    
    Args:
        server: DNS server IP address
        qname: Query name (domain to resolve)
        rrtype: Record type (A or AAAA)
        timeout_ms: Timeout in milliseconds
        
    Returns:
        Tuple of (success: bool, error_message: str)
    """
    try:
        timeout_sec = _ms_to_seconds(timeout_ms)
        
        # Build DNS query packet
        query = _build_dns_query(qname, rrtype)
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        
        try:
            # Send query to DNS server on default DNS port
            sock.sendto(query, (server, DEFAULT_DNS_PORT))
            
            # Receive response
            data, _ = sock.recvfrom(DNS_UDP_MAX_SIZE)
            
            # Parse and validate response
            success, error_msg = _parse_dns_response(data, rrtype)
            if not success:
                return False, error_msg
            return True, ""
        finally:
            sock.close()
            
    except socket.timeout:
        return False, "Timeout waiting for DNS response"
    except (socket.error, OSError) as e:
        return False, f"Socket error: {str(e)}"
    except (ValueError, struct.error) as e:
        return False, f"Protocol error: {str(e)}"
    # Catch any other unexpected exceptions to prevent script crash
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def check_all_dns(dns_checks: List[Dict[str, Any]], timeout_ms: int, max_total_time: float, debug: bool = False) -> Tuple[List[str], List[str]]:
    """
    Check all DNS resolvers in parallel (with timeout protection).
    
    Args:
        dns_checks: List of DNS check configurations
        timeout_ms: Timeout per DNS check in milliseconds
        max_total_time: Maximum total time allowed (seconds)
        debug: If True, print debug messages to stderr
        
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
            futures[future] = (name, server, qname)
        
        # Wait for all with overall timeout protection
        for future in futures:
            elapsed = time.time() - start_time
            remaining_time = max_total_time - elapsed
            name, server, qname = futures[future]
            
            if remaining_time <= 0:
                # Out of time, mark remaining as failed
                failed_names.append(name)
                _debug_log("DNS", f"FAIL: {name} ({server}) querying {qname} - Timeout (out of time)", debug)
                continue

            try:
                success, error_msg = future.result(timeout=min(remaining_time, _ms_to_seconds(timeout_ms) + 0.5))
                if not success:
                    failed_names.append(name)
                    _debug_log("DNS", f"FAIL: {name} ({server}) querying {qname} - {error_msg}", debug)
                else:
                    _debug_log("DNS", f"OK: {name} ({server}) querying {qname}", debug)
            except FutureTimeoutError:
                failed_names.append(name)
                _debug_log("DNS", f"FAIL: {name} ({server}) querying {qname} - Timeout waiting for response", debug)
            except Exception as e:
                failed_names.append(name)
                _debug_log("DNS", f"FAIL: {name} ({server}) querying {qname} - Exception: {str(e)}", debug)
    
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
    print(json.dumps(output, ensure_ascii=False))
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


def _build_dns_status_list(dns_checks: List[Dict[str, Any]], failed_dns: List[str]) -> List[str]:
    """Build list of 'Name OK/FAIL' strings for all DNS checks."""
    dns_statuses = []
    for i, check in enumerate(dns_checks):
        name = _get_dns_display_name(check, i)
        status = "FAIL" if name in failed_dns else "OK"
        dns_statuses.append(f"{name} {status}")
    return dns_statuses


def format_status_report(router_ok: bool, failed_dns: List[str], all_dns: List[str],
                        dns_checks: List[Dict[str, Any]]) -> str:
    """
    Format status report for Auto Responder mode.

    Returns current status of router and all DNS checks, optimized for
    200-character MeshMonitor message limit.

    Args:
        router_ok: Whether router check passed
        failed_dns: List of failed DNS resolver names
        all_dns: List of all DNS resolver names
        dns_checks: DNS check configurations (for name extraction)

    Returns:
        Formatted status message (max 200 chars with truncation)

    Output formats:
        - Router down: "Router DOWN"
        - Router OK, no DNS: "Router OK"
        - Router OK, all DNS fail: "Router OK, All DNS FAIL"
        - Router OK, mixed: "Router OK, DNS: Google OK, Cloudflare FAIL, ..."
    """
    # Router down - simple message
    if not router_ok:
        return "Router DOWN"

    # Router OK, no DNS checks configured
    if not all_dns:
        return "Router OK"

    # Router OK, all DNS failed
    if len(failed_dns) == len(all_dns):
        return "Router OK, All DNS FAIL"

    # Router OK, mixed DNS status - build detailed report
    # Format: "Router OK, DNS: Name1 OK, Name2 FAIL, Name3 OK"
    dns_report = ", ".join(_build_dns_status_list(dns_checks, failed_dns))
    message = f"Router OK, DNS: {dns_report}"

    # Truncate if exceeds MAX_MESSAGE_LENGTH (200 chars)
    if len(message) > MAX_MESSAGE_LENGTH:
        # Try abbreviated format: "Router OK, 2 of 5 DNS FAIL"
        fail_count = len(failed_dns)
        total_count = len(all_dns)
        message = f"Router OK, {fail_count} of {total_count} DNS FAIL"

        # If still too long, use minimal format
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[:MAX_MESSAGE_LENGTH - 3] + "..."

    return message


def format_router_report(router_ok: bool) -> str:
    """
    Format router-only status report for Auto Responder mode.

    Args:
        router_ok: Whether router check passed

    Returns:
        Formatted router status message
    """
    if router_ok:
        return "Router OK"
    return "Router DOWN"


def format_dns_report(router_ok: bool, failed_dns: List[str], all_dns: List[str],
                      dns_checks: List[Dict[str, Any]]) -> str:
    """
    Format DNS-only status report for Auto Responder mode.

    Router must be up to perform DNS checks. If router is down,
    reports that DNS could not be checked.

    Args:
        router_ok: Whether router check passed
        failed_dns: List of failed DNS resolver names
        all_dns: List of all DNS resolver names
        dns_checks: DNS check configurations (for name extraction)

    Returns:
        Formatted DNS status message (max 200 chars with truncation)
    """
    if not router_ok:
        return "DNS: Unknown (router down)"

    if not all_dns:
        return "DNS: No checks configured"

    if len(failed_dns) == len(all_dns):
        return "DNS: All FAIL"

    if not failed_dns:
        return "DNS: All OK"

    # Mixed status - show individual results
    dns_report = ", ".join(_build_dns_status_list(dns_checks, failed_dns))
    message = f"DNS: {dns_report}"

    if len(message) > MAX_MESSAGE_LENGTH:
        fail_count = len(failed_dns)
        total_count = len(all_dns)
        message = f"DNS: {fail_count} of {total_count} FAIL"
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[:MAX_MESSAGE_LENGTH - 3] + "..."

    return message


def format_help_message() -> str:
    """
    Format help guide listing supported Auto Responder commands.

    Returns:
        Help message string (fits within 200-char limit)
    """
    return "Commands: status/all (full report), router (router only), dns (DNS only), version"


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


def _run_auto_responder(router_ok: bool, failed_dns: List[str], all_dns: List[str],
                        dns_checks: List[Dict[str, Any]], ar_command: str, debug: bool) -> None:
    """
    Handle Auto Responder mode: emit report based on command (stateless).

    Args:
        router_ok: Whether router check passed
        failed_dns: List of failed DNS resolver names
        all_dns: List of all DNS resolver names
        dns_checks: DNS check configurations
        ar_command: Parsed Auto Responder command
        debug: If True, print debug messages to stderr
    """
    if ar_command == "router":
        message = format_router_report(router_ok)
    elif ar_command == "dns":
        message = format_dns_report(router_ok, failed_dns, all_dns, dns_checks)
    else:  # "status" / "all"
        message = format_status_report(router_ok, failed_dns, all_dns, dns_checks)
    _debug_log("Alert", f"Emitting: \"{message}\"", debug)
    emit_alert(message)


def _run_timer_trigger(config: Dict[str, Any], debug: bool, router_ok: bool,
                       failed_dns: List[str], all_dns: List[str], current_time: int) -> None:
    """
    Handle Timer Trigger mode: stateful alert logic with failure tracking and backoff.

    Args:
        config: Full configuration dictionary
        debug: If True, print debug messages to stderr
        router_ok: Whether router check passed
        failed_dns: List of failed DNS resolver names
        all_dns: List of all DNS resolver names
        current_time: Current Unix timestamp
    """
    must_fail_count = config.get("mustFailCount", 3)
    backoff_seconds = config.get("alertBackoffSeconds", 900)
    messages = config.get("messages", {})

    # Load state
    state = load_state(debug=debug)
    fail_streak = state.get("failStreak", 0)
    down_notified = state.get("downNotified", False)
    last_alert_ts = state.get("lastAlertTs", 0)
    last_status = state.get("lastStatus", None)
    last_failed_dns = state.get("lastFailedDns", [])

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

    _debug_log("Alert", f"status={status}, failStreak={fail_streak}/{must_fail_count}, "
               f"fire_down={fire_down}, fire_up={fire_up}, fire_partial={fire_partial_recovery}", debug)

    # Emit alerts and update state
    if fire_down:
        message = _format_alert_message(status, messages, failed_dns)
        _debug_log("Alert", f"Emitting DOWN: \"{message}\"", debug)
        emit_alert(message)
        down_notified = True
        last_alert_ts = current_time

    elif fire_up:
        message = messages.get("recovery", "Network connectivity restored")
        _debug_log("Alert", f"Emitting UP: \"{message}\"", debug)
        emit_alert(message)
        down_notified = False
        last_alert_ts = current_time

    elif fire_partial_recovery:
        # Partial recovery: routerDown -> ispDown/upstreamDnsDown, or ispDown -> upstreamDnsDown
        message = _format_alert_message(status, messages, failed_dns)
        _debug_log("Alert", f"Emitting PARTIAL: \"{message}\"", debug)
        emit_alert(message)
        last_alert_ts = current_time

    else:
        _debug_log("Alert", "No alert fired", debug)

    # Save updated state
    _update_state(state, fail_streak, down_notified, last_alert_ts, status, failed_dns)
    save_state(state, debug=debug)


def main() -> None:
    """
    Main function: orchestrate checks and alert logic with timeout protection.
    Supports two execution modes:
    - Auto Responder: Stateless, always returns current status
    - Timer Trigger: Stateful, conditional alerts with backoff
    """
    start_time = time.time()
    # Cache current time to avoid multiple system calls and ensure consistency
    current_time = int(time.time())

    # Load configuration
    config = load_config()
    timeout_ms = config.get("timeoutMs", 2500)
    debug = config.get("debug", False)
    router_check = config.get("routerCheck", {})
    dns_checks = config.get("dnsChecks", [])

    # Detect execution mode
    mode = detect_execution_mode()

    # Parse command for Auto Responder mode (before network checks to optimize)
    ar_command = None  # type: Optional[str]
    if mode == "auto_responder":
        ar_message = os.environ.get("MESSAGE", "")
        ar_command = parse_auto_responder_command(ar_message)
        _debug_log("Mode", f"auto_responder, command={ar_command}", debug)

        # Help and version commands need no network checks
        if ar_command == "help":
            emit_alert(format_help_message())
            return
        if ar_command == "version":
            emit_alert("MeMon v" + __version__)
            return
    else:
        _debug_log("Mode", "timer_trigger", debug)

    _debug_log("Config", f"timeoutMs={timeout_ms}, mustFailCount={config.get('mustFailCount', 3)}, "
               f"backoff={config.get('alertBackoffSeconds', 900)}s, dnsChecks={len(dns_checks)}", debug)

    # Calculate remaining time (ensure we finish before MeshMonitor timeout)
    elapsed = time.time() - start_time
    remaining_time = MESHMONITOR_TIMEOUT - elapsed - TIMEOUT_SAFETY_MARGIN
    if remaining_time <= 0:
        _debug_log("Timing", "Out of time before network checks, exiting", debug)
        return

    # Check router first
    router_ok = check_router(router_check, timeout_ms, debug)

    _debug_log("Timing", f"After router check: elapsed={time.time() - start_time:.2f}s, "
               f"remaining={MESHMONITOR_TIMEOUT - (time.time() - start_time) - TIMEOUT_SAFETY_MARGIN:.2f}s", debug)

    # Check DNS if router is up (skip for router-only command)
    failed_dns = []  # type: List[str]
    all_dns = []  # type: List[str]
    if router_ok and ar_command != "router":
        # Check DNS with remaining time
        elapsed = time.time() - start_time
        remaining_time = MESHMONITOR_TIMEOUT - elapsed - TIMEOUT_SAFETY_MARGIN
        if remaining_time > 0:
            failed_dns, all_dns = check_all_dns(dns_checks, timeout_ms, remaining_time, debug)

        _debug_log("Timing", f"After DNS checks: elapsed={time.time() - start_time:.2f}s", debug)

    # Dispatch to mode-specific handler
    if mode == "auto_responder":
        _run_auto_responder(router_ok, failed_dns, all_dns, dns_checks, ar_command, debug)
    else:
        _run_timer_trigger(config, debug, router_ok, failed_dns, all_dns, current_time)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: Unexpected error in main(): {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
