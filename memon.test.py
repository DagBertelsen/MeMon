#!/usr/bin/env python3
"""
Test suite for memon.py using Python unittest.
"""

import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
import json
import sys
import time
import socket
import struct
import urllib.error
import ssl

# Import the module under test
import memon


class TestConfigLoading(unittest.TestCase):
    """Test configuration loading functionality."""
    
    def test_load_config_missing_file(self):
        """Test that load_config errors when config file doesn't exist."""
        with patch('memon.os.path.exists', return_value=False):
            with self.assertRaises(FileNotFoundError) as context:
                memon.load_config("nonexistent.json")
            self.assertIn("Missing memon.config.json", str(context.exception))
            self.assertIn("copy memon.config.example.json", str(context.exception))
    
    def test_load_config_from_file(self):
        """Test loading config from existing file."""
        test_config = {
            "timeoutMs": 5000,
            "mustFailCount": 5,
            "messages": {
                "routerDown": "Custom router message"
            }
        }
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=json.dumps(test_config))):
                config = memon.load_config("test.json")
                self.assertEqual(config["timeoutMs"], 5000)
                self.assertEqual(config["mustFailCount"], 5)
                self.assertEqual(config["messages"]["routerDown"], "Custom router message")
    
    def test_load_config_invalid_json(self):
        """Test handling of invalid JSON in config file."""
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data="invalid json")):
                with patch('sys.exit') as mock_exit:
                    memon.load_config("test.json")
                    mock_exit.assert_called_once_with(1)


class TestStateLoading(unittest.TestCase):
    """Test state loading and saving functionality."""
    
    def test_load_state_defaults(self):
        """Test loading state with defaults when file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            state = memon.load_state("nonexistent.json")
            self.assertEqual(state["failStreak"], 0)
            self.assertEqual(state["downNotified"], False)
            self.assertEqual(state["lastAlertTs"], 0)
            self.assertEqual(state["lastFailedDns"], [])
    
    def test_load_state_from_file(self):
        """Test loading state from existing file."""
        test_state = {
            "failStreak": 5,
            "downNotified": True,
            "lastAlertTs": 1234567890
        }
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=json.dumps(test_state))):
                state = memon.load_state("test.json")
                self.assertEqual(state["failStreak"], 5)
                self.assertEqual(state["downNotified"], True)
                self.assertEqual(state["lastAlertTs"], 1234567890)
    
    def test_load_state_clock_skew_protection(self):
        """Test that future timestamps are clamped to current time."""
        future_ts = int(time.time()) + 3600
        test_state = {"lastAlertTs": future_ts}
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=json.dumps(test_state))):
                with patch('time.time', return_value=test_state["lastAlertTs"] - 3600):
                    state = memon.load_state("test.json")
                    current_time = int(time.time())
                    self.assertLessEqual(state["lastAlertTs"], current_time)
    
    def test_save_state(self):
        """Test saving state to file."""
        test_state = {"failStreak": 3, "downNotified": True, "lastAlertTs": 1234567890}
        with patch('builtins.open', mock_open()) as mock_file:
            memon.save_state(test_state, "test.json")
            mock_file.assert_called_once_with("test.json", 'w', encoding='utf-8')
            # Verify JSON was written
            written_data = ''.join(call.args[0] for call in mock_file().write.call_args_list)
            parsed = json.loads(written_data)
            self.assertEqual(parsed["failStreak"], 3)
    
    def test_save_state_error(self):
        """Test that save_state exits on write error."""
        test_state = {"failStreak": 3, "downNotified": True, "lastAlertTs": 1234567890}
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            with patch('sys.exit') as mock_exit:
                memon.save_state(test_state, "test.json")
                mock_exit.assert_called_once_with(1)


class TestRouterChecks(unittest.TestCase):
    """Test router check functionality."""
    
    @patch('urllib.request.urlopen')
    def test_check_router_https_success(self, mock_urlopen):
        """Test successful HTTPS router check."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        result = memon.check_router_https("https://192.168.1.1", False, 2500)
        self.assertTrue(result)
    
    @patch('urllib.request.urlopen')
    def test_check_router_https_failure(self, mock_urlopen):
        """Test failed HTTPS router check."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")
        
        result = memon.check_router_https("https://192.168.1.1", False, 2500)
        self.assertFalse(result)
    
    @patch('urllib.request.urlopen')
    def test_check_router_https_insecure_tls(self, mock_urlopen):
        """Test HTTPS check with insecure TLS."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        result = memon.check_router_https("https://192.168.1.1", True, 2500)
        self.assertTrue(result)
        # Verify SSL context was created with insecure settings
        call_kwargs = mock_urlopen.call_args[1]
        self.assertIn('context', call_kwargs)
    
    @patch('socket.create_connection')
    def test_check_router_tcp_success(self, mock_create_connection):
        """Test successful TCP socket connection router check."""
        mock_sock = Mock()
        mock_create_connection.return_value = mock_sock
        
        result = memon.check_router_tcp("192.168.1.1", 2500, 80)
        self.assertTrue(result)
        mock_create_connection.assert_called_once()
        mock_sock.close.assert_called_once()
    
    @patch('socket.create_connection')
    def test_check_router_tcp_failure(self, mock_create_connection):
        """Test failed TCP socket connection router check."""
        mock_create_connection.side_effect = socket.error("Connection refused")
        
        result = memon.check_router_tcp("192.168.1.1", 2500, 80)
        self.assertFalse(result)
    
    @patch('socket.create_connection')
    def test_check_router_tcp_timeout(self, mock_create_connection):
        """Test TCP socket connection router check with timeout."""
        mock_create_connection.side_effect = socket.timeout("Connection timed out")
        
        result = memon.check_router_tcp("192.168.1.1", 2500, 80)
        self.assertFalse(result)
    
    @patch('socket.create_connection')
    def test_check_router_tcp_custom_port(self, mock_create_connection):
        """Test TCP socket connection router check with custom port."""
        mock_sock = Mock()
        mock_create_connection.return_value = mock_sock
        
        result = memon.check_router_tcp("192.168.1.1", 2500, 443)
        self.assertTrue(result)
        # Verify port 443 was used
        call_args = mock_create_connection.call_args[0]
        self.assertEqual(call_args[0][1], 443)
    
    @patch('urllib.request.urlopen')
    def test_check_router_http_success(self, mock_urlopen):
        """Test successful HTTP router check."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        result = memon.check_router_http("http://192.168.1.1", 2500)
        self.assertTrue(result)
    
    @patch('urllib.request.urlopen')
    def test_check_router_http_failure(self, mock_urlopen):
        """Test failed HTTP router check."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")
        
        result = memon.check_router_http("http://192.168.1.1", 2500)
        self.assertFalse(result)
    
    @patch('memon.check_router_https')
    def test_check_router_https_method(self, mock_https):
        """Test router check with HTTPS method."""
        mock_https.return_value = True
        router_check = {"method": "https", "host": "192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("https://192.168.1.1:443", False, 2500)
    
    @patch('memon.check_router_tcp')
    def test_check_router_tcp_method(self, mock_tcp):
        """Test router check with TCP method."""
        mock_tcp.return_value = True
        router_check = {"method": "tcp", "host": "192.168.1.1"}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_tcp.assert_called_once_with("192.168.1.1", 2500, 80)
    
    @patch('memon.check_router_tcp')
    def test_check_router_tcp_method_with_port(self, mock_tcp):
        """Test router check with TCP method and custom port."""
        mock_tcp.return_value = True
        router_check = {"method": "tcp", "host": "192.168.1.1", "port": 443}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_tcp.assert_called_once_with("192.168.1.1", 2500, 443)
    
    @patch('memon.check_router_http')
    def test_check_router_http_method(self, mock_http):
        """Test router check with HTTP method."""
        mock_http.return_value = True
        router_check = {"method": "http", "host": "192.168.1.1"}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_http.assert_called_once_with("http://192.168.1.1:80", 2500)
    
    @patch('memon.check_router_http')
    def test_check_router_http_method_with_port(self, mock_http):
        """Test router check with HTTP method and custom port."""
        mock_http.return_value = True
        router_check = {"method": "http", "host": "192.168.1.1", "port": 8080}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_http.assert_called_once_with("http://192.168.1.1:8080", 2500)
    
    @patch('memon.check_router_https')
    def test_check_router_https_method_with_port(self, mock_https):
        """Test router check with HTTPS method and custom port."""
        mock_https.return_value = True
        router_check = {"method": "https", "host": "192.168.1.1", "port": 8443, "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("https://192.168.1.1:8443", False, 2500)
    
    @patch('memon.check_router_https')
    def test_check_router_default_method(self, mock_https):
        """Test router check defaults to HTTPS method."""
        mock_https.return_value = True
        router_check = {"host": "192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("https://192.168.1.1:443", False, 2500)


def _build_dns_response_packet(transaction_id: int, rcode: int, ancount: int, 
                                qname: str, qtype: int, answer_type: int, 
                                answer_data: bytes) -> bytes:
    """
    Build a DNS response packet for testing.
    
    Args:
        transaction_id: Transaction ID
        rcode: Response code (0=NOERROR, 3=NXDOMAIN)
        ancount: Number of answers
        qname: Query name
        qtype: Query type (1=A, 28=AAAA)
        answer_type: Answer type (1=A, 28=AAAA)
        answer_data: Answer data (4 bytes for A, 16 bytes for AAAA)
        
    Returns:
        DNS response packet as bytes
    """
    # Encode domain name
    qname_encoded = b""
    for label in qname.split("."):
        if label:
            qname_encoded += struct.pack("B", len(label)) + label.encode("ascii")
    qname_encoded += b"\x00"
    
    # Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    flags = 0x8180 | rcode  # Response flag + rcode
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, ancount, 0, 0)
    
    # Question section
    question = struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    
    # Answer section (if any)
    answer = b""
    if ancount > 0:
        # NAME (compressed pointer to question section at offset 12)
        answer += struct.pack("!H", 0xC00C)  # Pointer to offset 12
        # TYPE, CLASS, TTL, RDLENGTH
        answer += struct.pack("!HHIH", answer_type, 1, 300, len(answer_data))
        # RDATA
        answer += answer_data
    
    return header + qname_encoded + question + answer


class TestDNSChecks(unittest.TestCase):
    """Test DNS check functionality."""
    
    @patch('socket.socket')
    def test_check_dns_success(self, mock_socket_class):
        """Test successful DNS check using standard library."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Build valid DNS response with A record
        response = _build_dns_response_packet(
            transaction_id=12345,
            rcode=0,  # NOERROR
            ancount=1,
            qname="google.com",
            qtype=1,  # A
            answer_type=1,  # A
            answer_data=struct.pack("!BBBB", 8, 8, 8, 8)  # 8.8.8.8
        )
        mock_socket.recvfrom.return_value = (response, ("8.8.8.8", 53))
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertTrue(success)
        mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_socket.sendto.assert_called_once()
        mock_socket.recvfrom.assert_called_once()
        mock_socket.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_dns_failure(self, mock_socket_class):
        """Test failed DNS check (NXDOMAIN)."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Build DNS response with NXDOMAIN
        response = _build_dns_response_packet(
            transaction_id=12345,
            rcode=3,  # NXDOMAIN
            ancount=0,
            qname="google.com",
            qtype=1,  # A
            answer_type=1,  # A
            answer_data=b""
        )
        mock_socket.recvfrom.return_value = (response, ("8.8.8.8", 53))
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertFalse(success)
    
    @patch('socket.socket')
    def test_check_dns_timeout(self, mock_socket_class):
        """Test DNS check with timeout."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recvfrom.side_effect = socket.timeout()
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertFalse(success)
        mock_socket.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_dns_no_answer(self, mock_socket_class):
        """Test DNS check with no answer."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Build DNS response with no answers (ANCOUNT=0, but NOERROR)
        response = _build_dns_response_packet(
            transaction_id=12345,
            rcode=0,  # NOERROR
            ancount=0,  # No answers
            qname="google.com",
            qtype=1,  # A
            answer_type=1,  # A
            answer_data=b""
        )
        mock_socket.recvfrom.return_value = (response, ("8.8.8.8", 53))
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertFalse(success)
    
    @patch('socket.socket')
    def test_check_dns_aaaa_record(self, mock_socket_class):
        """Test DNS check with AAAA record type."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Build valid DNS response with AAAA record
        response = _build_dns_response_packet(
            transaction_id=12345,
            rcode=0,  # NOERROR
            ancount=1,
            qname="google.com",
            qtype=28,  # AAAA
            answer_type=28,  # AAAA
            answer_data=struct.pack("!HHHHHHHH", 0x2001, 0x4860, 0x4860, 0x0000,
                                   0x0000, 0x0000, 0x0000, 0x8888)  # Sample IPv6
        )
        mock_socket.recvfrom.return_value = (response, ("1.1.1.1", 53))
        
        success, _ = memon.check_dns("1.1.1.1", "google.com", "AAAA", 2500)
        self.assertTrue(success)
    
    @patch('memon.check_dns')
    def test_check_all_dns_all_pass(self, mock_check_dns):
        """Test checking all DNS resolvers when all pass."""
        mock_check_dns.return_value = (True, "")
        dns_checks = [
            {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
            {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
        ]
        
        failed, all_names = memon.check_all_dns(dns_checks, 2500, 10.0)
        self.assertEqual(len(failed), 0)
        self.assertEqual(len(all_names), 2)
    
    @patch('memon.check_dns')
    def test_check_all_dns_all_fail(self, mock_check_dns):
        """Test checking all DNS resolvers when all fail."""
        mock_check_dns.return_value = (False, "")
        dns_checks = [
            {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
            {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
        ]
        
        failed, all_names = memon.check_all_dns(dns_checks, 2500, 10.0)
        self.assertEqual(len(failed), 2)
        self.assertEqual(len(all_names), 2)
    
    @patch('memon.check_dns')
    def test_check_all_dns_partial_failure(self, mock_check_dns):
        """Test checking all DNS resolvers with partial failure."""
        def side_effect(*args):
            # First call succeeds, second fails
            if not hasattr(side_effect, 'call_count'):
                side_effect.call_count = 0
            side_effect.call_count += 1
            return (side_effect.call_count == 1, "")
        
        mock_check_dns.side_effect = side_effect
        dns_checks = [
            {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
            {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
        ]
        
        failed, all_names = memon.check_all_dns(dns_checks, 2500, 10.0)
        self.assertEqual(len(failed), 1)
        self.assertEqual(len(all_names), 2)


class TestStatusClassification(unittest.TestCase):
    """Test status classification functionality."""
    
    def test_classify_router_down(self):
        """Test classification when router is down."""
        status = memon.classify_status(False, [], [])
        self.assertEqual(status, "routerDown")
    
    def test_classify_all_dns_failed(self):
        """Test classification when all DNS resolvers fail."""
        status = memon.classify_status(True, ["DNS1", "DNS2"], ["DNS1", "DNS2"])
        self.assertEqual(status, "ispDown")
    
    def test_classify_some_dns_failed(self):
        """Test classification when some DNS resolvers fail."""
        status = memon.classify_status(True, ["DNS1"], ["DNS1", "DNS2"])
        self.assertEqual(status, "upstreamDnsDown")
    
    def test_classify_all_ok(self):
        """Test classification when all checks pass."""
        status = memon.classify_status(True, [], ["DNS1", "DNS2"])
        self.assertIsNone(status)
    
    def test_classify_no_dns_checks(self):
        """Test classification when no DNS checks are configured."""
        status = memon.classify_status(True, [], [])
        self.assertIsNone(status)


class TestAlertLogic(unittest.TestCase):
    """Test alert firing logic."""
    
    def test_should_fire_down_alert_meets_threshold(self):
        """Test DOWN alert fires when threshold is met."""
        current_time = int(time.time())
        result = memon.should_fire_down_alert(
            fail_streak=3,
            must_fail_count=3,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=900,
            current_time=current_time
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_below_threshold(self):
        """Test DOWN alert doesn't fire when below threshold."""
        current_time = int(time.time())
        result = memon.should_fire_down_alert(
            fail_streak=2,
            must_fail_count=3,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=900,
            current_time=current_time
        )
        self.assertFalse(result)
    
    def test_should_fire_down_alert_already_notified(self):
        """Test DOWN alert doesn't fire if already notified."""
        current_time = int(time.time())
        result = memon.should_fire_down_alert(
            fail_streak=3,
            must_fail_count=3,
            down_notified=True,
            last_alert_ts=0,
            backoff_seconds=900,
            current_time=current_time
        )
        self.assertFalse(result)
    
    def test_should_fire_down_alert_backoff(self):
        """Test DOWN alert doesn't fire during backoff period."""
        current_time = int(time.time())
        recent_alert = current_time - 100  # 100 seconds ago, backoff is 900
        result = memon.should_fire_down_alert(
            fail_streak=3,
            must_fail_count=3,
            down_notified=False,
            last_alert_ts=recent_alert,
            backoff_seconds=900,
            current_time=current_time
        )
        self.assertFalse(result)
    
    def test_should_fire_up_alert_all_ok_and_notified(self):
        """Test UP alert fires when all OK and previously notified."""
        result = memon.should_fire_up_alert(True, True)
        self.assertTrue(result)
    
    def test_should_fire_up_alert_not_notified(self):
        """Test UP alert doesn't fire if not previously notified."""
        result = memon.should_fire_up_alert(True, False)
        self.assertFalse(result)
    
    def test_should_fire_up_alert_not_all_ok(self):
        """Test UP alert doesn't fire if not all OK."""
        result = memon.should_fire_up_alert(False, True)
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_from_isp_down(self):
        """Test partial recovery alert fires when transitioning from ispDown to upstreamDnsDown."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_failed_dns=["DNS1", "DNS2", "DNS3"],
            current_failed_dns=["DNS1", "DNS2"]
        )
        self.assertTrue(result)
    
    def test_should_fire_partial_recovery_alert_not_previously_isp_down(self):
        """Test partial recovery alert doesn't fire if previous status wasn't ispDown and no fewer failures."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="upstreamDnsDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_failed_dns=["DNS1", "DNS2"],
            current_failed_dns=["DNS1", "DNS2"]
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_upstream_to_upstream_fewer_failures(self):
        """Test partial recovery alert fires when transitioning from upstreamDnsDown with more failures to fewer failures."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="upstreamDnsDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_failed_dns=["DNS1", "DNS2", "DNS3"],
            current_failed_dns=["DNS1"]
        )
        self.assertTrue(result)
    
    def test_should_fire_partial_recovery_alert_not_currently_upstream_dns_down(self):
        """Test partial recovery alert doesn't fire if current status isn't upstreamDnsDown."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="routerDown",
            down_notified=True,
            last_failed_dns=["DNS1", "DNS2", "DNS3"],
            current_failed_dns=[]
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_not_down_notified(self):
        """Test partial recovery alert doesn't fire if down alert wasn't previously sent."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=False,
            last_failed_dns=["DNS1", "DNS2", "DNS3"],
            current_failed_dns=["DNS1", "DNS2"]
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_bypasses_backoff(self):
        """Test partial recovery alert fires even during backoff period (backoff bypassed for recovery)."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_failed_dns=["DNS1", "DNS2", "DNS3"],
            current_failed_dns=["DNS1", "DNS2"]
        )
        self.assertTrue(result)
    
    def test_should_fire_partial_recovery_alert_router_down_to_isp_down(self):
        """Test partial recovery alert fires when transitioning from routerDown to ispDown."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="routerDown",
            current_status="ispDown",
            down_notified=True,
            last_failed_dns=[],
            current_failed_dns=["DNS1", "DNS2", "DNS3"]
        )
        self.assertTrue(result)
    
    def test_should_fire_partial_recovery_alert_router_down_to_upstream_dns_down(self):
        """Test partial recovery alert fires when transitioning from routerDown to upstreamDnsDown."""
        result = memon.should_fire_partial_recovery_alert(
            last_status="routerDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_failed_dns=[],
            current_failed_dns=["DNS1", "DNS2"]
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_auto_responder_immediate(self):
        """Test DOWN alert fires immediately after 1 failure with Auto Responder config (mustFailCount: 1)."""
        current_time = int(time.time())
        result = memon.should_fire_down_alert(
            fail_streak=1,
            must_fail_count=1,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=0,
            current_time=current_time
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_auto_responder_no_backoff(self):
        """Test DOWN alert fires with no backoff delay (alertBackoffSeconds: 0)."""
        current_time = int(time.time())
        recent_alert = current_time - 1  # 1 second ago, but backoff is 0
        result = memon.should_fire_down_alert(
            fail_streak=1,
            must_fail_count=1,
            down_notified=False,
            last_alert_ts=recent_alert,
            backoff_seconds=0,
            current_time=current_time
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_auto_responder_zero_backoff_immediate(self):
        """Test that with alertBackoffSeconds: 0, alert fires immediately even if lastAlertTs is recent."""
        current_time = int(time.time())
        very_recent_alert = current_time - 0  # Just now, backoff is 0
        result = memon.should_fire_down_alert(
            fail_streak=1,
            must_fail_count=1,
            down_notified=False,
            last_alert_ts=very_recent_alert,
            backoff_seconds=0,
            current_time=current_time
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_auto_responder_below_threshold(self):
        """Test DOWN alert doesn't fire when below threshold even with Auto Responder config."""
        current_time = int(time.time())
        result = memon.should_fire_down_alert(
            fail_streak=0,
            must_fail_count=1,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=0,
            current_time=current_time
        )
        self.assertFalse(result)


class TestPlaceholderReplacement(unittest.TestCase):
    """Test placeholder replacement in messages."""
    
    def test_replace_placeholders(self):
        """Test replacing {{failed}} placeholder."""
        template = "DNS resolvers failed: {{failed}}"
        failed = ["DNS1", "DNS2"]
        result = memon.replace_placeholders(template, failed)
        self.assertIn("DNS1", result)
        self.assertIn("DNS2", result)
        self.assertNotIn("{{failed}}", result)
    
    def test_replace_placeholders_no_placeholder(self):
        """Test message without placeholder."""
        template = "Router is down"
        result = memon.replace_placeholders(template, [])
        self.assertEqual(result, "Router is down")


class TestMainFunction(unittest.TestCase):
    """Test main function orchestration."""
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('sys.stdout')
    def test_main_no_alert(self, mock_stdout, mock_check_dns, mock_check_router,
                           mock_load_config, mock_load_state, mock_save_state):
        """Test main function when no alert should fire."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 1,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify no output to stdout
        mock_stdout.write.assert_not_called()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_fire_down_alert(self, mock_emit, mock_check_dns, mock_check_router,
                                   mock_load_config, mock_load_state, mock_save_state):
        """Test main function when DOWN alert should fire."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"routerDown": "Router is down"},
            "routerCheck": {},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 2,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = False  # Router down
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify alert was emitted
        mock_emit.assert_called_once()
        # Verify state was saved
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_fire_up_alert(self, mock_emit, mock_check_dns, mock_check_router,
                                 mock_load_config, mock_load_state, mock_save_state):
        """Test main function when UP alert should fire."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"recovery": "Network restored"},
            "routerCheck": {},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": True,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify alert was emitted
        mock_emit.assert_called_once()
        # Verify state was saved
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_fire_partial_recovery_alert(self, mock_emit, mock_check_dns, mock_check_router,
                                               mock_load_config, mock_load_state, mock_save_state):
        """Test main function when partial recovery alert should fire (ispDown → upstreamDnsDown)."""
        current_time = int(time.time())
        old_alert = current_time - 1000  # 1000 seconds ago, backoff is 900
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"upstreamDnsDown": "DNS resolvers failed: {{failed}}"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"},
                {"name": "DNS3", "server": "9.9.9.9", "qname": "quad9.net", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 4,
            "downNotified": True,
            "lastAlertTs": old_alert,
            "lastStatus": "ispDown",
            "lastFailedDns": ["DNS1", "DNS2", "DNS3"]
        }
        mock_check_router.return_value = True
        # 1 DNS recovered, 2 still down
        mock_check_dns.return_value = (["DNS1", "DNS2"], ["DNS1", "DNS2", "DNS3"])
        
        memon.main()
        
        # Verify alert was emitted with upstreamDnsDown message
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("DNS1", call_args)
        self.assertIn("DNS2", call_args)
        # Verify state was saved
        mock_save_state.assert_called_once()
        # Verify lastStatus was updated
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "upstreamDnsDown")
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_partial_recovery_bypasses_backoff(self, mock_emit, mock_check_dns, mock_check_router,
                                                     mock_load_config, mock_load_state, mock_save_state):
        """Test main function fires partial recovery alert even during backoff period (backoff bypassed)."""
        current_time = int(time.time())
        recent_alert = current_time - 100  # 100 seconds ago, backoff is 900
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"upstreamDnsDown": "DNS resolvers failed: {{failed}}"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 4,
            "downNotified": True,
            "lastAlertTs": recent_alert,
            "lastStatus": "ispDown",
            "lastFailedDns": ["DNS1", "DNS2"]
        }
        mock_check_router.return_value = True
        # 1 DNS recovered, 1 still down
        mock_check_dns.return_value = (["DNS1"], ["DNS1", "DNS2"])
        
        memon.main()
        
        # Verify alert was emitted (backoff bypassed for recovery)
        mock_emit.assert_called_once()
        # Verify state was saved
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_partial_recovery_upstream_to_upstream(self, mock_emit, mock_check_dns, mock_check_router,
                                                         mock_load_config, mock_load_state, mock_save_state):
        """Test main function fires partial recovery alert when upstreamDnsDown → upstreamDnsDown with fewer failures."""
        current_time = int(time.time())
        recent_alert = current_time - 100  # 100 seconds ago, backoff is 900
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"upstreamDnsDown": "DNS resolvers failed: {{failed}}"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"},
                {"name": "DNS3", "server": "9.9.9.9", "qname": "quad9.net", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 5,
            "downNotified": True,
            "lastAlertTs": recent_alert,
            "lastStatus": "upstreamDnsDown",
            "lastFailedDns": ["DNS1", "DNS2", "DNS3"]
        }
        mock_check_router.return_value = True
        # 2 DNS recovered, 1 still down
        mock_check_dns.return_value = (["DNS1"], ["DNS1", "DNS2", "DNS3"])
        
        memon.main()
        
        # Verify alert was emitted (partial recovery detected)
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("DNS1", call_args)
        # Verify state was saved with updated lastFailedDns
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastFailedDns"], ["DNS1"])
        self.assertEqual(saved_state["lastStatus"], "upstreamDnsDown")
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_router_down_all_dns_down(self, mock_emit, mock_check_dns, mock_check_router,
                                            mock_load_config, mock_load_state, mock_save_state):
        """Test main function when router is down and all DNS would be down (DNS checks skipped)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"routerDown": "Router is down"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"},
                {"name": "DNS3", "server": "9.9.9.9", "qname": "quad9.net", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 2,
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = False  # Router down
        # DNS checks should not be called when router is down
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify routerDown alert was emitted after mustFailCount
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertEqual(call_args, "Router is down")
        # Verify DNS checks were not called (router down skips DNS)
        mock_check_dns.assert_not_called()
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "routerDown")
        self.assertTrue(saved_state["downNotified"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_router_recovery_all_dns_down(self, mock_emit, mock_check_dns, mock_check_router,
                                                mock_load_config, mock_load_state, mock_save_state):
        """Test main function when router recovers but all DNS are still down."""
        current_time = int(time.time())
        old_alert = current_time - 1000  # 1000 seconds ago, backoff is 900
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"ispDown": "All DNS resolvers failed - ISP may be down"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"},
                {"name": "DNS3", "server": "9.9.9.9", "qname": "quad9.net", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 4,
            "downNotified": True,
            "lastAlertTs": old_alert,
            "lastStatus": "routerDown",
            "lastFailedDns": []
        }
        mock_check_router.return_value = True  # Router recovered
        # All DNS still down
        mock_check_dns.return_value = (["DNS1", "DNS2", "DNS3"], ["DNS1", "DNS2", "DNS3"])
        
        memon.main()
        
        # Verify ispDown alert was emitted (routerDown → ispDown transition)
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertEqual(call_args, "All DNS resolvers failed - ISP may be down")
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "ispDown")
        self.assertEqual(saved_state["lastFailedDns"], ["DNS1", "DNS2", "DNS3"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_router_recovery_partial_dns_recovery(self, mock_emit, mock_check_dns, mock_check_router,
                                                       mock_load_config, mock_load_state, mock_save_state):
        """Test main function when router recovers and some DNS recover (2 of 3 DNS still down)."""
        current_time = int(time.time())
        old_alert = current_time - 1000  # 1000 seconds ago, backoff is 900
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {"upstreamDnsDown": "DNS resolvers failed: {{failed}}"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"},
                {"name": "DNS3", "server": "9.9.9.9", "qname": "quad9.net", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 4,
            "downNotified": True,
            "lastAlertTs": old_alert,
            "lastStatus": "routerDown",
            "lastFailedDns": []
        }
        mock_check_router.return_value = True  # Router recovered
        # 2 of 3 DNS still down (1 recovered)
        mock_check_dns.return_value = (["DNS1", "DNS2"], ["DNS1", "DNS2", "DNS3"])
        
        memon.main()
        
        # Verify upstreamDnsDown alert was emitted (routerDown → upstreamDnsDown transition)
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("DNS1", call_args)
        self.assertIn("DNS2", call_args)
        self.assertNotIn("DNS3", call_args)
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "upstreamDnsDown")
        self.assertEqual(saved_state["lastFailedDns"], ["DNS1", "DNS2"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_auto_responder_fire_immediate_alert(self, mock_emit, mock_check_dns, mock_check_router,
                                                       mock_load_config, mock_load_state, mock_save_state):
        """Test main function fires alert immediately after 1 failure with Auto Responder config (mustFailCount: 1, alertBackoffSeconds: 0)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 1,
            "alertBackoffSeconds": 0,
            "messages": {"routerDown": "Router is down"},
            "routerCheck": {},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = False  # Router down
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify alert was emitted immediately after 1 failure
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertEqual(call_args, "Router is down")
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["failStreak"], 1)
        self.assertTrue(saved_state["downNotified"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_auto_responder_router_down_immediate(self, mock_emit, mock_check_dns, mock_check_router,
                                                        mock_load_config, mock_load_state, mock_save_state):
        """Test router down alert fires immediately with Auto Responder config."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 1,
            "alertBackoffSeconds": 0,
            "messages": {"routerDown": "Router is down"},
            "routerCheck": {},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = False  # Router down
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        
        # Verify alert was emitted
        mock_emit.assert_called_once()
        # Verify state was saved with correct values
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "routerDown")
        self.assertTrue(saved_state["downNotified"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_auto_responder_no_backoff_rapid_fire(self, mock_emit, mock_check_dns, mock_check_router,
                                                       mock_load_config, mock_load_state, mock_save_state):
        """Test that with alertBackoffSeconds: 0, alerts can fire immediately (though downNotified flag still prevents duplicates)."""
        current_time = int(time.time())
        recent_alert = current_time - 1  # 1 second ago, but backoff is 0
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 1,
            "alertBackoffSeconds": 0,
            "messages": {"ispDown": "All DNS resolvers failed - ISP may be down"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": recent_alert
        }
        mock_check_router.return_value = True
        # All DNS fail
        mock_check_dns.return_value = (["DNS1", "DNS2"], ["DNS1", "DNS2"])
        
        memon.main()
        
        # Verify alert was emitted despite recent lastAlertTs (backoff is 0)
        mock_emit.assert_called_once()
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "ispDown")
        self.assertTrue(saved_state["downNotified"])
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    @patch('memon.emit_alert')
    def test_main_auto_responder_dns_failure_immediate(self, mock_emit, mock_check_dns, mock_check_router,
                                                         mock_load_config, mock_load_state, mock_save_state):
        """Test DNS failure alert fires immediately with Auto Responder config."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 1,
            "alertBackoffSeconds": 0,
            "messages": {"upstreamDnsDown": "DNS resolvers failed: {{failed}}"},
            "routerCheck": {},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"},
                {"name": "DNS2", "server": "1.1.1.1", "qname": "cloudflare.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = True
        # 1 DNS fails
        mock_check_dns.return_value = (["DNS1"], ["DNS1", "DNS2"])
        
        memon.main()
        
        # Verify alert was emitted immediately after 1 failure
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("DNS1", call_args)
        # Verify state was saved
        mock_save_state.assert_called_once()
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(saved_state["lastStatus"], "upstreamDnsDown")
        self.assertEqual(saved_state["lastFailedDns"], ["DNS1"])


class TestEmitAlert(unittest.TestCase):
    """Test alert emission functionality."""
    
    @patch('sys.stdout')
    @patch('json.dumps')
    def test_emit_alert(self, mock_dumps, mock_stdout):
        """Test emitting an alert."""
        mock_dumps.return_value = '{"response": "Test message"}'
        memon.emit_alert("Test message")
        mock_dumps.assert_called_once()
        mock_stdout.flush.assert_called_once()
    
    @patch('sys.stdout')
    def test_emit_alert_truncation(self, mock_stdout):
        """Test that long messages are truncated to 200 chars."""
        long_message = "x" * 250
        with patch('json.dumps') as mock_dumps:
            memon.emit_alert(long_message)
            # Verify the message passed to json.dumps is truncated
            call_args = mock_dumps.call_args[0][0]
            self.assertEqual(len(call_args["response"]), 200)




if __name__ == '__main__':
    unittest.main()
