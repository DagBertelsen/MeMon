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




class TestModeDetection(unittest.TestCase):
    """Test execution mode detection."""

    @patch.dict('os.environ', {'MESSAGE': 'status check'})
    def test_auto_responder_detected_with_MESSAGE_env(self):
        """Test Auto Responder detection with MESSAGE env var."""
        mode = memon.detect_execution_mode()
        self.assertEqual(mode, "auto_responder")

    @patch.dict('os.environ', {'TRIGGER': 'netcheck'})
    def test_auto_responder_detected_with_TRIGGER_env(self):
        """Test Auto Responder detection with TRIGGER env var."""
        mode = memon.detect_execution_mode()
        self.assertEqual(mode, "auto_responder")

    @patch.dict('os.environ', {'MESSAGE': 'test', 'TRIGGER': 'test'})
    def test_auto_responder_detected_with_both_env_vars(self):
        """Test Auto Responder detection with both env vars present."""
        mode = memon.detect_execution_mode()
        self.assertEqual(mode, "auto_responder")

    @patch.dict('os.environ', {}, clear=True)
    def test_timer_trigger_detected_without_env_vars(self):
        """Test Timer Trigger detection without env vars."""
        mode = memon.detect_execution_mode()
        self.assertEqual(mode, "timer_trigger")


class TestStatusReportFormatting(unittest.TestCase):
    """Test status report formatting for Auto Responder mode."""

    def test_router_down_format(self):
        """Test Router DOWN message format."""
        message = memon.format_status_report(False, [], [], [])
        self.assertEqual(message, "Router DOWN")

    def test_router_ok_no_dns(self):
        """Test Router OK with no DNS checks configured."""
        message = memon.format_status_report(True, [], [], [])
        self.assertEqual(message, "Router OK")

    def test_router_ok_all_dns_fail(self):
        """Test Router OK but all DNS checks failing."""
        dns_checks = [
            {"name": "Google DNS", "server": "8.8.8.8"},
            {"name": "Cloudflare DNS", "server": "1.1.1.1"}
        ]
        failed = ["Google DNS", "Cloudflare DNS"]
        all_dns = ["Google DNS", "Cloudflare DNS"]
        message = memon.format_status_report(True, failed, all_dns, dns_checks)
        self.assertEqual(message, "Router OK, All DNS FAIL")

    def test_router_ok_mixed_dns(self):
        """Test Router OK with some DNS checks failing."""
        dns_checks = [
            {"name": "Google DNS", "server": "8.8.8.8"},
            {"name": "Cloudflare DNS", "server": "1.1.1.1"}
        ]
        failed = ["Cloudflare DNS"]
        all_dns = ["Google DNS", "Cloudflare DNS"]
        message = memon.format_status_report(True, failed, all_dns, dns_checks)
        self.assertEqual(message, "Router OK, DNS: Google DNS OK, Cloudflare DNS FAIL")

    def test_truncation_to_count_format(self):
        """Test truncation to count format when message exceeds 200 chars."""
        # Create 20 DNS checks with long names to exceed 200 chars
        dns_checks = [
            {"name": f"Very Long DNS Server Name Number {i}", "server": "1.1.1.1"}
            for i in range(20)
        ]
        failed = [f"Very Long DNS Server Name Number {i}" for i in range(10)]
        all_dns = [f"Very Long DNS Server Name Number {i}" for i in range(20)]
        message = memon.format_status_report(True, failed, all_dns, dns_checks)
        # Should use count format
        self.assertEqual(message, "Router OK, 10 of 20 DNS FAIL")
        self.assertLessEqual(len(message), 200)

    def test_fallback_dns_names(self):
        """Test fallback DNS names when names not configured."""
        # DNS checks without names - should use fallback DNS-0, DNS-1
        dns_checks = [
            {"server": "8.8.8.8"},
            {"server": "1.1.1.1"}
        ]
        failed = ["DNS-1"]
        all_dns = ["DNS-0", "DNS-1"]
        message = memon.format_status_report(True, failed, all_dns, dns_checks)
        self.assertEqual(message, "Router OK, DNS: DNS-0 OK, DNS-1 FAIL")


class TestAutoResponderMode(unittest.TestCase):
    """Test Auto Responder mode integration."""

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_always_emits(self, mock_load_config, mock_check_router,
                                         mock_check_dns, mock_emit,
                                         mock_load_state, mock_save_state):
        """Auto Responder always emits status, never calls state functions."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [{"name": "Google", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}],
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], ["Google"])

        memon.main()

        # Should emit alert
        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("Router OK", call_args)

        # Should NOT call state functions
        mock_load_state.assert_not_called()
        mock_save_state.assert_not_called()

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_router_down(self, mock_load_config, mock_check_router,
                                        mock_check_dns, mock_emit):
        """Auto Responder reports router down."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_check_router.return_value = False

        memon.main()

        mock_emit.assert_called_once_with("Router DOWN")
        # DNS checks should be skipped when router is down
        mock_check_dns.assert_not_called()

    @patch.dict('os.environ', {'MESSAGE': 'status', 'TRIGGER': 'netcheck'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_all_dns_fail(self, mock_load_config, mock_check_router,
                                         mock_check_dns, mock_emit):
        """Auto Responder reports all DNS failed."""
        dns_checks = [
            {"name": "Google DNS", "server": "8.8.8.8"},
            {"name": "Cloudflare DNS", "server": "1.1.1.1"}
        ]
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": dns_checks,
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = (["Google DNS", "Cloudflare DNS"], ["Google DNS", "Cloudflare DNS"])

        memon.main()

        mock_emit.assert_called_once_with("Router OK, All DNS FAIL")

    @patch.dict('os.environ', {'MESSAGE': 'status', 'TRIGGER': 'test'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_partial_dns_fail(self, mock_load_config, mock_check_router,
                                             mock_check_dns, mock_emit):
        """Auto Responder reports partial DNS failure."""
        dns_checks = [
            {"name": "Google DNS", "server": "8.8.8.8"},
            {"name": "Cloudflare DNS", "server": "1.1.1.1"}
        ]
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": dns_checks,
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = (["Cloudflare DNS"], ["Google DNS", "Cloudflare DNS"])

        memon.main()

        mock_emit.assert_called_once()
        call_args = mock_emit.call_args[0][0]
        self.assertIn("Google DNS OK", call_args)
        self.assertIn("Cloudflare DNS FAIL", call_args)

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_no_dns_checks(self, mock_load_config, mock_check_router,
                                          mock_check_dns, mock_emit):
        """Auto Responder with no DNS checks configured."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])

        memon.main()

        mock_emit.assert_called_once_with("Router OK")

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_with_debug_mode(self, mock_load_config, mock_check_router,
                                            mock_check_dns, mock_emit):
        """Auto Responder works with debug mode enabled."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "debug": True,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])

        memon.main()

        # Should still emit even in debug mode
        mock_emit.assert_called_once()

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_respects_message_length(self, mock_load_config, mock_check_router,
                                                     mock_check_dns, mock_emit):
        """Auto Responder respects 200-char message limit."""
        # Create many DNS checks
        dns_checks = [{"name": f"DNS Server {i}", "server": "1.1.1.1"} for i in range(50)]
        all_dns_names = [f"DNS Server {i}" for i in range(50)]
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": dns_checks,
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], all_dns_names)

        memon.main()

        mock_emit.assert_called_once()
        message = mock_emit.call_args[0][0]
        self.assertLessEqual(len(message), 200)


class TestParseAutoResponderCommand(unittest.TestCase):
    """Test Auto Responder command parsing."""

    def test_empty_message_returns_help(self):
        """Empty message returns help."""
        self.assertEqual(memon.parse_auto_responder_command(""), "help")

    def test_whitespace_only_returns_help(self):
        """Whitespace-only message returns help."""
        self.assertEqual(memon.parse_auto_responder_command("   "), "help")

    def test_none_returns_help(self):
        """None message returns help (defensive)."""
        self.assertEqual(memon.parse_auto_responder_command(None), "help")

    def test_unrecognized_keyword_returns_help(self):
        """Unrecognized keyword returns help."""
        self.assertEqual(memon.parse_auto_responder_command("netcheck"), "help")

    def test_status_keyword(self):
        """'status' keyword returns status."""
        self.assertEqual(memon.parse_auto_responder_command("status"), "status")

    def test_all_keyword(self):
        """'all' keyword returns status."""
        self.assertEqual(memon.parse_auto_responder_command("all"), "status")

    def test_router_keyword(self):
        """'router' keyword returns router."""
        self.assertEqual(memon.parse_auto_responder_command("router"), "router")

    def test_dns_keyword(self):
        """'dns' keyword returns dns."""
        self.assertEqual(memon.parse_auto_responder_command("dns"), "dns")

    def test_case_insensitive(self):
        """Keywords are case-insensitive."""
        self.assertEqual(memon.parse_auto_responder_command("STATUS"), "status")
        self.assertEqual(memon.parse_auto_responder_command("Router"), "router")
        self.assertEqual(memon.parse_auto_responder_command("DNS"), "dns")

    def test_keyword_in_sentence(self):
        """Keywords found inside a longer message."""
        self.assertEqual(memon.parse_auto_responder_command("check the router please"), "router")
        self.assertEqual(memon.parse_auto_responder_command("show me dns results"), "dns")

    def test_status_takes_priority_over_dns(self):
        """'status' or 'all' takes priority when multiple keywords present."""
        self.assertEqual(memon.parse_auto_responder_command("check all dns"), "status")
        self.assertEqual(memon.parse_auto_responder_command("status router dns"), "status")


class TestFormatRouterReport(unittest.TestCase):
    """Test router-only report formatting."""

    def test_router_ok(self):
        self.assertEqual(memon.format_router_report(True), "Router OK")

    def test_router_down(self):
        self.assertEqual(memon.format_router_report(False), "Router DOWN")


class TestFormatDnsReport(unittest.TestCase):
    """Test DNS-only report formatting."""

    def test_router_down(self):
        """Router down means DNS unknown."""
        result = memon.format_dns_report(False, [], [], [])
        self.assertEqual(result, "DNS: Unknown (router down)")

    def test_no_checks_configured(self):
        """No DNS checks configured."""
        result = memon.format_dns_report(True, [], [], [])
        self.assertEqual(result, "DNS: No checks configured")

    def test_all_ok(self):
        """All DNS checks pass."""
        dns_checks = [{"name": "Google", "server": "8.8.8.8"}]
        result = memon.format_dns_report(True, [], ["Google"], dns_checks)
        self.assertEqual(result, "DNS: All OK")

    def test_all_fail(self):
        """All DNS checks fail."""
        dns_checks = [{"name": "Google", "server": "8.8.8.8"}]
        result = memon.format_dns_report(True, ["Google"], ["Google"], dns_checks)
        self.assertEqual(result, "DNS: All FAIL")

    def test_mixed_status(self):
        """Mixed DNS results show individual statuses."""
        dns_checks = [
            {"name": "Google", "server": "8.8.8.8"},
            {"name": "Cloudflare", "server": "1.1.1.1"}
        ]
        result = memon.format_dns_report(True, ["Cloudflare"], ["Google", "Cloudflare"], dns_checks)
        self.assertIn("Google OK", result)
        self.assertIn("Cloudflare FAIL", result)

    def test_respects_message_length(self):
        """DNS report respects 200-char limit."""
        dns_checks = [{"name": f"DNS-Server-{i}", "server": f"10.0.0.{i}"} for i in range(30)]
        all_dns = [f"DNS-Server-{i}" for i in range(30)]
        failed = all_dns[:15]
        result = memon.format_dns_report(True, failed, all_dns, dns_checks)
        self.assertLessEqual(len(result), 200)


class TestFormatHelpMessage(unittest.TestCase):
    """Test help message formatting."""

    def test_contains_commands(self):
        """Help message lists all commands."""
        msg = memon.format_help_message()
        self.assertIn("status", msg)
        self.assertIn("router", msg)
        self.assertIn("dns", msg)
        self.assertIn("version", msg)

    def test_fits_message_length(self):
        """Help message fits within 200-char limit."""
        self.assertLessEqual(len(memon.format_help_message()), 200)


class TestVersion(unittest.TestCase):
    """Test version information."""

    def test_version_exists(self):
        """Script has a __version__ attribute."""
        self.assertTrue(hasattr(memon, '__version__'))

    def test_version_format(self):
        """Version follows semantic versioning format (X.Y.Z)."""
        self.assertRegex(memon.__version__, r'^\d+\.\d+\.\d+$')

    def test_version_command_recognized(self):
        """'version' keyword is recognized as a command."""
        self.assertEqual(memon.parse_auto_responder_command("version"), "version")

    def test_version_command_case_insensitive(self):
        """'VERSION' keyword is recognized case-insensitively."""
        self.assertEqual(memon.parse_auto_responder_command("VERSION"), "version")

    @patch.dict('os.environ', {'MESSAGE': 'version', 'TRIGGER': 'netcheck'})
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_version_command_emits_version(self, mock_emit, mock_load_config, mock_check_router):
        """Version command emits version string without network checks."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }

        memon.main()

        mock_emit.assert_called_once()
        message = mock_emit.call_args[0][0]
        self.assertIn("MeMon v", message)
        self.assertIn(memon.__version__, message)
        mock_check_router.assert_not_called()


class TestAutoResponderCommandDispatch(unittest.TestCase):
    """Test Auto Responder command dispatch in main()."""

    @patch.dict('os.environ', {'MESSAGE': 'netcheck', 'TRIGGER': 'netcheck'})
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_no_args_shows_help(self, mock_emit, mock_load_config, mock_check_router):
        """No recognized command shows help guide."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }

        memon.main()

        mock_emit.assert_called_once()
        message = mock_emit.call_args[0][0]
        self.assertIn("status", message)
        self.assertIn("router", message)
        self.assertIn("dns", message)
        # Should not have run network checks
        mock_check_router.assert_not_called()

    @patch.dict('os.environ', {'MESSAGE': 'router', 'TRIGGER': 'netcheck'})
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_router_command(self, mock_emit, mock_load_config, mock_check_router, mock_check_dns):
        """Router command returns router-only report."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [{"name": "DNS1", "server": "8.8.8.8"}],
            "messages": {}
        }
        mock_check_router.return_value = True

        memon.main()

        mock_emit.assert_called_once_with("Router OK")
        mock_check_dns.assert_not_called()

    @patch.dict('os.environ', {'MESSAGE': 'dns', 'TRIGGER': 'netcheck'})
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_dns_command(self, mock_emit, mock_load_config, mock_check_router, mock_check_dns):
        """DNS command returns DNS-only report."""
        dns_checks = [
            {"name": "Google", "server": "8.8.8.8"},
            {"name": "Cloudflare", "server": "1.1.1.1"}
        ]
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": dns_checks,
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = (["Cloudflare"], ["Google", "Cloudflare"])

        memon.main()

        mock_emit.assert_called_once()
        message = mock_emit.call_args[0][0]
        self.assertIn("DNS:", message)
        self.assertIn("Google OK", message)
        self.assertIn("Cloudflare FAIL", message)

    @patch.dict('os.environ', {'MESSAGE': 'dns', 'TRIGGER': 'netcheck'})
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_dns_command_router_down(self, mock_emit, mock_load_config, mock_check_router):
        """DNS command when router is down."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [{"name": "DNS1", "server": "8.8.8.8"}],
            "messages": {}
        }
        mock_check_router.return_value = False

        memon.main()

        mock_emit.assert_called_once_with("DNS: Unknown (router down)")

    @patch.dict('os.environ', {'MESSAGE': 'show status', 'TRIGGER': 'netcheck'})
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    @patch('memon.emit_alert')
    def test_status_command(self, mock_emit, mock_load_config, mock_check_router, mock_check_dns):
        """Status command returns full report."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "routerCheck": {},
            "dnsChecks": [{"name": "Google", "server": "8.8.8.8"}],
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], ["Google"])

        memon.main()

        mock_emit.assert_called_once_with("Router OK, DNS: Google OK")


class TestTimerTriggerModeUnchanged(unittest.TestCase):
    """Verify Timer Trigger mode behavior remains unchanged."""

    @patch.dict('os.environ', {}, clear=True)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_respects_must_fail_count(self, mock_load_config,
                                                     mock_check_router, mock_emit,
                                                     mock_load_state, mock_save_state):
        """Timer Trigger only alerts after mustFailCount failures."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 0,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {"routerDown": "Router down"}
        }
        mock_load_state.return_value = {
            "failStreak": 1,  # After this run becomes 2, still below 3
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = False

        memon.main()

        # Should not emit (only 2 failures total, need 3)
        mock_emit.assert_not_called()
        # Should save updated state
        mock_save_state.assert_called_once()

    @patch.dict('os.environ', {}, clear=True)
    @patch('time.time', return_value=1000)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_respects_backoff(self, mock_load_config, mock_check_router,
                                            mock_emit, mock_load_state, mock_save_state,
                                            mock_time):
        """Timer Trigger respects backoff period."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 1,
            "alertBackoffSeconds": 900,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {"routerDown": "Router down"}
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 500,  # 500 seconds ago (backoff is 900)
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = False

        memon.main()

        # Should not emit (backoff period not elapsed)
        mock_emit.assert_not_called()
        mock_save_state.assert_called_once()

    @patch.dict('os.environ', {}, clear=True)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_loads_and_saves_state(self, mock_load_config, mock_check_router,
                                                  mock_emit, mock_load_state, mock_save_state):
        """Timer Trigger loads and saves state file."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 0,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = True

        memon.main()

        # Should load and save state
        mock_load_state.assert_called_once()
        mock_save_state.assert_called_once()

    @patch.dict('os.environ', {}, clear=True)
    @patch('time.time', return_value=2000)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_recovery_alert(self, mock_load_config, mock_check_router,
                                          mock_emit, mock_load_state, mock_save_state,
                                          mock_time):
        """Timer Trigger fires recovery alert when network recovers."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {"recovery": "Network restored"}
        }
        mock_load_state.return_value = {
            "failStreak": 3,
            "downNotified": True,
            "lastAlertTs": 1000,
            "lastStatus": "routerDown",
            "lastFailedDns": []
        }
        mock_check_router.return_value = True

        memon.main()

        # Should emit recovery alert
        mock_emit.assert_called_once_with("Network restored")
        mock_save_state.assert_called_once()

    @patch.dict('os.environ', {}, clear=True)
    @patch('time.time', return_value=2000)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_partial_recovery_alert(self, mock_load_config, mock_check_router,
                                                   mock_check_dns, mock_emit, mock_load_state,
                                                   mock_save_state, mock_time):
        """Timer Trigger fires partial recovery alert."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "routerCheck": {},
            "dnsChecks": [{"name": "DNS1", "server": "8.8.8.8"}],
            "messages": {"ispDown": "All DNS failed"}
        }
        mock_load_state.return_value = {
            "failStreak": 3,
            "downNotified": True,
            "lastAlertTs": 1000,
            "lastStatus": "routerDown",
            "lastFailedDns": []
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = (["DNS1"], ["DNS1"])

        memon.main()

        # Should emit partial recovery alert (router recovered but DNS failed)
        mock_emit.assert_called_once()
        mock_save_state.assert_called_once()

    @patch.dict('os.environ', {}, clear=True)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_ignores_args(self, mock_load_config, mock_check_router,
                                        mock_emit, mock_load_state, mock_save_state):
        """Timer Trigger mode ignores command args (no command parsing)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 0,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = True

        memon.main()

        # Should behave normally: load state, check router, save state
        mock_load_state.assert_called_once()
        mock_save_state.assert_called_once()
        # Should NOT emit help guide
        mock_emit.assert_not_called()


class TestDebugOutput(unittest.TestCase):
    """Test debug logging output goes to stderr and respects debug flag."""

    def test_debug_log_writes_to_stderr(self):
        """_debug_log writes to stderr when debug=True."""
        import io
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon._debug_log("Test", "hello world", True)
        output = buf.getvalue()
        self.assertIn("[Test] hello world", output)

    def test_debug_log_silent_when_disabled(self):
        """_debug_log produces no output when debug=False."""
        import io
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon._debug_log("Test", "should not appear", False)
        self.assertEqual(buf.getvalue(), "")

    @patch('memon.check_router_https')
    def test_router_success_debug(self, mock_https):
        """Router check logs OK to stderr when debug=True and check passes."""
        import io
        mock_https.return_value = True
        router_check = {"method": "https", "host": "192.168.1.1", "insecureTls": False}
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_router(router_check, 2500, debug=True)
        output = buf.getvalue()
        self.assertIn("[Router] OK:", output)
        self.assertIn("192.168.1.1", output)

    @patch('memon.check_router_https')
    def test_router_failure_debug(self, mock_https):
        """Router check logs FAIL to stderr when debug=True and check fails."""
        import io
        mock_https.return_value = False
        router_check = {"method": "https", "host": "192.168.1.1", "insecureTls": False}
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_router(router_check, 2500, debug=True)
        output = buf.getvalue()
        self.assertIn("[Router] FAIL:", output)

    @patch('memon.check_router_https')
    def test_router_no_debug_output_when_disabled(self, mock_https):
        """Router check produces no stderr when debug=False."""
        import io
        mock_https.return_value = False
        router_check = {"method": "https", "host": "192.168.1.1", "insecureTls": False}
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_router(router_check, 2500, debug=False)
        self.assertEqual(buf.getvalue(), "")

    @patch('memon.check_dns')
    def test_dns_success_debug(self, mock_check_dns):
        """DNS check logs OK to stderr when debug=True and check passes."""
        import io
        mock_check_dns.return_value = (True, "")
        dns_checks = [{"name": "Google", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}]
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_all_dns(dns_checks, 2500, 5.0, debug=True)
        output = buf.getvalue()
        self.assertIn("[DNS] OK:", output)
        self.assertIn("Google", output)

    @patch('memon.check_dns')
    def test_dns_failure_debug(self, mock_check_dns):
        """DNS check logs FAIL to stderr when debug=True and check fails."""
        import io
        mock_check_dns.return_value = (False, "SERVFAIL")
        dns_checks = [{"name": "Google", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}]
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_all_dns(dns_checks, 2500, 5.0, debug=True)
        output = buf.getvalue()
        self.assertIn("[DNS] FAIL:", output)
        self.assertIn("SERVFAIL", output)

    @patch('memon.check_dns')
    def test_dns_no_debug_output_when_disabled(self, mock_check_dns):
        """DNS check produces no stderr when debug=False."""
        import io
        mock_check_dns.return_value = (False, "SERVFAIL")
        dns_checks = [{"name": "Google", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}]
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.check_all_dns(dns_checks, 2500, 5.0, debug=False)
        self.assertEqual(buf.getvalue(), "")

    def test_load_state_debug_output(self):
        """load_state logs state values to stderr when debug=True."""
        import io
        test_state = {"failStreak": 2, "downNotified": True, "lastAlertTs": 100}
        buf = io.StringIO()
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=json.dumps(test_state))):
                with patch('sys.stderr', buf):
                    memon.load_state("test.json", debug=True)
        output = buf.getvalue()
        self.assertIn("[State] Loaded:", output)
        self.assertIn("failStreak=2", output)

    def test_load_state_no_debug_when_disabled(self):
        """load_state produces no stderr when debug=False."""
        import io
        buf = io.StringIO()
        with patch('os.path.exists', return_value=False):
            with patch('sys.stderr', buf):
                memon.load_state("test.json", debug=False)
        self.assertEqual(buf.getvalue(), "")

    def test_save_state_debug_output(self):
        """save_state logs confirmation to stderr when debug=True."""
        import io
        test_state = {"failStreak": 3, "downNotified": True, "lastAlertTs": 100}
        buf = io.StringIO()
        with patch('builtins.open', mock_open()):
            with patch('sys.stderr', buf):
                memon.save_state(test_state, "test.json", debug=True)
        output = buf.getvalue()
        self.assertIn("[State] Saved:", output)

    @patch.dict('os.environ', {}, clear=True)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.emit_alert')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_timer_trigger_alert_decision_debug(self, mock_load_config, mock_check_router,
                                                 mock_emit, mock_load_state, mock_save_state):
        """Timer Trigger mode logs alert decision to stderr when debug=True."""
        import io
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "debug": True,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = True
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.main()
        output = buf.getvalue()
        self.assertIn("[Alert]", output)
        self.assertIn("fire_down=", output)

    @patch.dict('os.environ', {'MESSAGE': 'status'})
    @patch('memon.emit_alert')
    @patch('memon.check_all_dns')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_auto_responder_mode_debug(self, mock_load_config, mock_check_router,
                                        mock_check_dns, mock_emit):
        """Auto Responder mode logs mode and config to stderr when debug=True."""
        import io
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "debug": True,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.main()
        output = buf.getvalue()
        self.assertIn("[Mode] auto_responder", output)
        self.assertIn("[Config]", output)

    @patch.dict('os.environ', {}, clear=True)
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.check_router')
    @patch('memon.load_config')
    def test_no_debug_output_when_disabled(self, mock_load_config, mock_check_router,
                                            mock_load_state, mock_save_state):
        """No debug output on stderr when debug=False (Timer Trigger mode)."""
        import io
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "debug": False,
            "routerCheck": {},
            "dnsChecks": [],
            "messages": {}
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0,
            "lastStatus": None,
            "lastFailedDns": []
        }
        mock_check_router.return_value = True
        buf = io.StringIO()
        with patch('sys.stderr', buf):
            memon.main()
        self.assertEqual(buf.getvalue(), "")


class TestBuildDnsStatusList(unittest.TestCase):
    """Test the _build_dns_status_list helper."""

    def test_all_ok(self):
        """All DNS checks OK returns correct list."""
        dns_checks = [
            {"name": "Google", "server": "8.8.8.8"},
            {"name": "Cloudflare", "server": "1.1.1.1"}
        ]
        result = memon._build_dns_status_list(dns_checks, [])
        self.assertEqual(result, ["Google OK", "Cloudflare OK"])

    def test_all_fail(self):
        """All DNS checks failed returns correct list."""
        dns_checks = [
            {"name": "Google", "server": "8.8.8.8"},
            {"name": "Cloudflare", "server": "1.1.1.1"}
        ]
        result = memon._build_dns_status_list(dns_checks, ["Google", "Cloudflare"])
        self.assertEqual(result, ["Google FAIL", "Cloudflare FAIL"])

    def test_mixed_status(self):
        """Mixed DNS status returns correct list."""
        dns_checks = [
            {"name": "Google", "server": "8.8.8.8"},
            {"name": "Cloudflare", "server": "1.1.1.1"},
            {"name": "Quad9", "server": "9.9.9.9"}
        ]
        result = memon._build_dns_status_list(dns_checks, ["Cloudflare"])
        self.assertEqual(result, ["Google OK", "Cloudflare FAIL", "Quad9 OK"])

    def test_empty_checks(self):
        """Empty DNS checks returns empty list."""
        result = memon._build_dns_status_list([], [])
        self.assertEqual(result, [])

    def test_fallback_name(self):
        """DNS check without name uses fallback DNS-N."""
        dns_checks = [{"server": "8.8.8.8"}]
        result = memon._build_dns_status_list(dns_checks, [])
        self.assertEqual(result, ["DNS-0 OK"])


class TestCheckRouterHttpRequest(unittest.TestCase):
    """Test the _check_router_http_request helper."""

    @patch('urllib.request.urlopen')
    def test_http_request_success(self, mock_urlopen):
        """HTTP request succeeds with 200 response."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = memon._check_router_http_request("http://192.168.1.1", 2500)
        self.assertTrue(result)

    @patch('urllib.request.urlopen')
    def test_https_request_with_ssl_context(self, mock_urlopen):
        """HTTPS request passes SSL context through."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        ssl_context = ssl.create_default_context()

        result = memon._check_router_http_request("https://192.168.1.1", 2500, ssl_context)
        self.assertTrue(result)
        call_kwargs = mock_urlopen.call_args[1]
        self.assertIn('context', call_kwargs)

    @patch('urllib.request.urlopen')
    def test_http_no_ssl_context(self, mock_urlopen):
        """HTTP request without SSL context does not pass context."""
        mock_response = Mock()
        mock_response.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        memon._check_router_http_request("http://192.168.1.1", 2500)
        call_kwargs = mock_urlopen.call_args[1]
        self.assertNotIn('context', call_kwargs)

    @patch('urllib.request.urlopen')
    def test_connection_failure(self, mock_urlopen):
        """Connection failure returns False."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = memon._check_router_http_request("http://192.168.1.1", 2500)
        self.assertFalse(result)

    @patch('urllib.request.urlopen')
    def test_unexpected_exception(self, mock_urlopen):
        """Unexpected exception returns False (catch-all safety)."""
        mock_urlopen.side_effect = RuntimeError("unexpected")
        result = memon._check_router_http_request("http://192.168.1.1", 2500)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
