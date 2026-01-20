#!/usr/bin/env python3
"""
Test suite for memon.py using Python unittest.
"""

import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
import json
import sys
import time
import subprocess
import urllib.error
import ssl
import shutil

# Import the module under test
import memon


class TestConfigLoading(unittest.TestCase):
    """Test configuration loading functionality."""
    
    def test_load_config_defaults(self):
        """Test loading config with defaults when file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            config = memon.load_config("nonexistent.json")
            self.assertEqual(config["timeoutMs"], 2500)
            self.assertEqual(config["mustFailCount"], 3)
            self.assertIn("routerCheck", config)
            self.assertIn("dnsChecks", config)
    
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
    
    @patch('subprocess.run')
    def test_check_router_ping_success(self, mock_run):
        """Test successful ping router check."""
        mock_run.return_value = Mock(returncode=0)
        
        result = memon.check_router_ping("192.168.1.1", 1, 2500)
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_check_router_ping_failure(self, mock_run):
        """Test failed ping router check."""
        mock_run.return_value = Mock(returncode=1)
        
        result = memon.check_router_ping("192.168.1.1", 1, 2500)
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_check_router_ping_timeout(self, mock_run):
        """Test ping router check with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("ping", 1)
        
        result = memon.check_router_ping("192.168.1.1", 1, 2500)
        self.assertFalse(result)
    
    @patch('memon.check_router_https')
    def test_check_router_https_type(self, mock_https):
        """Test router check with HTTPS type."""
        mock_https.return_value = True
        router_check = {"type": "https", "host": "https://192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once()
    
    @patch('memon.check_router_ping')
    def test_check_router_ping_type(self, mock_ping):
        """Test router check with PING type."""
        mock_ping.return_value = True
        router_check = {"type": "ping", "host": "192.168.1.1", "pingCount": 1}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_ping.assert_called_once()
    
    @patch('memon.check_router_https')
    def test_check_router_https_host_without_protocol(self, mock_https):
        """Test HTTPS router check with host that doesn't have protocol (should prepend https://)."""
        mock_https.return_value = True
        router_check = {"type": "https", "host": "192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("https://192.168.1.1", False, 2500)
    
    @patch('memon.check_router_https')
    def test_check_router_https_host_with_https_protocol(self, mock_https):
        """Test HTTPS router check with host that has https:// protocol."""
        mock_https.return_value = True
        router_check = {"type": "https", "host": "https://192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("https://192.168.1.1", False, 2500)
    
    @patch('memon.check_router_https')
    def test_check_router_https_host_with_http_protocol(self, mock_https):
        """Test HTTPS router check with host that has http:// protocol."""
        mock_https.return_value = True
        router_check = {"type": "https", "host": "http://192.168.1.1", "insecureTls": False}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_https.assert_called_once_with("http://192.168.1.1", False, 2500)
    
    @patch('memon.check_router_ping')
    def test_check_router_ping_host_with_protocol(self, mock_ping):
        """Test PING router check with host that has protocol prefix (should strip it)."""
        mock_ping.return_value = True
        router_check = {"type": "ping", "host": "https://192.168.1.1", "pingCount": 1}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_ping.assert_called_once_with("192.168.1.1", 1, 2500)
    
    @patch('memon.check_router_ping')
    def test_check_router_ping_host_with_http_protocol(self, mock_ping):
        """Test PING router check with host that has http:// protocol prefix (should strip it)."""
        mock_ping.return_value = True
        router_check = {"type": "ping", "host": "http://192.168.1.1", "pingCount": 1}
        
        result = memon.check_router(router_check, 2500)
        self.assertTrue(result)
        mock_ping.assert_called_once_with("192.168.1.1", 1, 2500)


class TestDNSChecks(unittest.TestCase):
    """Test DNS check functionality."""
    
    @patch('subprocess.run')
    def test_check_dns_success_dig(self, mock_run):
        """Test successful DNS check using dig."""
        mock_run.return_value = Mock(returncode=0, stdout="8.8.8.8\n", stderr="")
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertTrue(success)
    
    @patch('subprocess.run')
    def test_check_dns_failure(self, mock_run):
        """Test failed DNS check."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertFalse(success)
    
    @patch('subprocess.run')
    def test_check_dns_timeout(self, mock_run):
        """Test DNS check with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("dig", 1)
        
        success, _ = memon.check_dns("8.8.8.8", "google.com", "A", 2500)
        self.assertFalse(success)
    
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
        result = memon.should_fire_down_alert(
            fail_streak=3,
            must_fail_count=3,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=900
        )
        self.assertTrue(result)
    
    def test_should_fire_down_alert_below_threshold(self):
        """Test DOWN alert doesn't fire when below threshold."""
        result = memon.should_fire_down_alert(
            fail_streak=2,
            must_fail_count=3,
            down_notified=False,
            last_alert_ts=0,
            backoff_seconds=900
        )
        self.assertFalse(result)
    
    def test_should_fire_down_alert_already_notified(self):
        """Test DOWN alert doesn't fire if already notified."""
        result = memon.should_fire_down_alert(
            fail_streak=3,
            must_fail_count=3,
            down_notified=True,
            last_alert_ts=0,
            backoff_seconds=900
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
            backoff_seconds=900
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
        current_time = int(time.time())
        old_alert = current_time - 1000  # 1000 seconds ago, backoff is 900
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_alert_ts=old_alert,
            backoff_seconds=900
        )
        self.assertTrue(result)
    
    def test_should_fire_partial_recovery_alert_not_previously_isp_down(self):
        """Test partial recovery alert doesn't fire if previous status wasn't ispDown."""
        current_time = int(time.time())
        old_alert = current_time - 1000
        result = memon.should_fire_partial_recovery_alert(
            last_status="upstreamDnsDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_alert_ts=old_alert,
            backoff_seconds=900
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_not_currently_upstream_dns_down(self):
        """Test partial recovery alert doesn't fire if current status isn't upstreamDnsDown."""
        current_time = int(time.time())
        old_alert = current_time - 1000
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="routerDown",
            down_notified=True,
            last_alert_ts=old_alert,
            backoff_seconds=900
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_not_down_notified(self):
        """Test partial recovery alert doesn't fire if down alert wasn't previously sent."""
        current_time = int(time.time())
        old_alert = current_time - 1000
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=False,
            last_alert_ts=old_alert,
            backoff_seconds=900
        )
        self.assertFalse(result)
    
    def test_should_fire_partial_recovery_alert_backoff(self):
        """Test partial recovery alert doesn't fire during backoff period."""
        current_time = int(time.time())
        recent_alert = current_time - 100  # 100 seconds ago, backoff is 900
        result = memon.should_fire_partial_recovery_alert(
            last_status="ispDown",
            current_status="upstreamDnsDown",
            down_notified=True,
            last_alert_ts=recent_alert,
            backoff_seconds=900
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
            "lastStatus": "ispDown"
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
    def test_main_no_partial_recovery_during_backoff(self, mock_emit, mock_check_dns, mock_check_router,
                                                      mock_load_config, mock_load_state, mock_save_state):
        """Test main function doesn't fire partial recovery alert during backoff period."""
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
            "lastStatus": "ispDown"
        }
        mock_check_router.return_value = True
        # 1 DNS recovered, 1 still down
        mock_check_dns.return_value = (["DNS1"], ["DNS1", "DNS2"])
        
        memon.main()
        
        # Verify no alert was emitted (backoff period)
        mock_emit.assert_not_called()
        # Verify state was still saved
        mock_save_state.assert_called_once()


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


class TestCommandAvailability(unittest.TestCase):
    """Test command availability checking functionality."""
    
    @patch('shutil.which')
    def test_check_command_available_true(self, mock_which):
        """Test check_command_available returns True when command exists."""
        mock_which.return_value = "/usr/bin/ping"
        result = memon.check_command_available("ping")
        self.assertTrue(result)
        mock_which.assert_called_once_with("ping")
    
    @patch('shutil.which')
    def test_check_command_available_false(self, mock_which):
        """Test check_command_available returns False when command doesn't exist."""
        mock_which.return_value = None
        result = memon.check_command_available("nonexistent")
        self.assertFalse(result)
        mock_which.assert_called_once_with("nonexistent")
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('sys.exit')
    def test_main_fails_when_ping_missing(self, mock_exit, mock_check_cmd, mock_load_config,
                                          mock_load_state, mock_save_state):
        """Test main() fails early when ping is missing but routerCheck.type='ping'."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "ping", "host": "192.168.1.1"},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        # ping not available
        def check_side_effect(cmd):
            return cmd != "ping"
        mock_check_cmd.side_effect = check_side_effect
        
        memon.main()
        mock_exit.assert_called_once_with(1)
        mock_save_state.assert_not_called()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('sys.exit')
    def test_main_fails_when_dns_commands_missing(self, mock_exit, mock_check_cmd, mock_load_config,
                                                   mock_load_state, mock_save_state):
        """Test main() fails early when dig/nslookup missing but dnsChecks configured."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "https", "host": "https://192.168.1.1"},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        # Neither dig nor nslookup available
        mock_check_cmd.return_value = False
        
        memon.main()
        mock_exit.assert_called_once_with(1)
        mock_save_state.assert_not_called()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    def test_main_continues_when_commands_available(self, mock_check_dns, mock_check_router,
                                                     mock_check_cmd, mock_load_config,
                                                     mock_load_state, mock_save_state):
        """Test main() continues normally when commands are available."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "ping", "host": "192.168.1.1"},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        # All commands available
        mock_check_cmd.return_value = True
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], ["DNS1"])
        
        memon.main()
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    def test_main_continues_when_commands_not_needed(self, mock_check_dns, mock_check_router,
                                                     mock_check_cmd, mock_load_config,
                                                     mock_load_state, mock_save_state):
        """Test main() continues normally when commands not needed (HTTPS router, no DNS)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "https", "host": "https://192.168.1.1"},
            "dnsChecks": []
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], [])
        
        memon.main()
        # check_command_available should not be called since no commands are needed
        mock_check_cmd.assert_not_called()
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    def test_main_continues_when_dig_available(self, mock_check_dns, mock_check_router,
                                               mock_check_cmd, mock_load_config,
                                               mock_load_state, mock_save_state):
        """Test main() continues when dig is available (nslookup not needed)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "https", "host": "https://192.168.1.1"},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        # dig available, nslookup not needed
        def check_side_effect(cmd):
            return cmd == "dig"
        mock_check_cmd.side_effect = check_side_effect
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], ["DNS1"])
        
        memon.main()
        mock_save_state.assert_called_once()
    
    @patch('memon.save_state')
    @patch('memon.load_state')
    @patch('memon.load_config')
    @patch('memon.check_command_available')
    @patch('memon.check_router')
    @patch('memon.check_all_dns')
    def test_main_continues_when_nslookup_available(self, mock_check_dns, mock_check_router,
                                                    mock_check_cmd, mock_load_config,
                                                    mock_load_state, mock_save_state):
        """Test main() continues when nslookup is available (dig not needed)."""
        mock_load_config.return_value = {
            "timeoutMs": 2500,
            "mustFailCount": 3,
            "alertBackoffSeconds": 900,
            "messages": {},
            "routerCheck": {"type": "https", "host": "https://192.168.1.1"},
            "dnsChecks": [
                {"name": "DNS1", "server": "8.8.8.8", "qname": "google.com", "rrtype": "A"}
            ]
        }
        mock_load_state.return_value = {
            "failStreak": 0,
            "downNotified": False,
            "lastAlertTs": 0
        }
        # nslookup available, dig not needed
        def check_side_effect(cmd):
            return cmd == "nslookup"
        mock_check_cmd.side_effect = check_side_effect
        mock_check_router.return_value = True
        mock_check_dns.return_value = ([], ["DNS1"])
        
        memon.main()
        mock_save_state.assert_called_once()


if __name__ == '__main__':
    unittest.main()
