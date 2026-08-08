import json
import os
import tempfile
import threading
import unittest
from unittest import mock

import server
import xray


class HostValidationTests(unittest.TestCase):
    def test_accepts_normal_ipv4_and_hostname(self):
        self.assertTrue(server.is_valid_host('1.1.1.1'))
        self.assertTrue(server.is_valid_host('panel.example.com'))

    def test_rejects_malformed_and_whitespace_hosts(self):
        self.assertFalse(server.is_valid_host('999.1.1.1'))
        self.assertFalse(server.is_valid_host('panel example.com'))

    def test_scan_targets_must_be_ip_addresses(self):
        self.assertTrue(server.is_valid_ip('1.1.1.1'))
        self.assertFalse(server.is_valid_ip('panel.example.com'))


class ScanTests(unittest.TestCase):
    def test_non_cloudflare_endpoint_is_not_successful(self):
        probe = {'status': 200, 'cloudflare': False, 'tcp': 1, 'tls': 1, 'ping': 2}
        with mock.patch.object(server, '_probe', return_value=probe):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=1)
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'not a Cloudflare edge')

    def test_scan_deduplicates_ips_at_api_boundary(self):
        self.assertEqual(list(dict.fromkeys(['1.1.1.1', '1.1.1.1'])), ['1.1.1.1'])

    def test_scan_many_refines_only_a_shortlist(self):
        def fake_scan(ip, sni, ports, timeout, passes, deep, cancel_event=None):
            return {'ip': ip, 'success': True, 'score': int(ip.split('.')[-1]),
                    'ping': 10, 'passes_used': passes}

        ips = [f'192.0.2.{i}' for i in range(1, 21)]
        with mock.patch.object(server, 'scan_ip', side_effect=fake_scan) as probe:
            results = server.scan_many(ips, 'example.com', (443,), 1, 3, False, False)
        self.assertEqual(len(results), len(ips))
        self.assertEqual(probe.call_count, 30)  # 20 fast probes + 10 refined probes
        self.assertEqual(max(r['passes_used'] for r in results), 3)

    def test_candidate_with_majority_failed_probes_is_not_healthy(self):
        good = {'status': 200, 'cloudflare': True, 'tcp': 1, 'tls': 1,
                'ping': 2, 'speed': None}
        with mock.patch.object(server, '_probe', side_effect=[good, OSError('down'), OSError('down')]), \
             mock.patch.object(server.time, 'sleep'):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=3)
        self.assertFalse(result['success'])
        self.assertEqual(result['loss'], 67)
        self.assertEqual(result['score'], 0)

    def test_fifty_percent_loss_is_not_healthy(self):
        good = {'status': 200, 'cloudflare': True, 'tcp': 1, 'tls': 1,
                'ping': 2, 'speed': None}
        with mock.patch.object(server, '_probe', side_effect=[good, OSError('down')]), \
             mock.patch.object(server.time, 'sleep'):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=2)
        self.assertFalse(result['success'])
        self.assertEqual(result['loss'], 50)

    def test_cancelled_scan_stops_before_connecting(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(server, '_probe') as probe:
            result = server.scan_ip('1.1.1.1', 'example.com', cancel_event=cancelled)
        probe.assert_not_called()
        self.assertEqual(result['error'], 'cancelled')


class XrayConfigTests(unittest.TestCase):

    def test_rejects_empty_vmess_payload(self):
        with self.assertRaisesRegex(ValueError, 'invalid server address'):
            xray.parse_link('vmess://e30=')

    def test_rejects_unsupported_transport(self):
        with self.assertRaisesRegex(ValueError, 'unsupported transport'):
            xray.parse_link('vless://uuid@example.com:443?type=madeup&security=tls')
    def test_vless_link_and_ip_substitution(self):
        spec = xray.parse_link('vless://uuid@example.com:443?security=tls&sni=panel.example.com')
        cfg = xray.build_config(spec, '1.1.1.1', 21081, 443)
        outbound = cfg['outbounds'][0]
        self.assertEqual(outbound['settings']['vnext'][0]['address'], '1.1.1.1')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], 'panel.example.com')

    def test_tunnel_cleans_up_when_startup_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = os.path.join(temp, 'xray')
            with open(fake, 'w', encoding='utf-8') as fh:
                fh.write('#!/bin/sh\nexit 1\n')
            os.chmod(fake, 0o755)
            spec = xray.parse_link('trojan://password@example.com:443?security=tls')
            tunnel = xray.XrayTunnel(fake, spec, '1.1.1.1', 21999)
            with self.assertRaises(RuntimeError):
                tunnel.__enter__()
            self.assertIsNone(tunnel._cfg_path)


if __name__ == '__main__':
    unittest.main()
