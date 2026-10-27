from dataclasses import asdict
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from cfai.clash import API, ControllerError
from cfai.config import Profile, ROUTING_FIELDS, Settings, Store, atomic_json
from cfai.export import dynamic_config, static_config
from cfai.scanner import check_config, core_path, FLAGS, free_port
from cfai.service import context_key


def profile():
    return Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')


class RoutingTests(unittest.TestCase):
    def test_both_exports_validate_offline_with_embedded_v4_v6_and_provider_only_stays_minimal(self):
        p = profile()
        rows = [{'ip': '104.16.1.1'}]
        with tempfile.TemporaryDirectory() as d:
            provider = Path(d) / 'nodes.yaml'
            atomic_json(provider, {'proxies': [p.node(rows[0]['ip'])]})
            full = static_config(p, rows)
            dynamic = dynamic_config(p, provider)
            for cfg in (full, dynamic):
                check_config(cfg)  # Empty disposable HOME, with no GeoIP database or network subscription.
                self.assertNotIn('GEOIP', ','.join(cfg['rules']))
                payload = cfg['rule-providers']['CFAI-CN']['payload']
                self.assertTrue(any(':' in cidr for cidr in payload))
                self.assertTrue(any(ipaddress.ip_address('223.5.5.5') in ipaddress.ip_network(cidr)
                                    for cidr in payload if ':' not in cidr))
                self.assertIn('MIT License', cfg['cfai-routing-info']['license'])
            normalized = [x.replace(p.outer, 'AI') for x in dynamic['rules']]
            self.assertEqual(full['rules'], normalized)
            self.assertEqual(set(static_config(p, rows, provider_only=True)), {'proxies'})

    def test_switches_exceptions_and_invalid_rule_input(self):
        p = profile()
        p.settings.direct_china = False
        p.settings.direct_stun = False
        p.settings.reject_foreign_quic = False
        p.settings.extra_direct_domains = ['game.example.org']
        p.settings.extra_direct_processes = ['国服 game.exe']
        cfg = static_config(p, [{'ip': '104.16.1.1'}])
        check_config(cfg)
        self.assertNotIn('rule-providers', cfg)
        self.assertIn('DOMAIN-SUFFIX,game.example.org,DIRECT', cfg['rules'])
        self.assertIn('PROCESS-NAME,国服 game.exe,DIRECT', cfg['rules'])
        self.assertFalse(any('3478' in r or 'REJECT' in r for r in cfg['rules']))
        for key, value in [('extra_direct_domains', ['https://example.com']),
                           ('extra_direct_domains', ['foo.com,AI']),
                           ('extra_direct_processes', ['game.exe,AI']), ('direct_china', 1)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                Settings.from_dict({key: value})

    def test_routing_changes_preserve_preupgrade_measurements_and_live_context(self):
        p = profile()
        old_settings = {k: v for k, v in asdict(p.settings).items() if k not in ROUTING_FIELDS}
        from cfai.config import SCORING_FIELDS
        old_key = hashlib.sha256(json.dumps([2, p.fingerprint(),
            {k: v for k, v in old_settings.items() if k not in SCORING_FIELDS}], sort_keys=True).encode()).hexdigest()
        old_context = hashlib.sha256(json.dumps([2, p.fingerprint(), old_settings, ['network']], sort_keys=True).encode()).hexdigest()
        self.assertEqual(context_key(p, ['network']), old_context)
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d))
            atomic_json(store.folder(p.id) / 'results.json', {'fingerprint': p.fingerprint(),
                'measurement_key': old_key, 'rows': [{'ip': '104.16.1.1'}]})
            p.settings.extra_direct_domains = ['game.example.org']
            p.settings.reject_foreign_quic = False
            self.assertEqual(p.measurement_key(), old_key)
            self.assertEqual(context_key(p, ['network']), old_context)
            self.assertEqual(len(store.results(p)), 1)

    def test_real_mihomo_routes_tcp_udp_and_resolved_unknown_game_without_external_dial(self):
        p = profile()
        p.settings.extra_direct_domains = ['custom-game.example']
        with tempfile.TemporaryDirectory(prefix='cfai-routing-') as d:
            root = Path(d)
            cfg = static_config(p, [{'ip': '104.16.1.1'}])
            port, controller = free_port(), free_port()
            while port == controller:
                controller = free_port()
            # Nonexistent interface forces all direct dials to fail locally, after real rule
            # selection. No packet can leave through a physical interface or production Clash.
            cfg.update({'mixed-port': port, 'external-controller': f'127.0.0.1:{controller}',
                        'secret': 'fixture', 'log-level': 'debug', 'interface-name': 'cfai-nonexistent-interface',
                        'find-process-mode': 'off', 'ipv6': True,
                        'dns': {'enable': True, 'listen': '127.0.0.1:0', 'ipv6': True,
                                'nameserver': ['udp://127.0.0.1:9'], 'use-hosts': True},
                        'hosts': {'unknown-game.example': '223.5.5.5', 'game.qq.com': '104.16.1.1',
                                  'chatgpt.com': '223.5.5.5', 'custom-game.example': '104.16.1.1',
                                  'foreign.example': '104.16.1.1'}})
            # Proxy marker rejects locally; its chain name still proves AI selection.
            cfg['proxies'] = []
            cfg['proxy-groups'][0]['proxies'] = ['REJECT']
            atomic_json(root / 'config.json', cfg)
            with (root / 'core.log').open('wb') as output:
                process = subprocess.Popen([str(core_path()), '-d', d, '-f', str(root / 'config.json')],
                    stdout=output, stderr=output, creationflags=FLAGS)
                try:
                    api = API(f'http://127.0.0.1:{controller}', 'fixture')
                    for _ in range(60):
                        try:
                            api.request('GET', '/version', timeout=.3)
                            break
                        except ControllerError:
                            time.sleep(.1)
                    else:
                        self.fail('Routing fixture core did not start')
                    def tcp(host):
                        with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                            authority = f'[{host}]:443' if ':' in host else f'{host}:443'
                            sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
                            sock.recv(4096)
                            sock.sendall(b'fixture')
                            try:
                                sock.recv(4096)
                            except TimeoutError:
                                pass
                    def udp(host, target_port):
                        with socket.create_connection(('127.0.0.1', port), timeout=2) as control:
                            control.sendall(b'\x05\x01\x00')
                            self.assertEqual(control.recv(2), b'\x05\x00')
                            control.sendall(b'\x05\x03\x00\x01' + b'\x00'*6)
                            response = control.recv(64)
                            self.assertEqual(response[:2], b'\x05\x00')
                            bind_port = struct.unpack('!H', response[-2:])[0]
                            name = host.encode()
                            packet = b'\x00\x00\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', target_port) + b'fixture'
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                                sock.sendto(packet, ('127.0.0.1', bind_port))
                                time.sleep(.12)
                    for host in ('game.qq.com', 'unknown-game.example', '223.5.5.5', '2400:3200::1',
                                 'chatgpt.com', 'custom-game.example', 'foreign.example'):
                        tcp(host)
                    for host, target_port in [('game.qq.com', 443), ('223.5.5.5', 443),
                                              ('104.16.1.1', 443), ('104.16.1.1', 3478), ('chatgpt.com', 443)]:
                        udp(host, target_port)
                    time.sleep(.2)
                finally:
                    process.terminate()
                    process.wait(timeout=5)
            log = (root / 'core.log').read_text(encoding='utf-8', errors='replace')
            expected = [('TCP', 'game.qq.com:443', 'DIRECT'), ('TCP', 'unknown-game.example:443', 'DIRECT'),
                        ('TCP', '223.5.5.5:443', 'DIRECT'), ('TCP', '[2400:3200::1]:443', 'DIRECT'),
                        ('TCP', 'chatgpt.com:443', 'AI'), ('TCP', 'custom-game.example:443', 'DIRECT'),
                        ('TCP', 'foreign.example:443', 'AI'), ('UDP', 'game.qq.com:443', 'DIRECT'),
                        ('UDP', '223.5.5.5:443', 'DIRECT'), ('UDP', '104.16.1.1:443', 'REJECT'),
                        ('UDP', '104.16.1.1:3478', 'DIRECT'), ('UDP', 'chatgpt.com:443', 'REJECT')]
            for protocol, target, route in expected:
                with self.subTest(protocol=protocol, target=target):
                    lines = [line for line in log.splitlines() if f'[{protocol}]' in line and target in line]
                    self.assertTrue(any(f'dial {route} ' in line or f'using {route}' in line for line in lines), '\n'.join(lines) or log)


if __name__ == '__main__':
    unittest.main()
