import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cfai.config import Profile, Settings, Store, atomic_json
from cfai.health import History, rank_results, scores
from cfai.scanner import isolated_core, free_port
from cfai.speed import Cancelled


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.requests_seen = 0

    def do_HEAD(self):
        self.requests_seen += 1
        if self.requests_seen == 1:
            time.sleep(.12)
        self.send_response(403 if self.path == '/blocked' else 204)
        self.send_header('Content-Length', '0')
        if self.path == '/close' or self.path == '/close-second' and self.requests_seen == 2:
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()

    def log_message(self, *args):
        pass


class PairedMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures = Path(__file__).parent / 'fixtures'
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(fixtures / 'localhost-cert.pem', fixtures / 'localhost-key.pem')
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.trusted = ssl.create_default_context(cafile=str(fixtures / 'localhost-cert.pem'))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_real_tls_socket_reused_and_per_node_listener_does_not_race_selector(self):
        nodes = [{'name': 'good', 'type': 'direct'},
                 {'name': 'bad', 'type': 'http', 'server': '127.0.0.1', 'port': free_port()}]
        with isolated_core(nodes, None, lambda: False, time.monotonic() + 20) as (api, _):
            api.select('TEST', 'bad')
            url = f'https://localhost:{self.server.server_port}'
            with patch('cfai.latency.ssl.create_default_context', return_value=self.trusted):
                result = api.measure('good', url + '/204', 2000)
                self.assertIsNotNone(result['latency'])
                self.assertGreater(result['first_request'] - result['latency'], 70)
                self.assertEqual(api.request('GET', '/proxies/TEST')['now'], 'bad')
                self.assertIsNone(api.measure('bad', url + '/204', 1000)['first_request'])
                closed = api.measure('good', url + '/close', 2000)
                self.assertIsNotNone(closed['first_request'])
                self.assertIsNone(closed['latency'])
                self.assertIsNotNone(api.measure('good', url + '/close-second', 2000)['latency'])
                self.assertEqual(api.measure('good', url + '/blocked', 2000), {'latency': None, 'first_request': None})
                with self.assertRaises(Cancelled):
                    api.measure('good', url + '/204', 2000, lambda: True)
            # Untrusted certificates must still fail in the real default TLS context.
            self.assertIsNone(api.measure('good', url + '/204', 2000)['first_request'])


class DualScoreTests(unittest.TestCase):
    def test_scan_ranking_is_independent_of_long_live_recovery_and_ages_original_download(self):
        now = time.time()
        rows = [{'ip': '104.16.1.1', 'accepted': True, 'validated_at': now,
                 'samples': [1000]*6, 'latency_samples': [200]*6, 'first_request_samples': [1000]*6,
                 'download': {'mbps': 5, 'at': now - 1000}}]
        s = Settings(); s.recovery_rounds = 20; s.bandwidth_ttl = 300
        result = rank_results(rows, s)[0]
        self.assertIsNotNone(result['score'])
        self.assertFalse(result['bandwidth_used'])

    def test_weights_reverse_preference_and_zero_available_weight_does_not_divide_by_zero(self):
        h = History(); s = Settings()
        for at in [980, 990, 1000]:
            h.record('warm-fast', 100, at, 2000)
            h.record('cold-fast', 400, at, 600)
        s.weight_success = s.weight_jitter = s.weight_bandwidth = 0
        s.weight_latency, s.weight_first_request = 100, 0
        result = scores(h, ['warm-fast', 'cold-fast'], s, 1000)
        self.assertGreater(result['warm-fast']['score'], result['cold-fast']['score'])
        s.weight_latency, s.weight_first_request = 0, 100
        result = scores(h, ['warm-fast', 'cold-fast'], s, 1000)
        self.assertGreater(result['cold-fast']['score'], result['warm-fast']['score'])
        h = History()
        for at in [980, 990, 1000]: h.record('warm-only', 100, at)
        self.assertIsNone(scores(h, ['warm-only'], s, 1000)['warm-only']['score'])
        s.weight_first_request = 0
        with self.assertRaises(ValueError): s.validate()

    def test_missing_cold_metric_removed_uniformly_and_history_restores_both(self):
        h = History(); s = Settings()
        for at in [980, 990, 1000]:
            h.record('a', 200, at, 600)
            h.record('b', 200, at)
        result = scores(History.restore(h.dump()), ['a', 'b'], s, 1000)
        self.assertEqual(result['a']['score'], result['b']['score'])
        self.assertFalse(result['a']['first_request_used'])
        self.assertEqual(result['a']['first_request'], 600)

    def test_store_rescores_dual_results_without_losing_measurements(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d))
            p = Profile('test', 'node.example.org', '11111111-2222-4333-8444-555555555555')
            rows = [{'ip': ip, 'accepted': True, 'validated_at': time.time(), 'samples': [cold]*6,
                     'latency_samples': [warm]*6, 'first_request_samples': [cold]*6}
                    for ip, warm, cold in [('104.16.1.1', 100, 2000), ('104.16.1.2', 400, 600)]]
            store.save_results(p, rows, ['network'])
            before = (store.folder(p.id) / 'results.json').read_bytes()
            p.settings.weight_success = p.settings.weight_jitter = p.settings.weight_bandwidth = 0
            p.settings.weight_latency, p.settings.weight_first_request = 100, 0
            self.assertEqual(store.results(p)[0]['ip'], '104.16.1.1')
            p.settings.weight_latency, p.settings.weight_first_request = 0, 100
            self.assertEqual(store.results(p)[0]['ip'], '104.16.1.2')
            self.assertEqual((store.folder(p.id) / 'results.json').read_bytes(), before)

    def test_legacy_result_is_cold_only_and_never_mislabeled_as_warm(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d))
            p = Profile('test', 'node.example.org', '11111111-2222-4333-8444-555555555555')
            legacy = p.to_dict()['settings']
            for key in ['first_request_reference', 'weight_first_request']: legacy.pop(key)
            key = hashlib.sha256(json.dumps([p.fingerprint(), legacy], sort_keys=True).encode()).hexdigest()
            atomic_json(store.folder(p.id) / 'results.json', {'fingerprint': p.fingerprint(), 'measurement_key': key,
                'rows': [{'ip': '104.16.1.1', 'median': 1100, 'score': 82, 'samples': [1100]*6}]})
            result = store.results(p)[0]
            self.assertEqual(result['first_request'], 1100)
            self.assertIsNone(result['median'])
            self.assertIsNone(result['score'])


if __name__ == '__main__':
    unittest.main()
