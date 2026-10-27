from contextlib import nullcontext
import copy
import ipaddress
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cfai.clash import ControllerError
from cfai.config import Profile, Store
from cfai.discovery import PrefixLearning
from cfai.scanner import Scanner, shortlist
from cfai.speed import Cancelled


RANGES = [ipaddress.ip_network('104.16.0.0/13'), ipaddress.ip_network('172.64.0.0/13')]


class DiscoveryScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name))
        self.p = Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')
        self.p.settings.sample_count = 64
        self.p.settings.validation_candidates = 12
        self.p.settings.validation_interval = 0
        self.network = SimpleNamespace(identity=('physical-network',), verify=lambda *a: None,
                                       connect=lambda *a, **kw: nullcontext())
        self.cancelled = False
        self.events = []
        self.path = self.store.folder(self.p.id) / 'discovery.json'

    def measure(self, name, *args):
        good = name.startswith('CF-104.')
        return {'latency': 100 if good else None, 'first_request': 600 if good else None}

    def run_scan(self, measure=None, discover=None, event=None, seeds=None):
        api = SimpleNamespace(measure=measure or self.measure)
        with patch('cfai.scanner.DirectNetwork.discover', side_effect=discover or [self.network, self.network]), \
             patch('cfai.scanner.API.discover', side_effect=ControllerError()), \
             patch('cfai.scanner.load_ranges', return_value=(RANGES, 'fixture')), \
             patch('cfai.scanner.isolated_core', return_value=nullcontext((api, 0))):
            return Scanner(self.store, self.p, event or (lambda *a: self.events.append(a))).run(
                lambda: self.cancelled, False, seeds)

    def evidence(self):
        doc = json.loads(self.path.read_text(encoding='utf-8'))
        return {key: value['evidence'] for key, value in doc['contexts'].items()}

    def prime(self):
        self.run_scan()
        return copy.deepcopy(self.evidence())

    def test_completed_scan_learns_and_next_batch_uses_successful_range_without_expanding_budget(self):
        first, _ = self.run_scan()
        self.assertTrue(self.path.exists())
        second, _ = self.run_scan()
        first_coverage, coverage = first[0]['scan_coverage'], second[0]['scan_coverage']
        self.assertEqual(first_coverage['preferred'], 0)
        self.assertGreater(coverage['preferred'], 0)
        self.assertEqual(coverage['sampled'], 64)
        self.assertGreaterEqual(coverage['exploration'], 20)
        self.assertGreaterEqual(coverage['validation_exploration'], 4)
        self.assertGreater(coverage['prefixes']['104.16.0.0/13']['sampled'], 44)
        self.assertEqual(sum(r['validated'] for r in coverage['prefixes'].values()), 12)
        self.assertEqual(len(second), 12)

    def test_validation_exploration_survives_fast_history_candidates_and_zero_old_exploration_share(self):
        self.p.settings.latency_share = .5
        self.p.settings.history_share = .5
        old = [{'ip': f'104.16.1.{i}', 'median_ms': i} for i in range(1, 21)]
        fresh = [{'ip': f'172.64.1.{i}', 'median_ms': 200} for i in range(1, 11)]
        history = [dict(r, accepted=True, score=90) for r in old]
        chosen = shortlist(old + fresh, 12, self.p.settings, history, exploration=fresh)
        self.assertEqual(len(chosen), 12)
        self.assertGreaterEqual(sum(r['ip'].startswith('172.') for r in chosen), 4)

    def test_cancel_after_partial_validation_preserves_preference_evidence(self):
        before = self.prime()
        def event(kind, value):
            if kind == 'scan' and '第 1/3' in value:
                self.cancelled = True
        with self.assertRaises(Cancelled):
            self.run_scan(event=event)
        self.assertEqual(self.evidence(), before)

    def test_network_change_after_validation_does_not_teach_or_publish_results(self):
        before = self.prime()
        results_path = self.store.folder(self.p.id) / 'results.json'
        saved = results_path.read_bytes()
        changed = SimpleNamespace(identity=('other-network',))
        with self.assertRaisesRegex(ValueError, '变化'):
            self.run_scan(discover=[self.network, changed])
        self.assertEqual(self.evidence(), before)
        self.assertEqual(results_path.read_bytes(), saved)

    def test_core_failure_and_final_physical_verify_failure_do_not_teach(self):
        before = self.prime()
        def fail(*a):
            raise ControllerError('fixture')
        with self.assertRaises(ControllerError):
            self.run_scan(measure=fail)
        self.assertEqual(self.evidence(), before)
        calls = []
        def verify(*a):
            calls.append(a)
            if len(calls) == 2:
                raise OSError('fixture')
        self.network.verify = verify
        with self.assertRaises(OSError):
            self.run_scan()
        self.assertEqual(self.evidence(), before)

    def test_cancellation_during_final_verify_does_not_teach(self):
        before = self.prime()
        calls = []
        def verify(*a):
            calls.append(a)
            if len(calls) == 2:
                self.cancelled = True
        self.network.verify = verify
        with self.assertRaises(Cancelled):
            self.run_scan()
        self.assertEqual(self.evidence(), before)

    def test_next_network_starts_balanced_and_does_not_import_old_result_seeds(self):
        self.prime()
        self.network.identity = ('new-network',)
        rows, _ = self.run_scan()
        coverage = rows[0]['scan_coverage']
        self.assertEqual(coverage['preferred'], 0)
        self.assertEqual(coverage['reused'], 0)
        self.assertEqual(coverage['exploration'], 64)


if __name__ == '__main__':
    unittest.main()
