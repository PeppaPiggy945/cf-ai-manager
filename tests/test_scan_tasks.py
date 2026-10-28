from contextlib import nullcontext
import ipaddress
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cfai.config import Profile, Store
from cfai.clash import ControllerError
from cfai.scanner import RANGES, Scanner, parse_ranges, sample, shortlist
from cfai.service import Service
from cfai.speed import Cancelled


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name))
        self.p = Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')
        self.store.save_profiles([self.p])
        self.events = []
        self.service = Service(self.store, lambda *a: self.events.append(a))
        self.addCleanup(self.service.handler.close)

    def finish(self):
        self.service.scan_thread.join(timeout=2)
        self.assertFalse(self.service.scan_thread.is_alive())
        self.assertTrue(self.service.scanning)  # ownership includes pending publication
        self.assertNotIn('scan_idle', [k for k, _ in self.events])
        action, args = self.service.commands.get(timeout=1)
        self.assertEqual(action, 'task_complete')
        self.service.command(action, *args)
        self.assertFalse(self.service.scanning)
        self.assertEqual(self.events[-1], ('scan_idle', self.p.id))

    def test_completion_is_published_only_after_worker_cleanup_and_releases_slot(self):
        rows = [{'ip': '104.16.1.1', 'accepted': False}]
        def run(scanner, *args):
            scanner.event('scan_done', {'rows': rows, 'bytes': 0})
            self.assertNotIn('scan_done', [k for k, _ in self.events])
            return rows, ['fixture']
        with patch.object(Scanner, 'run', run), patch('cfai.service.DirectNetwork.discover', return_value=SimpleNamespace(identity=['fixture'])):
            self.service.start_scan(self.p)
            self.finish()
        self.assertEqual([k for k, _ in self.events][-3:], ['results', 'scan_done', 'scan_idle'])
        self.assertTrue(self.service.submit('scan', self.p.id, False))

    def test_schedule_write_failure_still_releases_task_and_reports_error(self):
        with patch.object(Scanner, 'run', side_effect=Cancelled()), patch('cfai.service.atomic_json', side_effect=OSError('fixture')):
            self.service.start_scan(self.p)
            self.finish()
        self.assertIn('error', [k for k, _ in self.events])

    def test_completed_scan_reports_publication_failure_without_losing_completion(self):
        rows = [{'ip': '104.16.1.1', 'accepted': True}]
        def run(scanner, *args):
            scanner.event('scan_done', {'rows': rows, 'bytes': 0})
            return rows, ['fixture']
        with patch.object(Scanner, 'run', run), \
             patch('cfai.service.DirectNetwork.discover', return_value=SimpleNamespace(identity=['fixture'])), \
             patch.object(self.service, 'publish_discovery', side_effect=ControllerError('fixture')):
            self.service.start_scan(self.p)
            self.finish()
        summary = next(value for kind, value in self.events if kind == 'scan_done')
        self.assertEqual(summary['rows'], rows)
        self.assertIn('未同步', summary['publication'])
        self.assertIn('results', [kind for kind, _ in self.events])

    def test_cancel_and_scanner_exception_both_release_slot(self):
        for error in [Cancelled(), ValueError('fixture')]:
            with self.subTest(error=type(error).__name__), patch.object(Scanner, 'run', side_effect=error):
                self.events.clear()
                self.service.start_scan(self.p)
                self.finish()

    def test_queued_and_running_duplicate_requests_are_coalesced(self):
        self.service.submit('scan', self.p.id, True)
        self.service.submit('scan', self.p.id, True)
        self.service.submit('stream', self.p.id)
        self.assertEqual(self.service.commands.qsize(), 1)
        self.service.scan_thread = Mock()
        self.assertFalse(self.service.submit('scan', self.p.id, True))

    def test_cancel_reaches_worker_without_command_dispatch(self):
        self.service.submit('cancel')
        self.assertTrue(self.service.scan_cancel.is_set())

    def test_pending_command_interrupts_health_confirmation_without_scoring_it(self):
        def measure(*args):
            self.service.submit('scan', self.p.id, False)
            return {'latency': None, 'first_request': None}
        api = SimpleNamespace(measure=measure)
        with self.assertRaises(Cancelled):
            self.service.probe(api, self.p, 'fixture')

    def test_command_arriving_during_fallback_does_not_become_a_health_failure(self):
        self.p.settings.confirmation_seconds = 0
        calls = []
        def measure(*args):
            calls.append(args)
            if len(calls) == 2:
                self.service.submit('cancel')
            return {'latency': None, 'first_request': None}
        with self.assertRaises(Cancelled):
            self.service.probe(SimpleNamespace(measure=measure), self.p, 'fixture')
        self.assertEqual(len(calls), 2)

    def test_manager_drains_commands_before_any_monitoring(self):
        seen = []
        def command(action, *args):
            seen.append(action)
            if len(seen) == 3:
                self.service.stop()
        self.service.command = command
        self.service.monitor = Mock(side_effect=AssertionError('monitor overtook queued command'))
        for _ in range(3):
            self.service.submit('fixture')
        self.service.run()
        self.assertEqual(seen, ['fixture'] * 3)
        self.service.monitor.assert_not_called()

    def test_failed_worker_start_releases_reservation(self):
        with patch('cfai.service.threading.Thread.start', side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError):
                self.service.command('scan', self.p.id, False)
        self.assertFalse(self.service.scanning)
        self.assertFalse(self.service.task_requested)
        self.assertEqual(self.events[-1], ('scan_idle', self.p.id))


class CoverageTests(unittest.TestCase):
    def test_pool_size_balanced_batches_and_continuation_do_not_repeat(self):
        ranges = parse_ranges(' '.join(RANGES))
        self.assertEqual(sum(n.num_addresses for n in ranges), 1524736)
        first, cursor = sample(ranges, set(), 0, 256)
        second, _ = sample(ranges, set(first), cursor, 256)
        self.assertEqual(len(set(first)), 256)
        self.assertEqual(len(set(second)), 256)
        self.assertFalse(set(first) & set(second))
        self.assertTrue(all(any(ipaddress.ip_address(ip) in n for n in ranges) for ip in first + second))
        self.assertTrue(all(sum(ipaddress.ip_address(ip) in n for ip in first) >= 15 for n in ranges))
        offsets = [int(ipaddress.ip_address(ip)) - int(n.network_address) for n in ranges for ip in first if ipaddress.ip_address(ip) in n][:15]
        self.assertGreater(len(set(offsets)), 1)

    def test_exploration_adds_unrepresented_ranges_after_fastest_selection(self):
        from cfai.config import Settings
        rows = [{'ip': f'104.16.1.{i}', 'median_ms': i} for i in range(1, 20)]
        rows += [{'ip': str(ipaddress.ip_network(n).network_address + 37), 'median_ms': 200} for n in RANGES[:6]]
        chosen = shortlist(rows, 12, Settings(), [])
        self.assertEqual(len(chosen), 12)
        self.assertEqual(len({r['ip'] for r in chosen}), 12)
        self.assertGreaterEqual(sum(not r['ip'].startswith('104.16.') for r in chosen), 6)

    def test_all_failed_validation_keeps_failure_evidence_and_progress(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d))
            p = Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')
            p.settings.sample_count = 16
            p.settings.validation_candidates = 2
            p.settings.validation_interval = 0
            network = SimpleNamespace(identity=('fixture',), verify=Mock(), connect=lambda *a, **kw: nullcontext())
            api = SimpleNamespace(measure=lambda *a: {'latency': None, 'first_request': None, 'error': 'HTTP 403'})
            events = []
            with patch('cfai.scanner.DirectNetwork.discover', return_value=network), \
                 patch('cfai.scanner.API.discover', side_effect=ControllerError()), \
                 patch('cfai.scanner.load_ranges', return_value=(parse_ranges(' '.join(RANGES)), 'fixture')), \
                 patch('cfai.scanner.isolated_core', return_value=nullcontext((api, 0))):
                rows, _ = Scanner(store, p, lambda *a: events.append(a)).run(lambda: False)
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(not r['accepted'] and r['probe_errors'] == ['HTTP 403'] * 6 for r in rows))
            self.assertEqual(rows[0]['scan_coverage']['sampled'], 16)
            self.assertEqual(rows[0]['scan_coverage']['validated'], 2)
            self.assertTrue(any(k == 'scan' and '第 3/3' in v for k, v in events))


if __name__ == '__main__':
    unittest.main()
