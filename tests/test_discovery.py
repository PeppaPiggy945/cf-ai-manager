import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from cfai.config import Profile
from cfai.discovery import PrefixLearning


NOW = 1_800_000_000
RANGES = [ipaddress.ip_network(n) for n in ('104.16.0.0/13', '172.64.0.0/13', '103.21.244.0/22')]


def measured(ip, good=True, warm=100, cold=600):
    return {'ip': ip, 'accepted': good, 'first_request_samples': [cold if good else None] * 6,
            'latency_samples': [warm if good else None] * 6}


class LearningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'discovery.json'
        self.p = Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')
        self.network = ('fixture-guid', 4, '192.168.1.10', '192.168.1.1')

    def learning(self, network=None, now=NOW):
        return PrefixLearning(self.path, self.p, network or self.network, now=now)

    def test_successful_tunnels_get_more_new_addresses_with_exploration_reserved(self):
        model = self.learning()
        model.record([measured('104.16.1.1'), measured('172.64.1.1', False)], RANGES)
        ips, coverage = model.plan(RANGES, set(), [], 256)
        counts = [sum(ipaddress.ip_address(ip) in n for ip in ips) for n in RANGES]
        self.assertGreater(counts[0], 200)
        self.assertGreaterEqual(counts[1], 25)
        self.assertGreaterEqual(counts[2], 25)
        self.assertEqual(len(set(ips)), 256)
        self.assertEqual(coverage['preferred'], 179)
        self.assertEqual(coverage['exploration'], 77)

    def test_cold_start_and_failures_only_explore_even_when_tcp_was_fast(self):
        model = self.learning()
        model.record([measured('104.16.1.1', False)], RANGES)
        ips, coverage = model.plan(RANGES, set(), [], 256)
        counts = [sum(ipaddress.ip_address(ip) in n for ip in ips) for n in RANGES]
        self.assertLessEqual(max(counts) - min(counts), 1)
        self.assertEqual(coverage['preferred'], 0)
        self.assertEqual(coverage['exploration'], 256)

    def test_seed_flood_cannot_displace_fresh_exploration(self):
        seeds = [f'104.16.1.{i}' for i in range(1, 41)]
        ips, coverage = self.learning().plan(RANGES, set(seeds), seeds, 16)
        self.assertEqual(len(ips), 16)
        self.assertEqual(coverage['reused'], 11)
        self.assertGreaterEqual(len(set(ips) - set(seeds)), 5)
        self.assertEqual(coverage['exploration'], 5)
        self.assertEqual(sum(r['sampled'] for r in coverage['prefixes'].values()), 16)

    def test_overflow_seeds_are_known_addresses_even_without_recent_network_exclusions(self):
        seeds, _ = self.learning().plan(RANGES, set(), [], 16)
        ips, coverage = self.learning(network=('new-network',)).plan(RANGES, set(), seeds, 16)
        self.assertEqual(coverage['reused'], 11)
        self.assertEqual(coverage['exploration'], 5)
        self.assertGreaterEqual(len(set(ips) - set(seeds)), 5)
        self.assertFalse(set(coverage['exploration_ips']) & set(seeds))

    def test_persistence_continues_sampling_without_duplicates_and_does_not_store_secrets(self):
        model = self.learning()
        model.record([measured('104.16.1.1')], RANGES)
        first, _ = model.plan(RANGES, set(), [], 256)
        model.save()
        restored = self.learning()
        second, _ = restored.plan(RANGES, set(first), [], 256)
        self.assertFalse(set(first) & set(second))
        self.assertGreater(restored.scores(RANGES)['104.16.0.0/13']['score'], .5)
        raw = self.path.read_text(encoding='utf-8')
        self.assertNotIn(self.p.credential, raw)
        self.assertNotIn(self.p.domain, raw)
        self.assertNotIn('gstatic', raw)
        self.assertNotIn('192.168', raw)

    def test_network_template_endpoint_and_timeout_contexts_do_not_share_learning(self):
        model = self.learning()
        model.record([measured('104.16.1.1')], RANGES)
        model.save()
        other = self.learning(network=('other-guid', 5, '10.0.0.2', '10.0.0.1'))
        _, coverage = other.plan(RANGES, set(), [], 32)
        self.assertEqual(coverage['preferred'], 0)
        other.save()
        self.assertGreater(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)
        for field, value in [('port', 443), ('path', '/new')]:
            old = getattr(self.p, field)
            setattr(self.p, field, value)
            self.assertEqual(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)
            setattr(self.p, field, old)
        self.p.settings.probe_urls = ['https://a.example/204', 'https://b.example/204']
        self.assertEqual(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)
        self.p.settings.probe_urls = Profile('x', 'x.example', self.p.credential).settings.probe_urls
        self.p.settings.timeout_ms = 10000
        self.assertEqual(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)

    def test_scan_size_and_score_weights_do_not_discard_learning(self):
        model = self.learning()
        model.record([measured('104.16.1.1')], RANGES)
        model.save()
        self.p.settings.sample_count = 512
        self.p.settings.weight_latency = 100
        self.assertGreater(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)

    def test_old_success_fades_to_prior_and_expires_into_balanced_exploration(self):
        model = self.learning()
        model.record([measured('104.16.1.1')], RANGES)
        model.save()
        before = self.learning().scores(RANGES)['104.16.0.0/13']['score']
        week = self.learning(now=NOW + 7 * 86400).scores(RANGES)['104.16.0.0/13']['score']
        self.assertLess(week, before)
        expired = self.learning(now=NOW + 31 * 86400)
        self.assertEqual(expired.scores(RANGES)['104.16.0.0/13']['score'], .5)
        _, coverage = expired.plan(RANGES, set(), [], 32)
        self.assertEqual(coverage['preferred'], 0)

    def test_batch_size_cannot_multiply_confidence_and_one_bad_batch_does_not_erase_history(self):
        one, many = self.learning(), self.learning()
        one.record([measured('104.16.1.1')], RANGES)
        many.record([measured(f'104.16.1.{i}') for i in range(1, 13)], RANGES)
        self.assertEqual(one.scores(RANGES), many.scores(RANGES))
        for _ in range(4):
            one.record([measured('104.16.1.1')], RANGES)
        one.record([measured('104.16.1.1', False)], RANGES)
        self.assertGreater(one.scores(RANGES)['104.16.0.0/13']['score'], .5)
        _, coverage = one.plan(RANGES, set(), [], 32)
        self.assertGreater(coverage['preferred'], 0)

    def test_fast_stable_success_beats_slow_or_unstable_success(self):
        model = self.learning()
        slow = measured('172.64.1.1', warm=1200, cold=4000)
        unstable = measured('103.21.244.1')
        unstable['latency_samples'] = [10, 800, 10, 800, 10, 800]
        model.record([measured('104.16.1.1'), slow, unstable], RANGES)
        scores = model.scores(RANGES)
        self.assertGreater(scores['104.16.0.0/13']['score'], scores['172.64.0.0/13']['score'])
        self.assertGreater(scores['104.16.0.0/13']['score'], scores['103.21.244.0/22']['score'])

    def test_incomplete_validation_does_not_teach_preference(self):
        row = measured('104.16.1.1')
        row['first_request_samples'] = [600] * 4
        model = self.learning()
        model.record([row], RANGES)
        self.assertEqual(model.scores(RANGES)['104.16.0.0/13']['score'], .5)

    def test_corrupt_unknown_version_and_future_dated_evidence_fall_back(self):
        for content in ['{broken', '[]', '{"schema":99,"contexts":{}}']:
            with self.subTest(content=content):
                self.path.write_text(content, encoding='utf-8')
                _, coverage = self.learning().plan(RANGES, set(), [], 32)
                self.assertEqual(coverage['exploration'], 32)
        future = self.learning(now=NOW + 86400)
        future.record([measured('104.16.1.1')], RANGES)
        future.save()
        self.assertEqual(self.learning().scores(RANGES)['104.16.0.0/13']['score'], .5)

    def test_oversized_numeric_state_is_discarded_without_aborting_sampling(self):
        model = self.learning()
        model.record([measured('104.16.1.1')], RANGES)
        model.save()
        original = json.loads(self.path.read_text(encoding='utf-8'))
        for field in ('context_at', 'evidence_at', 'quality', 'accepted'):
            with self.subTest(field=field):
                doc = json.loads(json.dumps(original))
                context = next(iter(doc['contexts'].values()))
                if field == 'context_at':
                    context['at'] = 10**400
                else:
                    row = context['evidence']['104.16.0.0/13'][0]
                    row['at' if field == 'evidence_at' else field] = 10**400
                self.path.write_text(json.dumps(doc), encoding='utf-8')
                ips, coverage = self.learning().plan(RANGES, set(), [], 32)
                self.assertEqual(len(ips), 32)
                self.assertEqual(coverage['preferred'], 0)

    def test_exhausted_prefix_and_invalid_seeds_have_bounded_fallback(self):
        ranges = [ipaddress.ip_network('104.16.1.0/30'), RANGES[1]]
        excluded = {'104.16.1.1', '104.16.1.2', '104.16.1.3'}
        model = self.learning()
        model.record([measured('104.16.1.1')], ranges)
        ips, coverage = model.plan(ranges, excluded, ['invalid', '::1', '8.8.8.8'], 32)
        self.assertEqual(len(ips), 32)
        self.assertTrue(all(ipaddress.ip_address(ip) in RANGES[1] for ip in ips))
        self.assertEqual(coverage['preferred'], 0)
        self.assertEqual(coverage['exploration'], 32)

    def test_contexts_and_batch_history_are_bounded(self):
        for i in range(10):
            model = self.learning(network=(f'network-{i}',), now=NOW + i)
            for _ in range(40):
                model.record([measured('104.16.1.1')], RANGES)
            model.save()
        doc = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(len(doc['contexts']), 8)
        self.assertTrue(all(len(rows) <= 32 for c in doc['contexts'].values() for rows in c['evidence'].values()))


if __name__ == '__main__':
    unittest.main()
