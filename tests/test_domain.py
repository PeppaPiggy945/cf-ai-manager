import copy
import tempfile
import unittest
from pathlib import Path

from cfai.config import Profile, Settings, Store
from cfai.health import History, Policy, scores
from cfai.export import static_config, select_results


def profile():
    return Profile(name='测试线路', domain='node.example.org', credential='11111111-2222-4333-8444-555555555555')


class ConfigTests(unittest.TestCase):
    def test_template_preserves_credentials_and_separates_origin(self):
        p = profile()
        p.vps_ip = '8.8.8.8'
        node = p.node('104.16.1.1')
        self.assertEqual(node['server'], '104.16.1.1')
        self.assertEqual(node['servername'], p.domain)
        self.assertEqual(node['uuid'], p.credential)
        self.assertNotIn('interface-name', node)
        with self.assertRaises(ValueError):
            p.node('127.0.0.1')

    def test_config_atomic_roundtrip_and_invalid_preserves_previous(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d))
            p = profile()
            store.save_profiles([p])
            self.assertEqual(store.profiles()[0].id, p.id)
            p.port = 0
            with self.assertRaises(ValueError):
                store.save_profiles([p])
            self.assertEqual(store.profiles()[0].port, 8443)

    def test_invalid_settings_and_fingerprint(self):
        s = Settings()
        s.backup_seconds = 120
        with self.assertRaises(ValueError):
            s.validate()
        p = profile()
        original = p.fingerprint()
        p.name = '改名'
        self.assertEqual(p.fingerprint(), original)
        p.path = '/changed'
        self.assertNotEqual(p.fingerprint(), original)

    def test_corrupt_configuration_recovers_backup_with_management_off(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d))
            p=profile()
            p.managed=True
            store.save_profiles([p])
            p.name='updated'
            store.save_profiles([p])
            (Path(d)/'profiles.json').write_text('{broken',encoding='utf-8')
            recovered=store.profiles()
            self.assertEqual(recovered[0].name,'测试线路')
            self.assertFalse(recovered[0].managed)
            self.assertTrue(store.recovery_note)
            self.assertEqual(len(list(Path(d).glob('profiles.corrupt-*.json'))),1)

    def test_settings_change_invalidates_old_measurements(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d))
            p=profile()
            store.save_results(p,[{'ip':'104.16.1.1'}],['fixture'])
            self.assertEqual(len(store.results(p)),1)
            p.settings.weight_latency=30
            self.assertEqual(store.results(p),[])


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.s = Settings()
        self.h = History()

    def warm(self, name, delay, now=1000):
        for at in [now - 20, now - 10, now]:
            self.h.record(name, delay, at)

    def test_missing_bandwidth_uses_same_metrics(self):
        self.warm('a', 200)
        self.warm('b', 200)
        self.h.bandwidth['a'] = {'mbps': 100, 'at': 1000}
        result = scores(self.h, ['a', 'b'], self.s, 1001)
        self.assertEqual(result['a']['score'], result['b']['score'])
        self.assertFalse(result['a']['bandwidth_used'])

    def test_bandwidth_capped_and_future_stale_excluded(self):
        self.warm('a', 200)
        self.warm('b', 200)
        for name, speed in [('a', 2), ('b', 100)]:
            self.h.bandwidth[name] = {'mbps': speed, 'at': 1000}
        self.assertEqual(scores(self.h, ['a', 'b'], self.s, 1001)['a']['score'],
                         scores(self.h, ['a', 'b'], self.s, 1001)['b']['score'])
        self.assertIsNone(scores(self.h, ['a'], self.s, 2000)['a']['score'])

    def test_fault_only_never_chases_and_failure_requires_two(self):
        self.warm('a', 900)
        self.warm('b', 100)
        policy = Policy()
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1001, False, False, False))
        self.h.record('a', None, 1002)
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1002, False, False, False))
        self.h.record('a', None, 1003)
        self.assertEqual(policy.decide('a', self.h, ['a', 'b'], self.s, 1003, False, False, False)['target'], 'b')

    def test_active_optimization_new_rounds_cooldown_busy_and_hold(self):
        self.warm('a', 1800)
        self.warm('b', 100)
        policy = Policy()
        for _ in range(5):
            self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1001, True, False, False))
        self.h.record('b', 100, 1010)
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1010, True, False, False))
        self.h.record('b', 100, 1020)
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1020, True, True, False))
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1020, True, False, True))
        decision = policy.decide('a', self.h, ['a', 'b'], self.s, 1020, True, False, False)
        self.assertEqual(decision['reason'], 'optimization')
        policy.switched(1020, 'optimization')
        self.assertIsNone(policy.decide('a', self.h, ['a', 'b'], self.s, 1021, True, False, False))


class ExportTests(unittest.TestCase):
    def test_static_has_no_local_dependencies_and_rebuilds_from_template(self):
        p = profile()
        rows = [{'ip': '104.16.1.1', 'accepted': True, 'validated_at': 1000, 'samples': [100]*6, 'score': 90,
                 'node': {'uuid': 'untrusted'}}]
        selected = select_results(rows, 5, now=1001)
        cfg = static_config(p, selected)
        self.assertNotIn('proxy-providers', cfg)
        self.assertEqual(cfg['proxies'][0]['uuid'], p.credential)
        self.assertEqual(cfg['proxy-groups'][0]['type'], 'select')
        self.assertNotIn('external-controller', cfg)
        with self.assertRaises(ValueError):
            select_results(rows, 5, now=100000)


if __name__ == '__main__':
    unittest.main()
