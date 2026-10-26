import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cfai.config import Profile, atomic_json, read_json
from cfai.clash import API, ControllerError, NodePool, guard, validate_controller
from cfai.speed import Budget, summarize, round_orders


def profile():
    return Profile('线路', 'node.example.org', '11111111-2222-4333-8444-555555555555')


class FakeAPI:
    def __init__(self, p, names):
        self.p = p
        self.names = names
        self.current = names[0]
        self.mode = 'rule'
        self.outer = p.group
        self.updates = []
        self.failure = False

    def snapshot(self, p):
        return {'mode': self.mode, 'outer': {'type': 'Selector', 'now': self.outer, 'all': [p.group]},
                'cf': {'type': 'Selector', 'now': self.current, 'all': self.names},
                'provider': {'vehicleType': 'File', 'proxies': [{'name': n} for n in self.names]}, 'global': p.outer}

    def update(self, name):
        self.updates.append(name)
        if self.failure:
            raise ControllerError('fixture')


class RuntimeTests(unittest.TestCase):
    def test_controller_local_only(self):
        for value in ['http://example.com:9090', 'http://127.0.0.1:9090/path', 'http://user:pass@localhost:9090', 'https://localhost:9090']:
            with self.assertRaises(ValueError):
                validate_controller(value)
        validate_controller('http://127.0.0.1:9090')

    def test_membership_drift_is_owned_not_wrong_profile(self):
        p = profile()
        api = FakeAPI(p, ['CF-104.16.1.1', 'CF-104.16.1.2', 'CF-104.16.1.3'])
        self.assertEqual(guard(api.snapshot(p), p)[0], 'cf')
        api.outer = 'DIRECT'
        self.assertEqual(guard(api.snapshot(p), p)[0], 'paused')

    def test_crash_transaction_restores_before_membership_guard(self):
        p = profile()
        with tempfile.TemporaryDirectory() as d:
            pool = NodePool(Path(d), p, Path(d) / 'provider.yaml')
            old = [p.node('104.16.1.1'), p.node('104.16.1.2')]
            new = old + [p.node('104.16.1.3')]
            pool.initialize(old)
            atomic_json(pool.journal, {'old': old, 'new': new})
            atomic_json(pool.provider_path, {'proxies': new})
            api = FakeAPI(p, [n['name'] for n in new])
            api.current = new[-1]['name']
            pool.recover(api)
            self.assertEqual(len(pool.nodes()), 3)
            self.assertFalse(pool.journal.exists())

    def test_provider_refresh_failure_rolls_back_and_keeps_marker(self):
        p = profile()
        with tempfile.TemporaryDirectory() as d:
            pool = NodePool(Path(d), p, Path(d) / 'provider.yaml')
            old = [p.node('104.16.1.1'), p.node('104.16.1.2')]
            pool.initialize(old)
            api = FakeAPI(p, [n['name'] for n in old])
            api.failure = True
            with self.assertRaises(ControllerError):
                pool.publish(api, old + [p.node('104.16.1.3')], lambda: True)
            self.assertEqual(pool.nodes(), old)
            self.assertTrue(pool.journal.exists())

    def test_explicit_regeneration_supersedes_old_transaction(self):
        p=profile()
        with tempfile.TemporaryDirectory() as d:
            pool=NodePool(Path(d),p,Path(d)/'provider.yaml')
            old=[p.node('104.16.1.1'),p.node('104.16.1.2')]
            pool.initialize(old)
            atomic_json(pool.journal,{'old':old,'new':old+[p.node('104.16.1.3')]})
            regenerated=[old[0],p.node('104.16.1.4')]
            pool.initialize(regenerated)
            api=FakeAPI(p,[n['name'] for n in regenerated])
            pool.recover(api)
            self.assertEqual(pool.nodes(),regenerated)
            self.assertFalse(pool.journal.exists())

    def test_budget_and_interleaved_order(self):
        b = Budget(1000)
        b.reserve(600)
        b.consume(200)
        b.release(400)
        b.reserve(800)
        with self.assertRaises(ValueError):
            b.reserve(1)
        self.assertEqual(b.used, 200)
        for order in round_orders(['a', 'b', 'c'], 3):
            self.assertEqual(set(order), {'a', 'b', 'c'})
        self.assertNotEqual(round_orders(['a', 'b', 'c'], 3)[0], round_orders(['a', 'b', 'c'], 3)[1])

    def test_speed_stability_and_failures_not_hidden(self):
        self.assertIsNone(summarize([{'ok': True, 'mbps': 1}, {'ok': False}, {'ok': True, 'mbps': 1}], .45)['mbps'])
        self.assertIsNone(summarize([{'ok': True, 'mbps': x} for x in [1, 100, 1]], .45)['mbps'])
        self.assertEqual(summarize([{'ok': True, 'mbps': 2}] * 3, .45)['mbps'], 2)


if __name__ == '__main__':
    unittest.main()
