import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cfai.clash import API, ControllerError, NodePool, guard
from cfai.config import Profile, atomic_json
from cfai.export import dynamic_config
from cfai.scanner import core_path, free_port, FLAGS, isolated_core


class MihomoContractTests(unittest.TestCase):
    def test_real_core_provider_refresh_preserves_selection(self):
        p=Profile('fixture','node.example.org','11111111-2222-4333-8444-555555555555')
        with tempfile.TemporaryDirectory(prefix='cfai-contract-') as d:
            folder=Path(d)
            pool=NodePool(folder,p,folder/'nodes.yaml')
            old=[p.node('104.16.1.1'),p.node('104.16.1.2')]
            pool.initialize(old)
            config=dynamic_config(p,pool.provider_path)
            port=free_port()
            config.update({'external-controller':f'127.0.0.1:{port}','secret':'fixture','log-level':'silent'})
            config.pop('mixed-port')
            atomic_json(folder/'config.json',config)
            process=subprocess.Popen([str(core_path()),'-d',d,'-f',str(folder/'config.json')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=FLAGS)
            api=API(f'http://127.0.0.1:{port}','fixture')
            try:
                for _ in range(60):
                    try:api.request('GET','/version',timeout=.3);break
                    except ControllerError:time.sleep(.1)
                api.select(p.outer,p.group)
                api.select(p.group,old[1]['name'])
                self.assertEqual(guard(api.snapshot(p),p),('cf',old[1]['name']))
                nodes=old+[p.node('104.16.1.3')]
                pool.publish(api,nodes,lambda:guard(api.snapshot(p),p)==('cf',old[1]['name']))
                self.assertEqual(len(pool.nodes()),3)
                self.assertEqual(guard(api.snapshot(p),p),('cf',old[1]['name']))
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_isolated_core_starts_and_cleans_up_without_external_probe(self):
        p=Profile('fixture','node.example.org','11111111-2222-4333-8444-555555555555')
        with isolated_core([p.node('104.16.1.1')],None,lambda:False,time.monotonic()+15) as (api,port):
            self.assertTrue(api.request('GET','/version').get('version'))
            address=api.url
        with self.assertRaises(ControllerError):API(address).request('GET','/version',timeout=.3)
