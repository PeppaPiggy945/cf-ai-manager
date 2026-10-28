import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cfai.clash import API, ControllerError, NodePool, guard
from cfai.config import Profile, Store, atomic_json
from cfai.export import dynamic_config
from cfai.scanner import core_path, free_port, FLAGS, isolated_core
from cfai.service import Service


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
                # Refresh a full pool by replacing an unused standby, retaining selection.
                replacement=[old[1],p.node('104.16.1.4')]
                pool.publish(api,replacement,lambda:guard(api.snapshot(p),p)==('cf',old[1]['name']))
                self.assertEqual(pool.nodes(),replacement)
                self.assertEqual(set(api.snapshot(p)['cf']['all']),{n['name'] for n in replacement})
                self.assertEqual(guard(api.snapshot(p),p),('cf',old[1]['name']))
                # Re-generating the imported configuration must refresh its file provider,
                # including when automatic management is off and manual hold is persisted.
                p.controller=api.url;p.secret='fixture';p.settings.target_pool=2
                store=Store(folder/'state')
                store.save_profiles([p])
                store.save_results(p,[{'ip':'104.16.1.5','accepted':True,'samples':[100]*6,
                                      'validated_at':time.time(),'score':90}],['fixture'])
                atomic_json(store.folder(p.id)/'observations.json',{'hold':True})
                events=[]
                service=Service(store,lambda *args:events.append(args))
                try:
                    with patch('cfai.service.NodePool',return_value=pool), \
                         patch('cfai.service.DirectNetwork.discover',return_value=SimpleNamespace(identity=('fixture',))):
                        service.command('dynamic',p.id,str(folder/'regenerated.yaml'))
                    expected={old[1]['name'],'CF-104.16.1.5'}
                    self.assertEqual({n['name'] for n in pool.nodes()},expected)
                    self.assertEqual(set(api.snapshot(p)['cf']['all']),expected)
                    self.assertEqual({n['name'] for n in api.snapshot(p)['provider']['proxies']},expected)
                    self.assertEqual(guard(api.snapshot(p),p),('cf',old[1]['name']))
                    self.assertIn('已同步',events[-1][1]['publication'])
                    self.assertTrue(service.sessions[p.id].hold)
                finally:
                    service.handler.close()
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_isolated_core_starts_and_cleans_up_without_external_probe(self):
        p=Profile('fixture','node.example.org','11111111-2222-4333-8444-555555555555')
        with isolated_core([p.node('104.16.1.1')],None,lambda:False,time.monotonic()+15) as (api,port):
            self.assertTrue(api.request('GET','/version').get('version'))
            address=api.url
        with self.assertRaises(ControllerError):API(address).request('GET','/version',timeout=.3)
