import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import nullcontext
from types import SimpleNamespace

from cfai.config import Profile, Store
from cfai.health import History
from cfai.service import Service, Session
from cfai.clash import ControllerError, NodePool


class FakeAPI:
    def __init__(self,p,names):
        self.p=p
        self.names=names
        self.current=names[0]
        self.values={n:200 for n in names}
        self.selected=[]
        self.before_select=None
    def snapshot(self,p):
        return {'mode':'rule','outer':{'type':'Selector','now':p.group,'all':[p.group]},
            'cf':{'type':'Selector','now':self.current,'all':self.names},
            'provider':{'vehicleType':'File','proxies':[{'name':n} for n in self.names]}}
    def delay(self,name,*args):
        value=self.values[name]
        if isinstance(value,Exception): raise value
        return value
    def measure(self,name,*args):
        value=self.delay(name)
        return {'latency':value,'first_request':value*5 if value is not None else None}
    def select(self,group,name):
        self.selected.append(name)
        self.current=name
    def update(self,*a): pass
    def connections(self): return []


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name))
        self.p=Profile('test','node.example.org','11111111-2222-4333-8444-555555555555')
        self.p.settings.confirmation_seconds=0
        self.store.save_profiles([self.p])
        self.service=Service(self.store)
        self.addCleanup(self.service.handler.close)
        self.pool=NodePool(self.store.folder(self.p.id),self.p,Path(self.tmp.name)/'provider.json')
        self.pool.initialize([self.p.node('104.16.1.1'),self.p.node('104.16.1.2')])
        self.api=FakeAPI(self.p,[n['name'] for n in self.pool.nodes()])
        network_patch=patch('cfai.service.DirectNetwork.discover',return_value=SimpleNamespace(identity=('network',)))
        network_patch.start();self.addCleanup(network_patch.stop)
        core_patch=patch('cfai.service.isolated_core',return_value=nullcontext((self.api,0)))
        core_patch.start();self.addCleanup(core_patch.stop)
        self.session=Session(self.p,self.store,['network'])
        self.service.start_scan=lambda *a,**kw:None

    def test_controller_error_never_scores_failure(self):
        current=self.api.current
        self.api.values[current]=ControllerError('fixture')
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            with self.assertRaises(ControllerError): self.service.tick(self.p,self.session)
        self.assertEqual(self.session.history.samples,{})
        self.assertEqual(self.api.selected,[])

    def test_manual_selection_enters_hold_before_probe(self):
        self.session.expected=self.api.names[1]
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,self.session)
        self.assertTrue(self.session.hold)
        self.assertEqual(self.session.history.samples,{})

    def test_warm_request_failure_does_not_mark_working_node_down(self):
        self.api.measure=lambda name,*args:{'latency':None,'first_request':900}
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            for _ in range(3): self.service.tick(self.p,self.session)
        stats=self.session.history.stats(self.api.current,self.p.settings,__import__('time').time())
        self.assertEqual(stats['failed'],0)
        self.assertEqual(stats['first_request'],900)
        self.assertIsNone(stats['median'])
        self.assertEqual(self.api.selected,[])

    def test_failure_switch_only_after_two_failed_rounds(self):
        import time
        now=time.time()
        current,target=self.api.names
        self.api.values[current]=None
        for at in [now-20,now-10,now]: self.session.history.record(target,100,at)
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,self.session)
            self.assertEqual(self.api.selected,[])
            self.service.tick(self.p,self.session)
        self.assertEqual(self.api.selected,[target])
        self.assertEqual(self.session.expected,target)

    def test_optimization_leading_rounds_survive_healthy_ticks(self):
        import time
        now=time.time()
        current,target=self.api.names
        self.p.optimize=True
        self.p.settings.protect_activity=False
        self.api.values[current]=1800
        self.api.values[target]=100
        for at in [now-20,now-10,now]:
            self.session.history.record(current,1800,at)
            self.session.history.record(target,100,at)
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            for i in range(3):
                self.session.last_backup=0
                self.service.tick(self.p,self.session)
                if i<2: self.assertEqual(self.api.selected,[])
        self.assertEqual(self.api.selected,[target])

    def test_queued_results_from_old_network_never_publish(self):
        from types import SimpleNamespace
        self.service.publish_discovery=lambda *a: self.fail('old network result published')
        with patch('cfai.service.DirectNetwork.discover',return_value=SimpleNamespace(identity=('new-network',))):
            self.service.command('scan_finished',self.p.id,self.p.measurement_key(),[],['old-network'],True)

    def test_unknown_controller_blocks_dynamic_provider_overwrite(self):
        import time
        rows=[{'ip':ip,'accepted':True,'validated_at':time.time(),'samples':[100]*6,'score':90} for ip in ['104.16.1.1','104.16.1.2']]
        self.service.usable_results=lambda p:rows
        before=self.pool.provider_path.read_bytes()
        with patch('cfai.service.NodePool',return_value=self.pool),patch('cfai.service.API.discover',side_effect=ControllerError('unknown')):
            with self.assertRaises(ValueError):self.service.command('dynamic',self.p.id)
        self.assertEqual(self.pool.provider_path.read_bytes(),before)


if __name__=='__main__': unittest.main()
