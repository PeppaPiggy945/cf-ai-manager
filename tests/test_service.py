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

    def test_manual_selection_keeps_monitoring_and_reports_metrics_without_switching(self):
        self.session.expected=self.api.names[1]
        events=[];self.service.emit=lambda *args:events.append(args)
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,self.session)
        self.assertTrue(self.session.hold)
        self.assertTrue(self.session.history.samples)
        self.assertEqual(self.api.selected,[])
        state=next(v for kind,v in events if kind=='state')
        self.assertEqual(state['state'],'hold')
        self.assertEqual(state['stats'][self.api.current]['median'],200)
        self.assertEqual(state['stats'][self.api.current]['first_request'],1000)
        self.assertGreater(state['last_probe_at'],0)
        self.assertIn('next_scan_at',state)

    def test_hold_blocks_failure_switch_and_pool_publication_but_allows_discovery(self):
        import time
        now=time.time();current,target=self.api.names
        self.p.managed=True;self.p.optimize=True;self.session.hold=True
        self.service.sessions[self.p.id]=self.session
        for at in [now-30,now-20,now-10]:
            self.session.history.record(current,None,at)
            self.session.history.record(target,100,at,600)
        self.api.values[current]=None
        scans=[];self.service.start_scan=lambda *args,**kw:scans.append(kw)
        before=self.pool.provider_path.read_bytes()
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,self.session)
            self.service.publish_discovery(self.p,[{'ip':'104.16.1.3','accepted':True}])
        self.assertEqual(self.api.selected,[])
        self.assertEqual(self.pool.provider_path.read_bytes(),before)
        self.assertEqual(len(scans),1)
        self.assertTrue(scans[0]['automatic'])

    def test_setting_change_does_not_reuse_an_unrelated_expected_selection(self):
        from cfai.config import atomic_json
        atomic_json(self.store.folder(self.p.id)/'observations.json',{'context':self.session.key,'expected':self.api.names[1],'hold':False})
        self.p.settings.poll_seconds=20
        session=Session(self.p,self.store,['network'])
        self.assertIsNone(session.expected)
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,session)
        self.assertFalse(session.hold)

    def test_scan_schedule_reports_daily_due_time_without_forcing_a_fresh_scan(self):
        import time
        from cfai.config import atomic_json
        now=time.time();last_scan=now-5*3600
        atomic_json(self.store.folder(self.p.id)/'schedule.json',{'last_success':last_scan,'next_allowed':last_scan+900})
        events=[];self.service.emit=lambda *args:events.append(args)
        scans=[];self.service.start_scan=lambda *args,**kw:scans.append(kw)
        with patch('cfai.service.API.discover',return_value=self.api),patch('cfai.service.NodePool',return_value=self.pool):
            self.service.tick(self.p,self.session)
        state=next(v for kind,v in events if kind=='state')
        self.assertEqual(state['last_scan_at'],last_scan)
        self.assertEqual(state['next_scan_at'],last_scan+self.p.settings.daily_seconds)
        self.assertEqual(scans,[])

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

    def test_dynamic_saved_to_selected_location_with_absolute_provider_reference(self):
        import time
        import json
        rows=[{'ip':ip,'accepted':True,'validated_at':time.time(),'samples':[100]*6,'score':90} for ip in ['104.16.1.1','104.16.1.2']]
        self.service.usable_results=lambda p:rows
        events=[];self.service.emit=lambda *args:events.append(args)
        # The existing pool is inactive in the current Clash profile.
        self.api.snapshot=lambda p:{'cf':{},'provider':{}}
        destination=Path(self.tmp.name)/'导入 Clash 的配置.yaml'
        with patch('cfai.service.NodePool',return_value=self.pool),patch('cfai.service.API.discover',return_value=self.api):
            self.service.command('dynamic',self.p.id,str(destination))
        config=json.loads(destination.read_text(encoding='utf-8'))
        self.assertEqual(Path(config['proxy-providers'][self.p.provider]['path']),self.pool.provider_path.resolve())
        self.assertEqual(events[-1],('generated',str(destination)))
        self.assertEqual(self.api.selected,[])

    def test_dynamic_destination_failure_leaves_existing_pool_unchanged(self):
        import time
        rows=[{'ip':ip,'accepted':True,'validated_at':time.time(),'samples':[100]*6,'score':90} for ip in ['104.16.1.1','104.16.1.2']]
        self.service.usable_results=lambda p:rows
        self.api.snapshot=lambda p:{'cf':{},'provider':{}}
        before=self.pool.provider_path.read_bytes()
        with patch('cfai.service.NodePool',return_value=self.pool),patch('cfai.service.API.discover',return_value=self.api):
            with self.assertRaises(ValueError):
                self.service.command('dynamic',self.p.id,str(self.pool.provider_path))
            with patch('cfai.service.write_yaml',side_effect=PermissionError('fixture')):
                with self.assertRaises(PermissionError):
                    self.service.command('dynamic',self.p.id,str(Path(self.tmp.name)/'not-writable.yaml'))
        self.assertEqual(self.pool.provider_path.read_bytes(),before)


if __name__=='__main__': unittest.main()
