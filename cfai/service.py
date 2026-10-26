from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
import copy
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import queue
import threading
import time

from .clash import API, Activity, ControllerError, NodePool, guard
from .config import Profile, atomic_json, read_json
from .export import dynamic_config, select_results, static_config, write_yaml
from .health import History, Policy, scores
from .network import DirectNetwork
from .scanner import Scanner, check_config
from .speed import Cancelled


def context_key(p, network):
    return hashlib.sha256(json.dumps([p.fingerprint(), asdict(p.settings), network], sort_keys=True).encode()).hexdigest()


class Session:
    def __init__(self, p, store, network):
        self.key = context_key(p, network)
        saved = read_json(store.folder(p.id) / 'observations.json', {})
        self.history = History.restore(saved.get('history', {})) if saved.get('context') == self.key else History()
        self.policy = Policy()
        self.policy.last_optimization = saved.get('last_optimization', -1e20) if saved.get('context') == self.key else -1e20
        self.activity = Activity()
        self.hold = saved.get('hold', False)
        self.expected = saved.get('expected')
        self.last_tick = 0
        self.last_backup = 0
        self.state = 'waiting'
        self.current = None
        self.last_switch = saved.get('last_switch')
        self.failed_since = saved.get('failed_since', {}) if saved.get('context') == self.key else {}


class Service:
    def __init__(self, store, emit=lambda *a: None):
        self.store, self.emit = store, emit
        self.commands = queue.Queue()
        self.stop_event = threading.Event()
        self.scan_cancel = threading.Event()
        self.scan_thread = None
        self.scan_id = None
        self.scan_auto = False
        self.sessions = {}
        self.network = None
        self.network_checked = 0
        self.profiles = store.profiles()
        self.thread = threading.Thread(target=self.run, name='cfai-manager', daemon=False)
        self.logger = logging.getLogger(f'cfai-{id(self)}')
        self.logger.setLevel(logging.INFO)
        self.handler = RotatingFileHandler(store.root / 'events.log', maxBytes=1_000_000, backupCount=3, encoding='utf-8')
        self.handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(self.handler)

    @property
    def scanning(self):
        return self.scan_thread is not None and self.scan_thread.is_alive()

    def start(self):
        self.thread.start()

    def submit(self, action, *args):
        self.commands.put((action, args))

    def notify(self, kind, value):
        self.emit(kind, value)

    def profile(self, instance):
        return next(p for p in self.profiles if p.id == instance)

    def usable_results(self, p):
        document = read_json(self.store.folder(p.id) / 'results.json', {})
        current_network = list(DirectNetwork.discover().identity)
        if document.get('network') != current_network:
            raise ValueError('网络出口已变化，请在当前网络重新优选后再生成或导出')
        return self.store.results(p)

    def run(self):
        while not self.stop_event.is_set():
            try:
                action, args = self.commands.get(timeout=.2)
                try:
                    self.command(action, *args)
                except Exception as exc:
                    self.notify('error', str(exc) if isinstance(exc, (ValueError, ControllerError)) else f'操作失败（{type(exc).__name__}），原配置已保留')
                    self.logger.info('command_failed %s %s', action, type(exc).__name__)
            except queue.Empty:
                pass
            if self.stop_event.is_set():
                break
            try:
                self.monitor()
            except Exception as exc:
                self.logger.info('monitor_wait %s', type(exc).__name__)
        self.scan_cancel.set()
        if self.scan_thread:
            self.scan_thread.join(timeout=35)
        self.handler.close()
        self.notify('stopped', True)

    def stop(self):
        self.stop_event.set()
        self.scan_cancel.set()

    def command(self, action, *args):
        if action == 'save':
            profiles = args[0]
            if self.scanning:
                self.scan_cancel.set()
            self.store.save_profiles(profiles)
            self.profiles = copy.deepcopy(profiles)
            for session in self.sessions.values():
                session.last_tick = 0
            self.notify('profiles', [p.to_dict() for p in self.profiles])
        elif action == 'scan':
            self.start_scan(self.profile(args[0]), with_download=args[1])
        elif action == 'cancel':
            self.scan_cancel.set()
        elif action == 'resume':
            session = self.sessions.get(args[0])
            if session:
                session.hold = False
                session.expected = session.current
                session.policy.reset()
                session.last_tick = 0
        elif action == 'check':
            p = self.profile(args[0])
            api = API.discover(p)
            snapshot = api.snapshot(p)
            state, current = guard(snapshot, p)
            self.notify('notice', f'Clash 控制连接正常；' + ('此配置已接入' if state != 'other_profile' else '尚未启用本工具生成的动态配置'))
        elif action == 'dynamic':
            p = self.profile(args[0])
            if self.scanning:
                raise ValueError('请等待当前优选完成，再生成动态配置')
            rows = select_results(self.usable_results(p), p.settings.target_pool, ttl=p.settings.export_ttl)
            if len(rows) < 2:
                raise ValueError('动态配置至少需要两条通过真实验证的节点')
            pool = NodePool(self.store.folder(p.id), p)
            if pool.manifest.exists():
                try:
                    snapshot = API.discover(p).snapshot(p)
                    if snapshot.get('cf', {}).get('type') == 'Selector' and snapshot.get('provider'):
                        raise ValueError('此配置正在使用，请先在 Clash 切换到其他配置再重新生成')
                except ControllerError:
                    raise ValueError('无法确认 Clash 当前配置，不能覆盖已有动态节点池；请恢复控制连接后重试，或新建独立实例') from None
            nodes = [p.node(r['ip']) for r in rows]
            # Validate with an isolated local provider path first; production provider is never a staging area.
            from tempfile import TemporaryDirectory
            with TemporaryDirectory(prefix='cfai-dynamic-check-') as d:
                staged = Path(d) / 'nodes.yaml'
                atomic_json(staged, {'proxies': nodes})
                check_config(dynamic_config(p, staged))
            pool.initialize(nodes)
            destination = self.store.folder(p.id) / 'dynamic.yaml'
            write_yaml(destination, dynamic_config(p, pool.provider_path))
            self.notify('generated', str(destination))
        elif action == 'export':
            instance, destination, provider_only, strategy, selected, count = args
            p = self.profile(instance)
            rows = select_results(self.usable_results(p), count, ttl=p.settings.export_ttl, ips=selected)
            config = static_config(p, rows, provider_only, strategy)
            if not provider_only:
                check_config(config)
            else:
                check_config(static_config(p, rows))
            write_yaml(destination, config)
            self.notify('notice', f'已导出 {len(rows)} 条节点：{destination}')
        elif action == 'scan_finished':
            instance, fingerprint, rows, network, automatic = args
            p = self.profile(instance)
            if p.measurement_key() != fingerprint:
                return
            if list(DirectNetwork.discover().identity) != list(network):
                self.notify('notice', '优选结束后网络已变化，本轮结果不会发布；请在当前网络重新优选')
                return
            session = self.sessions.get(instance)
            if session and self.network and list(self.network) == list(network):
                for row in rows:
                    bw = row.get('download', {}).get('mbps')
                    if row.get('accepted') and bw is not None:
                        session.history.bandwidth[f"CF-{row['ip']}"] = {'mbps': bw, 'at': time.time()}
            if automatic:
                self.publish_discovery(p, rows)
            self.notify('results', instance)
        elif action == 'stream':
            self.start_stream(self.profile(args[0]))

    def start_scan(self, p, with_download=True, automatic=False, expected=None):
        if self.scanning:
            raise ValueError('已有优选或诊断任务，请先等待完成或取消')
        self.scan_cancel = threading.Event()
        cancel = self.scan_cancel
        self.scan_id, self.scan_auto = p.id, automatic
        p = copy.deepcopy(p)
        pool = NodePool(self.store.folder(p.id), p)
        try:
            seeds = [n['server'] for n in pool.nodes()]
        except ValueError:
            seeds = []
        self.notify('scan_started', p.id)
        finished = threading.Event()
        def watch():
            while not finished.wait(1) and not cancel.is_set() and not self.stop_event.is_set():
                try:
                    if guard(API.discover(p).snapshot(p), p) != ('cf', expected):
                        cancel.set()
                except Exception:
                    cancel.set()
        if automatic:
            threading.Thread(target=watch, name='cfai-scan-watchdog', daemon=True).start()
        def work():
            schedule = read_json(self.store.folder(p.id) / 'schedule.json', {})
            try:
                rows, network = Scanner(self.store, p, self.notify).run(lambda: cancel.is_set() or self.stop_event.is_set(), with_download, seeds)
                schedule.update(last_success=time.time(), failures=0, next_allowed=time.time() + p.settings.replenish_seconds)
                self.submit('scan_finished', p.id, p.measurement_key(), rows, network, automatic)
            except Cancelled:
                self.notify('scan_cancelled', p.id)
                schedule['next_allowed'] = time.time() + p.settings.replenish_seconds
            except Exception as exc:
                failures = min(schedule.get('failures', 0) + 1, 10)
                schedule.update(failures=failures, next_allowed=time.time() + min(7200, 900 * 2**min(failures-1, 3)))
                message = str(exc) if isinstance(exc, (ValueError, ControllerError)) else f'优选失败（{type(exc).__name__}）'
                self.notify('error', message)
                self.logger.info('scan_failed %s', type(exc).__name__)
            finally:
                atomic_json(self.store.folder(p.id) / 'schedule.json', schedule)
                finished.set()
                self.notify('scan_idle', p.id)
        self.scan_thread = threading.Thread(target=work, name='cfai-scan', daemon=False)
        self.scan_thread.start()

    def monitor(self):
        managed = [p for p in self.profiles if p.managed]
        if not managed:
            return
        now = time.time()
        if now - self.network_checked >= 60:
            self.network_checked = now
            try:
                network = DirectNetwork.discover().identity
            except (OSError, ValueError):
                self.network = None
                self.scan_cancel.set()
                for p in managed:
                    self.notify('state', {'id': p.id, 'state': 'network_unknown', 'message': '物理出口未确认，自动管理暂停'})
                return
            if self.network is not None and network != self.network:
                self.sessions.clear()
                self.scan_cancel.set()
            self.network = network
        if self.network is None:
            return
        for p in managed:
            if self.stop_event.is_set():
                return
            session = self.sessions.get(p.id)
            if session is None or session.key != context_key(p, self.network):
                session = self.sessions[p.id] = Session(p, self.store, self.network)
            if now - session.last_tick < p.settings.poll_seconds:
                continue
            session.last_tick = now
            try:
                self.tick(p, session)
            except ControllerError:
                session.state = 'unknown'
                session.policy.reset()
                if self.scan_auto and self.scan_id == p.id:
                    self.scan_cancel.set()
                self.notify('state', {'id': p.id, 'state': 'unknown', 'message': '控制连接暂不可用；保留当前线路'})
            except (ValueError, OSError) as exc:
                self.notify('state', {'id': p.id, 'state': 'error', 'message': str(exc) if isinstance(exc, ValueError) else '本机文件暂不可读'})

    def probe(self, api, p, name, cancelled=lambda: False):
        if self.stop_event.is_set() or cancelled():
            raise ControllerError('探测已取消')
        delay = api.delay(name, p.settings.probe_urls[0], p.settings.timeout_ms, p.provider)
        if delay is None:
            if self.stop_event.wait(p.settings.confirmation_seconds) or cancelled():
                raise ControllerError('探测已取消')
            delay = api.delay(name, p.settings.probe_urls[1], p.settings.timeout_ms, p.provider)
        return delay

    def tick(self, p, session):
        api = API.discover(p)
        snapshot = api.snapshot(p)
        state, current = guard(snapshot, p)
        session.state, session.current = state, current
        if state != 'cf':
            session.policy.reset()
            if self.scan_auto and self.scan_id == p.id:
                self.scan_cancel.set()
            self.notify('state', {'id': p.id, 'state': state, 'message': '等待启用此实例的动态配置' if state == 'other_profile' else '直连或其他策略，管理已暂停'})
            return
        pool = NodePool(self.store.folder(p.id), p)
        pool.recover(api)
        snapshot = api.snapshot(p)
        state, current = guard(snapshot, p)
        if state != 'cf':
            return
        if session.expected and current != session.expected:
            session.hold = True
            session.policy.reset()
        session.expected = current
        session.current = current
        names = [n['name'] for n in pool.nodes()]
        if current not in names:
            raise ControllerError('节点池尚未对齐')
        if session.hold:
            self.notify('state', {'id': p.id, 'state': 'hold', 'current': current, 'message': '检测到手动选择，点击“恢复自动管理”解除保持'})
            self.persist(p, session)
            return
        delay = self.probe(api, p, current)
        completed_at = time.time()
        session.history.record(current, delay, completed_at)
        # Failure decisions use recent backups first and do not wait for a full dead pool.
        failed = session.history.stats(current, p.settings, time.time())['failed']
        decision = (session.policy.decide(current, session.history, names, p.settings, time.time(), False, False, False)
                    if failed >= p.settings.failure_rounds else None)
        if not decision and time.time() - session.last_backup >= p.settings.backup_seconds:
            others = [n for n in names if n != current]
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {executor.submit(self.probe, api, p, name): name for name in others}
                completed = []
                for future in as_completed(futures):
                    completed.append((futures[future], future.result(), time.time()))
                # All responses must be trustworthy; controller errors leave the entire batch unscored.
                for name, value, at in completed:
                    session.history.record(name, value, at)
            session.last_backup = time.time()
        busy = False
        if p.optimize and p.settings.protect_activity:
            try:
                busy = session.activity.busy(api.connections(), p, time.time(), p.settings.idle_seconds)
            except ControllerError:
                busy = True
        decision = decision or session.policy.decide(current, session.history, names, p.settings, time.time(), p.optimize, busy, session.hold)
        if decision:
            target = decision['target']
            target_delay = self.probe(api, p, target)
            session.history.record(target, target_delay, time.time())
            if target_delay is not None:
                recovered = self.probe(api, p, current)
                # A failure switch is abandoned if the original node has recovered.
                if decision['reason'] != 'failure' or recovered is None:
                    final = api.snapshot(p)
                    if guard(final, p) == ('cf', current) and not self.stop_event.is_set():
                        if decision['reason'] == 'optimization' and p.settings.protect_activity:
                            busy = session.activity.busy(api.connections(), p, time.time(), p.settings.idle_seconds)
                        refreshed = scores(session.history, names, p.settings, time.time())
                        still_better = (refreshed.get(target, {}).get('score') is not None and refreshed.get(current, {}).get('score') is not None
                            and refreshed[target]['score'] - refreshed[current]['score'] >= p.settings.advantage_points)
                        if decision['reason'] == 'failure' or (not busy and still_better):
                            api.select(p.group, target)
                            if guard(api.snapshot(p), p) == ('cf', target):
                                session.expected = session.current = target
                                session.last_switch = {'at': time.time(), 'from': current, 'to': target, 'reason': decision['reason']}
                                session.policy.switched(time.time(), decision['reason'])
                                self.logger.info('switch %s %s', p.id, decision['reason'])
                else:
                    session.history.record(current, recovered, time.time())
        stats = scores(session.history, names, p.settings, time.time())
        healthy = sum(r['fresh'] and r['streak'] >= p.settings.recovery_rounds for n, r in stats.items() if n != session.current)
        self.notify('state', {'id': p.id, 'state': 'cf', 'current': session.current, 'stats': stats,
                             'healthy': healthy, 'last_switch': session.last_switch, 'busy': busy, 'message': '综合优化已开启' if p.optimize else '健康时保持线路，仅故障切换'})
        self.persist(p, session)
        schedule = read_json(self.store.folder(p.id) / 'schedule.json', {})
        warmed = all(r['samples'] >= p.settings.recovery_rounds for n, r in stats.items() if n != session.current)
        now = time.time()
        if (not self.scanning and not self.stop_event.is_set() and now >= schedule.get('next_allowed', 0)
                and (now - schedule.get('last_success', 0) >= p.settings.daily_seconds or (warmed and healthy < 3))):
            self.start_scan(p, p.settings.background_bandwidth, automatic=True, expected=session.current)

    def persist(self, p, session):
        atomic_json(self.store.folder(p.id) / 'observations.json', {'context': session.key, 'history': session.history.dump(),
            'expected': session.expected, 'hold': session.hold, 'last_switch': session.last_switch,
            'last_optimization': session.policy.last_optimization, 'failed_since': session.failed_since})

    def publish_discovery(self, p, rows):
        api = API.discover(p)
        state, current = guard(api.snapshot(p), p)
        session = self.sessions.get(p.id)
        if state != 'cf' or not p.managed or (session and session.hold):
            return
        pool = NodePool(self.store.folder(p.id), p)
        nodes = pool.nodes()
        protected = {current}
        try:
            for row in api.connections():
                protected.update(row.get('chains', []))
        except ControllerError:
            return
        now = time.time()
        for name, stat in scores(session.history, [n['name'] for n in nodes], p.settings, now).items():
            if stat['failed']:
                session.failed_since.setdefault(name, now)
            else:
                session.failed_since.pop(name, None)
        original = copy.deepcopy(nodes)
        for row in rows:
            if not row['accepted'] or row['ip'] in {n['server'] for n in nodes}:
                continue
            if len(nodes) >= p.settings.target_pool:
                victims = [n for n in nodes if n['name'] not in protected and now - session.failed_since.get(n['name'], now) >= 1800]
                if not victims:
                    break
                nodes.remove(victims[0])
            if len(nodes) < p.settings.max_pool:
                nodes.append(p.node(row['ip']))
        if nodes != original:
            pool.publish(api, nodes, lambda: not self.stop_event.is_set() and guard(api.snapshot(p), p) == ('cf', current))

    def start_stream(self, p):
        if not p.settings.stream_url:
            raise ValueError('请先在高级参数中填写自有流式诊断 HTTPS 地址')
        if self.scanning:
            raise ValueError('请先结束当前任务')
        from .diagnostics import stream_diagnostic
        self.scan_cancel = threading.Event()
        self.scan_id, self.scan_auto = p.id, False
        cancel = self.scan_cancel
        self.notify('scan_started', p.id)
        def work():
            try:
                result = stream_diagnostic(p, self.store.results(p), cancel.is_set, self.notify)
                self.notify('notice', result)
            except Cancelled:
                self.notify('scan_cancelled', p.id)
            except Exception as exc:
                self.notify('error', str(exc) if isinstance(exc, ValueError) else f'诊断失败（{type(exc).__name__}）')
            finally:
                self.notify('scan_idle', p.id)
        self.scan_thread = threading.Thread(target=work, name='cfai-diagnostic', daemon=False)
        self.scan_thread.start()
