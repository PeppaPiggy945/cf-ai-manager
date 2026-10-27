from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import copy
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import random
import secrets
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time

from .clash import API, ControllerError
from .config import atomic_json, read_json
from .discovery import EXPLORATION_SHARE, PrefixLearning
from .health import rank_results
from .network import DirectNetwork
from .speed import Budget, Cancelled, download, round_orders, summarize
from .process import ChildJob

RANGES = '''173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22'''.split()
FLAGS = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def core_path():
    base = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))
    path = base / 'resources' / 'mihomo.exe'
    manifest = read_json(base / 'resources' / 'core.json')
    if not manifest or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest['sha256']:
        raise ValueError('独立测试内核缺失或校验失败，请重新解压完整发布包')
    return path


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def check_config(config):
    with tempfile.TemporaryDirectory(prefix='cfai-syntax-') as d:
        config = copy.deepcopy(config)
        # Syntax validation must stay inside its disposable HOME. Verify the actual production
        # SAFE_PATHS separately when the user activates the generated dynamic profile.
        for index, provider in enumerate(config.get('proxy-providers', {}).values()):
            if provider.get('type') == 'file':
                source = Path(provider['path'])
                staged = Path(d) / f'provider-{index}.json'
                staged.write_bytes(source.read_bytes())
                provider['path'] = staged.name
        path = Path(d) / 'config.json'
        atomic_json(path, config)
        proc = subprocess.run([str(core_path()), '-t', '-d', d, '-f', str(path)], capture_output=True, timeout=20, creationflags=FLAGS)
        if proc.returncode:
            raise ValueError('Mihomo 配置检查未通过，请检查节点参数')


@contextmanager
def isolated_core(nodes, network, cancelled, deadline):
    with tempfile.TemporaryDirectory(prefix='cfai-probe-') as d:
        folder = Path(d)
        controller_port, proxy_port = free_port(), free_port()
        while proxy_port == controller_port:
            proxy_port = free_port()
        secret = secrets.token_hex(24)
        used_ports = {controller_port, proxy_port}
        probe_ports = {}
        for node in nodes:
            port = free_port()
            while port in used_ports:
                port = free_port()
            used_ports.add(port)
            probe_ports[node['name']] = port
        test_nodes = copy.deepcopy(nodes)
        if network:
            for node in test_nodes:
                node['interface-name'] = network.interface['name']
        config = {'external-controller': f'127.0.0.1:{controller_port}', 'secret': secret,
                  'mixed-port': proxy_port, 'bind-address': '127.0.0.1', 'allow-lan': False,
                  'log-level': 'silent', 'mode': 'rule', 'profile': {'store-selected': False},
                  'proxies': test_nodes, 'proxy-groups': [{'name': 'TEST', 'type': 'select', 'proxies': [n['name'] for n in nodes]}],
                  'rules': ['MATCH,TEST'], 'dns': {'enable': False}}
        # Dedicated per-node inbounds allow concurrent paired HTTPS requests without
        # racing the shared TEST selector or touching the user's active Clash core.
        config['listeners'] = [{'name': f'probe-{i}', 'type': 'mixed', 'listen': '127.0.0.1',
                                'port': probe_ports[n['name']], 'proxy': n['name'], 'udp': False}
                               for i, n in enumerate(nodes)]
        if network:
            config['interface-name'] = network.interface['name']
        path = folder / 'config.json'
        atomic_json(path, config)
        with (folder / 'core.log').open('wb') as output:
            job = ChildJob()
            process = None
            try:
                process = subprocess.Popen([str(core_path()), '-d', d, '-f', str(path)], stdout=output, stderr=output, creationflags=FLAGS)
                job.attach(process)
                api = API(f'http://127.0.0.1:{controller_port}', secret)
                api.probe_ports = probe_ports
                for _ in range(80):
                    if cancelled() or time.monotonic() > deadline or process.poll() is not None:
                        raise Cancelled()
                    try:
                        api.request('GET', '/version', timeout=.5)
                        break
                    except ControllerError:
                        time.sleep(.1)
                else:
                    raise ValueError('独立测试内核未能启动')
                yield api, proxy_port
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                job.close()


def parse_ranges(text):
    if len(text) > 8192:
        raise ValueError('网段响应过大')
    result = [ipaddress.ip_network(v) for v in text.split()]
    trusted = [ipaddress.ip_network(v) for v in RANGES]
    if not result or len(result) > 64 or any(n.version != 4 or not any(n.subnet_of(t) for t in trusted) for n in result):
        raise ValueError('网段不在已核实的 CF IPv4 范围中')
    return result


def load_ranges(network, folder):
    cache = read_json(Path(folder) / 'ranges.json', {})
    if 0 <= time.time() - cache.get('at', 0) < 86400:
        return parse_ranges(cache['text']), '官方网段缓存'
    try:
        # Resolve no DNS through the running TUN: physical connection to known CF edge, normal verified SNI.
        raw = network.connect(('104.16.132.229', 443), 4)
        with ssl.create_default_context().wrap_socket(raw, server_hostname='www.cloudflare.com') as stream:
            stream.sendall(b'GET /ips-v4 HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(stream)
            response.begin()
            if response.status != 200:
                raise OSError()
            text = response.read(8193).decode('ascii')
            ranges = parse_ranges(text)
            atomic_json(Path(folder) / 'ranges.json', {'text': text, 'at': time.time()})
            return ranges, 'Cloudflare 官方网段'
    except (OSError, ValueError, UnicodeError, http.client.HTTPException):
        if cache:
            try:
                return parse_ranges(cache['text']), '获取失败，使用官方缓存'
            except (KeyError, ValueError):
                pass
        return parse_ranges(' '.join(RANGES)), '获取失败，使用随包核实网段'


def sample(ranges, excluded, cursor, count):
    ips, seen = [], set(excluded)
    index = cursor
    while len(ips) < count and index < cursor + count * 20:
        n = ranges[index % len(ranges)]
        # Independent prefix offsets avoid probing the same suffix in every range.
        offset = int.from_bytes(hashlib.sha256(str(n).encode()).digest()[:4], 'big')
        position = ((index // len(ranges)) * 2654435761 + offset) % n.num_addresses
        ip = str(n.network_address + position)
        if ip not in seen and position % 256 not in (0, 255):
            ips.append(ip)
            seen.add(ip)
        index += 1
    return ips, index


def shortlist(rows, maximum, settings, previous, exploration=None):
    selected = []
    def prefix(row):
        return next((n for n in RANGES if ipaddress.IPv4Address(row['ip']) in ipaddress.ip_network(n)), row['ip'])
    def take(source, count):
        added = 0
        for row in source:
            if added >= count or len(selected) >= maximum:
                break
            if row not in selected:
                selected.append(row)
                added += 1
    if exploration:
        # Keep fresh exploration in the expensive stage even when history/latency fills all other slots.
        reserve = math.ceil(min(maximum, len(rows)) * EXPLORATION_SHARE)
        distinct, seen = [], set()
        for row in exploration:
            if prefix(row) not in seen:
                distinct.append(row)
                seen.add(prefix(row))
        take(distinct, reserve)
        take(exploration, max(0, reserve - len(selected)))
    take(sorted(rows, key=lambda r: r['median_ms']), max(1, round(maximum * settings.latency_share)))
    reputation = {r['ip']: r.get('score') or 0 for r in previous if r.get('accepted')}
    take(sorted([r for r in rows if r['ip'] in reputation], key=lambda r: -reputation[r['ip']]), round(maximum * settings.history_share))
    shuffled = list(rows)
    random.shuffle(shuffled)
    # Reserve exploration for prefixes not yet represented by latency/history picks.
    represented = {prefix(r) for r in selected}
    for row in shuffled:
        key = prefix(row)
        if key not in represented and len(selected) < maximum:
            selected.append(row)
            represented.add(key)
    take(shuffled, maximum)
    return selected


class Scanner:
    def __init__(self, store, profile, event=lambda *a: None):
        self.store, self.p, self.event = store, profile, event

    def run(self, cancelled, with_download=True, seed_ips=None):
        p, s = self.p, self.p.settings
        folder = self.store.folder(p.id)
        deadline = time.monotonic() + 600
        def stopped():
            return cancelled() or time.monotonic() >= deadline
        self.event('scan', '确认物理网络出口')
        network = DirectNetwork.discover()
        api = None
        try:
            api = API.discover(p)
            api.request('GET', '/version', timeout=2)
        except ControllerError:
            api = None
        self.event('scan', '验证物理出口（不修改系统路由）')
        verified = False
        for ip in list(seed_ips or [])[:3] + ['104.16.132.229', '104.17.154.105']:
            if stopped():
                raise Cancelled()
            try:
                network.verify(api, ip, p.port)
                verified = True
                break
            except OSError:
                continue
        if not verified:
            raise ValueError('物理出口验证失败，已暂停；没有退回现用代理测速')
        ranges, source = load_ranges(network, folder)
        state = read_json(folder / 'scan-state.json', {})
        network_key = hashlib.sha256(repr((network.identity, p.port)).encode()).hexdigest()[:16]
        previous = self.store.results(p)
        # Same-network successes may be retested; recent failed candidates are excluded.
        recent = state.get('recent', {}) if state.get('network') == network_key else {}
        excluded = {ip for ip, at in recent.items() if 0 <= time.time() - at < 30 * 86400}
        learning = PrefixLearning(folder / 'discovery.json', p, network.identity)
        seeds = list(dict.fromkeys([*(seed_ips or []), *[r['ip'] for r in previous
                                  if r.get('accepted') and r.get('network') == list(network.identity)]]))
        ips, allocation = learning.plan(ranges, excluded, seeds, s.sample_count)
        exploration_ips = set(allocation.pop('exploration_ips'))
        coverage = {'ranges': len(ranges), 'pool_addresses': sum(n.num_addresses for n in ranges),
                    'sampled': len(ips), 'tcp_passed': 0, 'validated': 0, 'rounds': 3, **allocation}
        self.event('scan', f"TCP 初筛 · {len(ips)} 个入口 / {coverage['ranges']} 段 · "
                   f"偏好 {coverage['preferred']} / 探索 {coverage['exploration']} / 复测 {coverage['reused']} · {source}")
        def tcp(ip):
            values = []
            for _ in range(3):
                if stopped():
                    return None
                start = time.perf_counter()
                try:
                    with network.connect((ip, p.port), timeout=2):
                        values.append((time.perf_counter() - start) * 1000)
                except OSError:
                    pass
            return {'ip': ip, 'median_ms': statistics.median(values)} if len(values) >= 2 else None
        screened = []
        with ThreadPoolExecutor(max_workers=s.tcp_workers) as pool:
            for completed, future in enumerate(as_completed([pool.submit(tcp, ip) for ip in ips]), 1):
                row = future.result()
                if row:
                    screened.append(row)
                if completed % s.tcp_workers == 0 or completed == len(ips):
                    self.event('scan', f'TCP 初筛 · {completed}/{len(ips)} · {len(screened)} 个通过')
        if stopped():
            raise Cancelled()
        recent = {ip: at for ip, at in recent.items() if time.time() - at < 30 * 86400}
        recent.update({ip: time.time() for ip in ips})
        atomic_json(folder / 'scan-state.json', {'network': network_key, 'cursor': state.get('cursor', 0),
                                                'recent': dict(list(recent.items())[-20000:])})
        learning.save()  # Sampling progress only; no tunnel evidence from partial tasks.
        exploration = learning.validation_order([r for r in screened if r['ip'] in exploration_ips], ranges)
        chosen = shortlist(screened, s.validation_candidates, s, previous, exploration=exploration)
        coverage.update(tcp_passed=len(screened), validated=len(chosen))
        coverage['validation_exploration'] = sum(r['ip'] in exploration_ips for r in chosen)
        for net in ranges:
            counts = coverage['prefixes'][str(net)]
            counts['tcp_passed'] = sum(ipaddress.IPv4Address(r['ip']) in net for r in screened)
            counts['validated'] = sum(ipaddress.IPv4Address(r['ip']) in net for r in chosen)
        if not chosen:
            raise ValueError('本轮没有入口通过 TCP 初筛，原节点池保持不变')
        self.event('scan', f'真实隧道验证 · {len(chosen)} 个候选 / 3 轮')
        rows = [{'ip': r['ip'], 'samples': [], 'latency_samples': [], 'first_request_samples': [], 'sample_times': [],
                 'probe_errors': [], 'scan_coverage': coverage} for r in chosen]
        nodes = [p.node(r['ip']) for r in rows]
        with isolated_core(nodes, network, stopped, deadline) as (test_api, proxy_port):
            def probe(row):
                pair = []
                for url in s.probe_urls[:2]:
                    if stopped():
                        raise Cancelled()
                    pair.append(test_api.measure(f"CF-{row['ip']}", url, s.timeout_ms, stopped))
                return row, pair, time.time()
            for round_index in range(3):
                with ThreadPoolExecutor(max_workers=s.validation_workers) as pool:
                    for completed_count, future in enumerate(as_completed([pool.submit(probe, r) for r in rows]), 1):
                        row, pair, completed = future.result()
                        row['first_request_samples'].extend(v['first_request'] for v in pair)
                        row['latency_samples'].extend(v['latency'] for v in pair)
                        row['samples'].extend(v['first_request'] for v in pair)
                        row['sample_times'].extend([completed] * 2)
                        row['probe_errors'].extend(v.get('error', '') for v in pair)
                        self.event('scan', f'真实隧道验证 · 第 {round_index+1}/3 轮 · {completed_count}/{len(rows)} 个候选完成')
                if round_index < 2:
                    self.event('scan', f'验证间隔 · 等待 {s.validation_interval} 秒 · 可取消')
                    until = time.monotonic() + s.validation_interval
                    while time.monotonic() < until:
                        if stopped():
                            raise Cancelled()
                        time.sleep(.1)
            for row in rows:
                values = row['samples']
                row.update(accepted=sum(x is not None for x in values) >= 5 and all(x is not None for x in values[-2:]),
                           validated_at=time.time(), network=list(network.identity), source=source)
            accepted = [r for r in rows if r['accepted']]
            budget = Budget(s.budget_bytes)
            if with_download and accepted:
                selected = shortlist([dict(r, median_ms=statistics.median(x for x in r['samples'] if x)) for r in accepted], s.download_candidates, s, previous)
                by_ip = {r['ip']: r for r in rows}
                runs = {r['ip']: [] for r in selected}
                failed = set()
                for index, order in enumerate(round_orders(list(runs), s.download_rounds)):
                    for ip in order:
                        if stopped():
                            raise Cancelled()
                        if ip in failed:
                            runs[ip].append(None)
                            continue
                        self.event('scan', f'轻量下载 · 第 {index+1}/{s.download_rounds} 轮 · {ip} · {budget.used/1e6:.1f} MB')
                        test_api.select('TEST', f'CF-{ip}')
                        if test_api.request('GET', '/proxies/TEST').get('now') != f'CF-{ip}':
                            raise ValueError('独立测试节点选择未确认')
                        try:
                            if index == 0 and s.warmup_bytes:
                                download(proxy_port, s.download_url, s.warmup_bytes, s.download_timeout, budget, stopped)
                            result = download(proxy_port, s.download_url, s.download_bytes, s.download_timeout, budget, stopped)
                        except ValueError:
                            result = {'ok': False, 'error': '预算不足'}
                        runs[ip].append(result)
                        if not result.get('ok'):
                            failed.add(ip)
                for ip, values in runs.items():
                    summary = summarize(values, s.maximum_cv)
                    summary['at'] = time.time()
                    by_ip[ip]['download'] = summary
            # Batch ranking is an export snapshot, not production freshness. A long download batch
            # must not erase valid earlier latency samples; never seed live recovery streaks from it.
            for row in rows:
                row['download_bytes_total'] = budget.used
            rows = rank_results(rows, s)
        if stopped():
            raise Cancelled()
        self.event('scan', '验证已结束，正在复核物理网络并保存结果…')
        if DirectNetwork.discover().identity != network.identity:
            raise ValueError('出口网卡已变化，本轮结果已丢弃')
        network.verify(api, rows[0]['ip'], p.port)
        if stopped():
            raise Cancelled()
        rows.sort(key=lambda r: (not r['accepted'], -(r.get('score') or 0)))
        self.store.save_results(p, rows, network.identity)
        learning.record(rows, ranges)
        learning.save()
        self.event('scan_done', {'rows': rows, 'bytes': budget.used, 'network': list(network.identity), 'coverage': coverage})
        return rows, network.identity
