from __future__ import annotations

import json
import math
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener
import yaml

from .config import atomic_json, read_json


class ControllerError(Exception):
    pass


def verge_home():
    return Path(os.environ.get('APPDATA', Path.home())) / 'io.github.clash-verge-rev.clash-verge-rev'


def validate_controller(url):
    p = urlsplit(url)
    if (p.scheme != 'http' or p.hostname not in ('127.0.0.1', 'localhost', '::1')
            or p.username or p.password or p.path not in ('', '/') or p.query or p.fragment):
        raise ValueError('Clash 控制地址必须是本机 HTTP 地址，如 http://127.0.0.1:9090')
    try:
        if not p.port or not 0 < p.port <= 65535:
            raise ValueError()
    except ValueError:
        raise ValueError('Clash 控制端口无效') from None
    return url.rstrip('/')


class API:
    def __init__(self, url, secret=''):
        self.url = validate_controller(url)
        self.secret = secret
        self.opener = build_opener(ProxyHandler({}))

    @classmethod
    def discover(cls, profile=None):
        if profile and profile.controller:
            return cls(profile.controller, profile.secret)
        for name in ('clash-verge.yaml', 'config.yaml'):
            try:
                cfg = yaml.safe_load((verge_home() / name).read_text(encoding='utf-8-sig'))
                address = cfg.get('external-controller', '')
                if address:
                    host, port = address.rsplit(':', 1)
                    if host in ('', '0.0.0.0', '::', '[::]'):
                        address = '127.0.0.1:' + port
                    return cls('http://' + address, cfg.get('secret', '') or '')
            except (OSError, ValueError, AttributeError, yaml.YAMLError):
                continue
        raise ControllerError('未发现 Clash 本机控制接口；可在服务器高级设置中填写')

    def request(self, method, path, body=None, timeout=4, probe=False):
        headers = {'Content-Type': 'application/json'}
        if self.secret:
            headers['Authorization'] = 'Bearer ' + self.secret
        req = Request(self.url + path, data=json.dumps(body).encode() if body is not None else None,
                      headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as response:
                raw = response.read(8_000_001)
                if len(raw) > 8_000_000:
                    raise ControllerError('控制接口响应过大')
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            if probe and exc.code in (503, 504):
                return None
            raise ControllerError(f'Clash 控制接口 HTTP {exc.code}') from None
        except (OSError, URLError, ValueError):
            raise ControllerError('Clash 控制接口不可达或响应无效') from None

    def snapshot(self, p):
        proxies = self.request('GET', '/proxies').get('proxies', {})
        configs = self.request('GET', '/configs')
        providers = self.request('GET', '/providers/proxies').get('providers', {})
        return {'mode': configs.get('mode', ''), 'tun': configs.get('tun', {}).get('enable', False),
                'outer': proxies.get(p.outer, {}), 'cf': proxies.get(p.group, {}),
                'provider': providers.get(p.provider, {}), 'global': proxies.get('GLOBAL', {}).get('now')}

    def delay(self, name, url, timeout_ms, provider=None):
        if provider:
            route = '/providers/proxies/' + quote(provider, safe='') + '/' + quote(name, safe='') + '/healthcheck'
        else:
            route = '/proxies/' + quote(name, safe='') + '/delay'
        value = self.request('GET', route + '?' + urlencode({'url': url, 'timeout': timeout_ms, 'expected': '204'}),
                             timeout=timeout_ms / 1000 + 2, probe=True)
        delay = value.get('delay') if isinstance(value, dict) else None
        return float(delay) if type(delay) in (int, float) and math.isfinite(delay) and 0 < delay <= timeout_ms else None

    def measure(self, name, url, timeout_ms, cancelled=lambda: False):
        from .latency import measure_pair
        ports = getattr(self, 'probe_ports', {})
        if name not in ports:
            raise ControllerError('独立双指标探测端口不可用')
        self.request('GET', '/version', timeout=1)
        try:
            result = measure_pair(ports[name], url, timeout_ms, cancelled)
        except ConnectionRefusedError:
            raise ControllerError('独立测试代理不可用') from None
        if result['first_request'] is None:
            self.request('GET', '/version', timeout=1)
        return result

    def select(self, group, name):
        self.request('PUT', '/proxies/' + quote(group, safe=''), {'name': name})

    def update(self, provider):
        self.request('PUT', '/providers/proxies/' + quote(provider, safe=''), timeout=8)

    def connections(self):
        return self.request('GET', '/connections', timeout=3).get('connections', [])


def guard(snapshot, p):
    outer, cf, provider = snapshot.get('outer', {}), snapshot.get('cf', {}), snapshot.get('provider', {})
    expected = {p.group} | ({f'直连 · {p.id}'} if p.direct else set())
    if (outer.get('type') != 'Selector' or cf.get('type') != 'Selector'
            or set(outer.get('all', [])) != expected or provider.get('vehicleType', '').lower() != 'file'):
        return 'other_profile', None
    mode = snapshot.get('mode', '').lower()
    if mode not in ('rule', 'global') or (mode == 'global' and snapshot.get('global') != p.outer):
        return 'paused', None
    if outer.get('now') != p.group:
        return 'paused', None
    current = cf.get('now')
    if current not in cf.get('all', []):
        return 'paused', None
    return 'cf', current


class Activity:
    def __init__(self):
        self.previous = {}
        self.last_busy = None

    def busy(self, rows, p, now, idle_seconds):
        relevant = {r.get('id'): (r.get('upload', 0) + r.get('download', 0)) for r in rows
                    if p.group in r.get('chains', []) or p.outer in r.get('chains', [])}
        # First observation and new connections are conservative, as their history is unknown.
        if self.last_busy is None or any(k not in self.previous or v != self.previous[k] for k, v in relevant.items()):
            self.last_busy = now
        self.previous = relevant
        return now - self.last_busy < idle_seconds


class NodePool:
    def __init__(self, folder, profile, provider_path=None):
        self.folder, self.profile = Path(folder), profile
        self.manifest = self.folder / 'pool.json'
        self.journal = self.folder / 'pool-transaction.json'
        self.provider_path = Path(provider_path) if provider_path else verge_home() / 'providers' / 'cf-ai-manager' / profile.id / 'nodes.yaml'

    def validated(self, nodes):
        if not 2 <= len(nodes) <= self.profile.settings.max_pool:
            raise ValueError('动态池须有 2–20 条节点')
        rebuilt = [self.profile.node(n['server']) for n in nodes]
        if rebuilt != nodes or len({n['server'] for n in nodes}) != len(nodes):
            raise ValueError('节点池含不匹配参数或重复地址')
        return nodes

    def nodes(self):
        value = read_json(self.manifest, {'fingerprint': self.profile.fingerprint(), 'nodes': []})
        if value.get('fingerprint') != self.profile.fingerprint():
            raise ValueError('节点模板已变化，请重新优选并生成动态配置')
        nodes = value['nodes']
        return self.validated(nodes) if nodes else []

    def save_manifest(self, nodes):
        atomic_json(self.manifest, {'fingerprint': self.profile.fingerprint(), 'nodes': self.validated(nodes)})

    def initialize(self, nodes):
        nodes = self.validated(nodes)
        # Explicit generation is allowed only after the service confirms this profile is inactive.
        # Supersede any old interrupted publication BEFORE touching provider/manifest, so recovery
        # cannot silently restore an unrelated older template or pool after this operation.
        atomic_json(self.journal, {'old': nodes, 'new': nodes})
        atomic_json(self.provider_path, {'proxies': nodes})
        self.save_manifest(nodes)
        self.journal.unlink(missing_ok=True)

    def recover(self, api):
        if self.journal.exists():
            tx = read_json(self.journal)
            old, new = self.validated(tx['old']), self.validated(tx['new'])
            snapshot = api.snapshot(self.profile)
            state, current = guard(snapshot, self.profile)
            if state == 'other_profile':
                return
            actual = set(snapshot['cf'].get('all', []))
            # The new pool was loaded and the user may be using a new member: commit it.
            if actual == {n['name'] for n in new}:
                chosen = new
            elif current is None or current in {n['name'] for n in old}:
                chosen = old
            else:
                raise ControllerError('事务恢复暂缓：保留当前用户选择')
            atomic_json(self.provider_path, {'proxies': chosen})
            self.save_manifest(chosen)
            api.update(self.profile.provider)
            check = api.snapshot(self.profile)
            if set(check['cf'].get('all', [])) != {n['name'] for n in chosen}:
                raise ControllerError('节点池恢复等待内核确认')
            self.journal.unlink()
        expected = self.nodes()
        if expected:
            snapshot = api.snapshot(self.profile)
            if guard(snapshot, self.profile)[0] != 'other_profile' and set(snapshot['cf'].get('all', [])) != {n['name'] for n in expected}:
                current = snapshot['cf'].get('now')
                if current and current not in {n['name'] for n in expected}:
                    raise ControllerError('节点池成员变化，当前选择未在本机池中；请重新接入')
                atomic_json(self.provider_path, {'proxies': expected})
                api.update(self.profile.provider)

    def publish(self, api, nodes, unchanged):
        self.validated(nodes)
        old = self.nodes()
        if not unchanged():
            raise ControllerError('配置或手动选择已变化，取消发布')
        atomic_json(self.journal, {'old': old, 'new': nodes})
        atomic_json(self.provider_path, {'proxies': nodes})
        try:
            if not unchanged():
                raise ControllerError('配置或选择已变化')
            api.update(self.profile.provider)
            snapshot = api.snapshot(self.profile)
            if guard(snapshot, self.profile)[0] == 'other_profile' or set(snapshot['cf'].get('all', [])) != {n['name'] for n in nodes}:
                raise ControllerError('节点池刷新尚未确认')
            self.save_manifest(nodes)
            self.journal.unlink()
        except Exception:
            # Let startup reconciliation adopt an already loaded new pool, preserving manual selection.
            atomic_json(self.provider_path, {'proxies': old})
            self.save_manifest(old)
            raise
