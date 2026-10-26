from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field, fields
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import tempfile
import uuid


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except FileNotFoundError:
        return copy.deepcopy(default)


def public_ip(value):
    address = ipaddress.IPv4Address(value)
    if not address.is_global:
        raise ValueError('请输入公网 IPv4 地址')
    return str(address)


SCORING_FIELDS = {'latency_reference', 'first_request_reference', 'jitter_reference', 'bandwidth_floor',
                  'weight_success', 'weight_latency', 'weight_first_request', 'weight_jitter', 'weight_bandwidth'}


@dataclass
class Settings:
    poll_seconds: int = 15
    backup_seconds: int = 60
    timeout_ms: int = 5000
    confirmation_seconds: int = 3
    failure_rounds: int = 2
    recovery_rounds: int = 3
    window_seconds: int = 600
    fresh_seconds: int = 90
    advantage_points: float = 10
    leading_rounds: int = 3
    cooldown_seconds: int = 1800
    idle_seconds: int = 60
    protect_activity: bool = True
    sample_count: int = 256
    tcp_workers: int = 8
    validation_candidates: int = 12
    validation_workers: int = 2
    validation_interval: int = 10
    download_candidates: int = 6
    download_bytes: int = 1_000_000
    download_rounds: int = 3
    warmup_bytes: int = 128_000
    budget_bytes: int = 30_000_000
    download_timeout: int = 15
    bandwidth_floor: float = 2
    maximum_cv: float = 0.45
    bandwidth_ttl: int = 21600
    target_pool: int = 8
    max_pool: int = 20
    export_count: int = 5
    export_ttl: int = 86400
    daily_seconds: int = 86400
    replenish_seconds: int = 900
    background_bandwidth: bool = False
    latency_share: float = 0.5
    history_share: float = 0.25
    latency_reference: float = 300
    first_request_reference: float = 1500
    jitter_reference: float = 100
    weight_success: float = 60
    weight_latency: float = 15
    weight_first_request: float = 5
    weight_jitter: float = 15
    weight_bandwidth: float = 5
    probe_urls: list = field(default_factory=lambda: ['https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204'])
    download_url: str = 'https://speed.cloudflare.com/__down'
    stream_url: str = ''
    stream_seconds: int = 60
    stream_idle_seconds: int = 15

    def validate(self):
        from urllib.parse import urlsplit
        integer_limits = {
            'poll_seconds': (5, 3600), 'backup_seconds': (10, 3600), 'timeout_ms': (1000, 30000),
            'confirmation_seconds': (0, 30), 'failure_rounds': (1, 10), 'recovery_rounds': (2, 20),
            'window_seconds': (60, 86400), 'fresh_seconds': (20, 7200), 'leading_rounds': (2, 20),
            'cooldown_seconds': (60, 86400), 'idle_seconds': (5, 3600), 'sample_count': (16, 2048),
            'tcp_workers': (1, 32), 'validation_candidates': (2, 40), 'validation_workers': (1, 4),
            'validation_interval': (0, 60), 'download_candidates': (1, 20), 'download_bytes': (64000, 20_000_000),
            'download_rounds': (2, 5), 'warmup_bytes': (0, 1_000_000), 'budget_bytes': (100000, 500_000_000),
            'download_timeout': (3, 120), 'bandwidth_ttl': (300, 86400), 'target_pool': (2, 20),
            'max_pool': (2, 20), 'export_count': (1, 20), 'export_ttl': (300, 86400),
            'daily_seconds': (3600, 604800), 'replenish_seconds': (300, 86400),
            'stream_seconds': (10, 600), 'stream_idle_seconds': (2, 120)}
        for key, (minimum, maximum) in integer_limits.items():
            value = getattr(self, key)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f'{key} 必须是 {minimum}–{maximum} 之间的整数')
        for key in ('protect_activity', 'background_bandwidth'):
            if type(getattr(self, key)) is not bool:
                raise ValueError(f'{key} 必须是开关值')
        for key in ('advantage_points', 'bandwidth_floor', 'maximum_cv', 'latency_share', 'history_share',
                    'latency_reference', 'first_request_reference', 'jitter_reference', 'weight_success', 'weight_latency',
                    'weight_first_request', 'weight_jitter', 'weight_bandwidth'):
            value = getattr(self, key)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f'{key} 必须是非负有限数字')
        if self.fresh_seconds < self.backup_seconds + self.timeout_ms / 1000 * 2:
            raise ValueError('备用新鲜期须覆盖备用探测周期及两次请求超时')
        if self.window_seconds < self.fresh_seconds or self.target_pool > self.max_pool:
            raise ValueError('统计窗口或节点池上下限不合理')
        if (self.latency_share + self.history_share > 1 or self.bandwidth_floor <= 0
                or self.latency_reference <= 0 or self.first_request_reference <= 0 or self.jitter_reference <= 0 or not 0 < self.maximum_cv <= 2
                or self.advantage_points > 100):
            raise ValueError('评分参考值、波动或候选比例不合理')
        if self.weight_success + self.weight_latency + self.weight_first_request + self.weight_jitter <= 0:
            raise ValueError('连通性评分权重总和必须大于零')
        if self.budget_bytes < self.download_bytes + self.warmup_bytes:
            raise ValueError('流量预算不足以完成一次下载与预热')
        if not isinstance(self.probe_urls, list) or len(set(self.probe_urls)) < 2:
            raise ValueError('需要至少两个不同的 HTTPS 探测地址')
        for url in [*self.probe_urls, self.download_url, *([self.stream_url] if self.stream_url else [])]:
            parts = urlsplit(url)
            if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
                raise ValueError('探测地址必须是无内嵌凭据的 HTTPS URL')
        return self

    @classmethod
    def from_dict(cls, value):
        known = {f.name for f in fields(cls)}
        if not isinstance(value, dict) or set(value) - known:
            raise ValueError('设置含未知字段或结构错误')
        return cls(**value).validate()

    def preset(self, name):
        other = Settings()
        if name == 'multimodal':
            other.bandwidth_floor = 10
            other.weight_success, other.weight_latency, other.weight_first_request, other.weight_jitter, other.weight_bandwidth = 50, 12, 5, 13, 20
        elif name != 'ai':
            raise ValueError('未知预设')
        return other


@dataclass
class Profile:
    name: str
    domain: str
    credential: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    vps_ip: str = ''
    protocol: str = 'vless'
    port: int = 8443
    path: str = '/'
    sni: str = ''
    host: str = ''
    controller: str = ''
    secret: str = ''
    direct: dict | None = None
    managed: bool = False
    optimize: bool = False
    settings: Settings = field(default_factory=Settings)

    @property
    def provider(self):
        return f'CFAI-{self.id}'

    @property
    def group(self):
        return f'CF · {self.id}'

    @property
    def outer(self):
        return f'AI · {self.id}'

    def validate(self):
        if not re.fullmatch(r'[a-f0-9]{12}', self.id):
            raise ValueError('配置 ID 无效')
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 80:
            raise ValueError('请输入 1–80 字的线路名称')
        for domain in [self.domain, self.sni or self.domain, self.host or self.domain]:
            if not isinstance(domain, str) or not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', domain) or '.' not in domain:
                raise ValueError('请输入有效域名（不含 https:// 或路径）')
        if self.protocol not in ('vless', 'vmess', 'trojan'):
            raise ValueError('仅支持 VLESS / VMess / Trojan 的 WS+TLS')
        if self.protocol != 'trojan':
            try:
                if uuid.UUID(self.credential).int == 0:
                    raise ValueError()
            except (ValueError, AttributeError):
                raise ValueError('请输入有效的非零 UUID') from None
        elif not isinstance(self.credential, str) or not self.credential.strip():
            raise ValueError('请输入 Trojan 密码')
        if type(self.port) is not int or self.port not in (443, 2053, 2083, 2087, 2096, 8443):
            raise ValueError('端口须为 Cloudflare HTTPS 入口端口')
        if not self.path.startswith('/') or any(c in self.path for c in '\r\n'):
            raise ValueError('WebSocket 路径必须以 / 开始且不能包含换行')
        if self.vps_ip:
            public_ip(self.vps_ip)
        if self.controller:
            from .clash import validate_controller
            validate_controller(self.controller)
        if self.direct is not None and (not isinstance(self.direct, dict) or not self.direct.get('type') or not self.direct.get('server')):
            raise ValueError('直连模板须为一个有效 Mihomo 节点对象')
        if type(self.managed) is not bool or type(self.optimize) is not bool:
            raise ValueError('管理策略必须是开关值')
        self.settings.validate()
        return self

    def node(self, ip):
        ip = public_ip(ip)
        result = {'name': f'CF-{ip}', 'type': self.protocol, 'server': ip, 'port': self.port,
                  'network': 'ws', 'udp': True, 'ws-opts': {'path': self.path, 'headers': {'Host': self.host or self.domain}}}
        if self.protocol == 'trojan':
            result.update(password=self.credential, sni=self.sni or self.domain)
        else:
            result.update(uuid=self.credential, tls=True, servername=self.sni or self.domain)
            if self.protocol == 'vmess':
                result.update(alterId=0, cipher='auto')
        return result

    def fingerprint(self):
        payload = self.node('104.16.1.1')
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def measurement_key(self):
        settings = {k: v for k, v in asdict(self.settings).items() if k not in SCORING_FIELDS}
        return hashlib.sha256(json.dumps([2, self.fingerprint(), settings], sort_keys=True).encode()).hexdigest()

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        value = copy.deepcopy(value)
        value['settings'] = Settings.from_dict(value.get('settings', {}))
        return cls(**value).validate()


class Store:
    def __init__(self, root=None):
        self.root = Path(root) if root else Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'CFAIManager'
        self.root.mkdir(parents=True, exist_ok=True)
        self.recovery_note = ''

    def protect(self):
        """Restrict credential directory to its user and SYSTEM; never alters global security settings."""
        if os.name != 'nt':
            self.root.chmod(0o700)
            return
        import subprocess
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, timeout=5, creationflags=flags)
        match = re.search(r'S-1-5-\d+(?:-\d+)+', identity.stdout.decode('utf-8', 'replace'))
        if identity.returncode or not match:
            raise ValueError('无法确认本机用户身份，未开始保存凭据')
        result = subprocess.run(['icacls', str(self.root), '/inheritance:r', '/grant:r',
            f'*{match.group()}:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'], capture_output=True, timeout=5, creationflags=flags)
        if result.returncode:
            raise ValueError('无法保护本机凭据目录，请选择当前用户可写的数据目录')

    def folder(self, instance):
        if not re.fullmatch(r'[a-f0-9]{12}', instance):
            raise ValueError('实例 ID 无效')
        folder = self.root / 'instances' / instance
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def profiles(self):
        def decode(document):
            if not isinstance(document, dict) or document.get('schema') != 1:
                raise ValueError('配置版本不受支持；原文件保留')
            profiles = [Profile.from_dict(p) for p in document['profiles']]
            if len({p.id for p in profiles}) != len(profiles):
                raise ValueError('配置 ID 重复')
            return profiles
        destination = self.root / 'profiles.json'
        try:
            return decode(read_json(destination, {'schema': 1, 'profiles': []}))
        except (ValueError, KeyError, TypeError):
            backup = self.root / 'profiles.last-good.json'
            if not backup.exists():
                raise ValueError('配置损坏且没有有效备份，原文件已保留') from None
            document = read_json(backup)
            profiles = decode(document)
            import shutil
            shutil.copy2(destination, self.root / ('profiles.corrupt-' + uuid.uuid4().hex[:8] + '.json'))
            # Recovery is conservative: user explicitly re-enables monitoring after inspecting the restored profile.
            for p in profiles:
                p.managed = False
            atomic_json(destination, {'schema': 1, 'profiles': [p.to_dict() for p in profiles]})
            self.recovery_note = '主配置损坏，已恢复最后可用备份；动态管理已关闭，原损坏文件保留'
            return profiles

    def save_profiles(self, profiles):
        for p in profiles:
            p.validate()
        if len({p.id for p in profiles}) != len(profiles):
            raise ValueError('配置 ID 重复')
        destination = self.root / 'profiles.json'
        if destination.exists():
            atomic_json(self.root / 'profiles.last-good.json', read_json(destination))
        atomic_json(destination, {'schema': 1, 'profiles': [p.to_dict() for p in profiles]})

    def results(self, p):
        document = read_json(self.folder(p.id) / 'results.json', {})
        if document.get('fingerprint') != p.fingerprint():
            return []
        if document.get('measurement_key') == p.measurement_key():
            from .health import rank_results
            return rank_results(document.get('rows', []), p.settings)
        # Previous releases measured cold requests only. Keep the real cold values visible,
        # but never reinterpret them as connection latency or retain their old score.
        legacy = asdict(p.settings)
        for key in ('first_request_reference', 'weight_first_request'):
            legacy.pop(key)
        legacy_key = hashlib.sha256(json.dumps([p.fingerprint(), legacy], sort_keys=True).encode()).hexdigest()
        if document.get('measurement_key') == legacy_key:
            rows = copy.deepcopy(document.get('rows', []))
            for row in rows:
                row.update(first_request=row.get('median'), first_request_samples=row.get('samples', []),
                           latency_samples=[None] * len(row.get('samples', [])), median=None, jitter=None,
                           score=None, legacy_measurement=True)
            return rows
        return []

    def save_results(self, p, rows, network):
        atomic_json(self.folder(p.id) / 'results.json', {'fingerprint': p.fingerprint(), 'measurement_key': p.measurement_key(), 'network': list(network), 'rows': rows})
