import copy
from pathlib import Path
import time
import yaml


def select_results(rows, count, now=None, ttl=86400, ips=None):
    now = time.time() if now is None else now
    valid = []
    for row in rows:
        pair = row.get('samples', [])
        if (row.get('accepted') and 0 <= now - row.get('validated_at', 0) <= ttl
                and len(pair) == 6 and sum(x is not None for x in pair) >= 5
                and all(x is not None for x in pair[-2:]) and (ips is None or row['ip'] in ips)):
            valid.append(row)
    valid.sort(key=lambda r: -(r.get('score') or 0))
    result = valid[:count]
    if not result:
        raise ValueError('没有在有效期内通过真实验证的节点，请先优选')
    return result


def static_config(profile, rows, provider_only=False, strategy='select'):
    if strategy not in ('select', 'fallback', 'url-test'):
        raise ValueError('导出策略无效')
    nodes = [profile.node(r['ip']) for r in rows]
    if not nodes:
        raise ValueError('没有可导出的节点')
    if provider_only:
        return {'proxies': nodes}
    group = {'name': 'AI', 'type': strategy, 'proxies': [n['name'] for n in nodes]}
    if strategy != 'select':
        group.update(url=profile.settings.probe_urls[0], interval=300)
    return {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
            'proxies': nodes, 'proxy-groups': [group], 'rules': ['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
            'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve', 'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
            'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve', 'MATCH,AI']}


def write_yaml(path, data):
    from .config import atomic_json
    # JSON is also valid YAML; consistent atomic writes avoid partially exported credentials.
    atomic_json(path, data)


def dynamic_config(profile, provider_path):
    group = {'name': profile.group, 'type': 'select', 'use': [profile.provider]}
    outer = {'name': profile.outer, 'type': 'select', 'proxies': [profile.group]}
    nodes = []
    if profile.direct:
        direct = copy.deepcopy(profile.direct)
        direct['name'] = f'直连 · {profile.id}'
        nodes.append(direct)
        outer['proxies'].append(direct['name'])
    return {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
            'profile': {'store-selected': True}, 'proxies': nodes,
            'proxy-providers': {profile.provider: {'type': 'file', 'path': str(Path(provider_path).resolve()).replace('\\', '/'),
                'health-check': {'enable': False}}},
            'proxy-groups': [outer, group], 'rules': [f'MATCH,{profile.outer}']}
