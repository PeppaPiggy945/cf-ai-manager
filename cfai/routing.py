"""Shared, offline export routing. No live controller or user profile is modified."""
from functools import lru_cache
import hashlib
import ipaddress
import json
from pathlib import Path
import sys


AI_DOMAINS = ('openai.com', 'chatgpt.com', 'oaiusercontent.com', 'oaistatic.com', 'oaist.com',
              'ai.com', 'anthropic.com', 'claude.ai', 'googleapis.com', 'gemini.google.com',
              'generativelanguage.googleapis.com', 'aistudio.google.com')
# Domestic publisher/login/CDN domains also cover endpoints hosted outside CN ranges.
GAME_DOMAINS = ('cn', 'qq.com', 'gtimg.com', 'qcloud.com', 'myqcloud.com', 'tencent.com',
                'tencentgames.com', 'wegame.com', 'wegame.com.cn', 'netease.com', '163.com',
                '126.net', '127.net', 'netease.im', 'mihoyo.com', 'miyoushe.com',
                'biligame.com', 'biligame.net', 'bilibili.com', 'hdslb.com', 'wanmei.com',
                'perfectworld.com', 'xoyo.com', 'kingsoft.com', '4399.com', '4399api.com',
                '7k7k.com', 'taptap.com', 'xd.com')
PRIVATE_RANGES = ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                  '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4',
                  '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')


@lru_cache(maxsize=1)
def china_snapshot():
    base = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])) / 'resources' / 'routing'
    manifest = json.loads((base / 'manifest.json').read_text(encoding='utf-8'))
    payload = []
    for name in ('china.txt', 'china6.txt'):
        data = (base / name).read_bytes()
        meta = manifest['files'][name]
        if hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('国内直连网段资源校验失败，请重新解压完整便携包')
        networks = [ipaddress.ip_network(x) for x in data.decode('ascii').splitlines() if x.strip()]
        if len(networks) != meta['count'] or not all(n.is_global and n.prefixlen > 0 for n in networks):
            raise ValueError('国内直连网段资源格式错误')
        payload.extend(map(str, networks))
    license_data = (base / 'LICENSE.txt').read_bytes()
    if hashlib.sha256(license_data).hexdigest() != manifest['license_sha256']:
        raise ValueError('国内直连网段授权资源校验失败')
    return tuple(payload), manifest['source'], manifest['snapshot_date'], license_data.decode('utf-8')


def routing_config(settings, proxy):
    rules = [f'IP-CIDR,{cidr},DIRECT,no-resolve' for cidr in PRIVATE_RANGES]
    # AI domains win over broad CN CDN/IP classification. Reject QUIC first so browsers
    # can retry over TCP instead of attempting unsupported UDP over a WS tunnel.
    for domain in AI_DOMAINS:
        if settings.reject_foreign_quic:
            rules.append(f'AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,{domain})),REJECT')
        rules.append(f'DOMAIN-SUFFIX,{domain},{proxy}')
    rules.extend(f'PROCESS-NAME,{name},DIRECT' for name in dict.fromkeys(settings.extra_direct_processes))
    domains = list(GAME_DOMAINS) if settings.direct_china else []
    domains.extend(settings.extra_direct_domains)
    rules.extend(f'DOMAIN-SUFFIX,{domain.lower()},DIRECT' for domain in dict.fromkeys(domains))
    result = {}
    if settings.direct_stun:
        rules.append('AND,((NETWORK,UDP),(DST-PORT,3478)),DIRECT')
    if settings.direct_china:
        payload, source, snapshot, license_text = china_snapshot()
        result['rule-providers'] = {'CFAI-CN': {'type': 'inline', 'behavior': 'ipcidr', 'payload': list(payload)}}
        # Deliberately resolve domains here; no-resolve would miss game hosts outside the explicit list.
        rules.append('RULE-SET,CFAI-CN,DIRECT')
        result['cfai-routing-info'] = {'source': source, 'snapshot': snapshot, 'license': license_text}
    # CN rules precede this rejection, preserving domestic QUIC/game UDP/443.
    if settings.reject_foreign_quic:
        rules.append('AND,((NETWORK,UDP),(DST-PORT,443)),REJECT')
    rules.append(f'MATCH,{proxy}')
    result['rules'] = rules
    return result
