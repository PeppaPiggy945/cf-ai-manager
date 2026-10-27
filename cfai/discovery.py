"""Bounded per-network tunnel evidence and exploratory Cloudflare address sampling."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import statistics
import time

from .config import atomic_json, read_json

RETENTION = 30 * 86400
HALF_LIFE = 7 * 86400
EXPLORATION_SHARE = .30


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


class PrefixLearning:
    def __init__(self, path, profile, network_identity, now=None):
        self.path = Path(path)
        self.now = time.time() if now is None else now
        # Sampling size and score/export settings do not change the measurement context.
        context = [1, list(network_identity), profile.fingerprint(),
                   profile.settings.probe_urls[:2], profile.settings.timeout_ms]
        self.key = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
        self.contexts = self._load()
        self.state = self.contexts.get(self.key, {'at': self.now, 'evidence': {},
                                                 'cursors': {}, 'explore_cursor': 0})

    def _load(self):
        try:
            if self.path.exists() and self.path.stat().st_size > 2_000_000:
                return {}
            doc = read_json(self.path, {})
        except (OSError, ValueError, TypeError):
            return {}
        if not isinstance(doc, dict) or doc.get('schema') != 1 or not isinstance(doc.get('contexts'), dict):
            return {}
        result = {}
        for key, value in doc['contexts'].items():
            if (len(key) != 64 or any(c not in '0123456789abcdef' for c in key)
                    or not isinstance(value, dict) or not _number(value.get('at'))
                    or not 0 <= self.now - value['at'] <= RETENTION):
                continue
            evidence, cursors = {}, {}
            raw = value.get('evidence', {})
            for prefix, rows in (raw.items() if isinstance(raw, dict) else []):
                try:
                    net = ipaddress.IPv4Network(prefix)
                except ValueError:
                    continue
                if not isinstance(rows, list):
                    continue
                clean = [r for r in rows if isinstance(r, dict)
                         and all(_number(r.get(k)) for k in ('at', 'quality', 'accepted'))
                         and 0 <= self.now - r['at'] <= RETENTION
                         and 0 <= r['quality'] <= 1 and 0 <= r['accepted'] <= 1]
                if clean:
                    evidence[str(net)] = [{k: r[k] for k in ('at', 'quality', 'accepted')}
                                          for r in sorted(clean, key=lambda r: r['at'])[-32:]]
            raw = value.get('cursors', {})
            for prefix, cursor in (raw.items() if isinstance(raw, dict) else []):
                try:
                    net = ipaddress.IPv4Network(prefix)
                except ValueError:
                    continue
                if type(cursor) is int and 0 <= cursor <= 10**16:
                    cursors[str(net)] = cursor
            explore = value.get('explore_cursor', 0)
            result[key] = {'at': value['at'], 'evidence': dict(list(evidence.items())[:64]),
                           'cursors': dict(list(cursors.items())[:64]),
                           'explore_cursor': explore if type(explore) is int and 0 <= explore <= 10**16 else 0}
        return dict(sorted(result.items(), key=lambda pair: pair[1]['at'])[-8:])

    def scores(self, ranges):
        result = {}
        for net in ranges:
            evidence = [(r, 2 ** (-(self.now - r['at']) / HALF_LIFE))
                        for r in self.state['evidence'].get(str(net), [])
                        if 0 <= self.now - r['at'] <= RETENTION]
            weight = sum(w for _, w in evidence)
            result[str(net)] = {'score': round((1 + sum(r['quality'] * w for r, w in evidence)) / (2 + weight), 8),
                                'effective_batches': round(weight, 8),
                                'success_evidence': round(sum(r['accepted'] * w for r, w in evidence), 8)}
        return result

    def plan(self, ranges, excluded, seeds, count):
        scores = self.scores(ranges)
        preferred = sorted([n for n in ranges if scores[str(n)]['success_evidence'] > 0
                            and scores[str(n)]['score'] > .5],
                           key=lambda n: -scores[str(n)]['score'])[:3]
        reserve = math.ceil(count * EXPLORATION_SHARE)
        seed_limit = count - reserve
        valid_seeds = []
        for ip in seeds:
            try:
                address = ipaddress.IPv4Address(ip)
            except (ValueError, TypeError):
                continue
            if any(address in net for net in ranges) and str(address) not in valid_seeds:
                valid_seeds.append(str(address))
        ips = valid_seeds[:seed_limit]
        # Even seeds beyond the retest quota are known addresses, never fresh exploration.
        seen = set(excluded) | set(valid_seeds)
        by_prefix = {str(net): dict(scores[str(net)], sampled=0, preferred=0, exploration=0, reused=0)
                     for net in ranges}
        for ip in ips:
            net = next(n for n in ranges if ipaddress.IPv4Address(ip) in n)
            by_prefix[str(net)]['reused'] += 1
        exhausted = set()
        cursors = self.state['cursors']

        def draw(net):
            key = str(net)
            if key in exhausted:
                return None
            index = cursors.get(key, 0)
            offset = int.from_bytes(hashlib.sha256(key.encode()).digest()[:4], 'big')
            for _ in range(min(net.num_addresses, 2 * len(seen) + 256)):
                position = (index * 2654435761 + offset) % net.num_addresses
                index += 1
                ip = str(net.network_address + position)
                if ip not in seen and position % 256 not in (0, 255):
                    cursors[key] = index
                    seen.add(ip)
                    return ip
            cursors[key] = index
            exhausted.add(key)
            return None

        exploration = []
        def explore():
            for _ in ranges:
                index = self.state['explore_cursor']
                self.state['explore_cursor'] = index + 1
                net = ranges[index % len(ranges)]
                ip = draw(net)
                if ip:
                    ips.append(ip)
                    exploration.append(ip)
                    by_prefix[str(net)]['exploration'] += 1
                    return True
            return False

        # Allocate fresh exploration before allowing old seeds or preferred prefixes to fill the rest.
        for _ in range(reserve):
            if not explore():
                break
        preferred_count = 0
        while len(ips) < count:
            available = [n for n in preferred if str(n) not in exhausted]
            if not available:
                if not explore():
                    break
                continue
            net = min(available, key=lambda n: (by_prefix[str(n)]['preferred'] + 1) / scores[str(n)]['score']**2)
            ip = draw(net)
            if ip:
                ips.append(ip)
                by_prefix[str(net)]['preferred'] += 1
                preferred_count += 1
        for row in by_prefix.values():
            row['sampled'] = row['preferred'] + row['exploration'] + row['reused']
        return ips, {'preferred': preferred_count, 'exploration': len(exploration), 'reused': len(valid_seeds[:seed_limit]),
                     'exploration_ips': exploration, 'prefixes': by_prefix,
                     'mode': 'learned' if preferred_count else 'balanced'}

    def validation_order(self, rows, ranges):
        scores = self.scores(ranges)
        # Lesser-observed prefixes get first access to the validation exploration reserve.
        return sorted(rows, key=lambda r: (scores[str(next(n for n in ranges if ipaddress.IPv4Address(r['ip']) in n))]['effective_batches'],
                                           r['median_ms']))

    def record(self, rows, ranges):
        grouped = defaultdict(list)
        seen = set()
        for row in rows:
            if row['ip'] in seen:
                continue
            seen.add(row['ip'])
            values = row.get('first_request_samples', [])
            if len(values) != 6 or any(v is not None and (not _number(v) or v <= 0) for v in values):
                continue
            net = next((n for n in ranges if ipaddress.IPv4Address(row['ip']) in n), None)
            if net is None:
                continue
            accepted = sum(v is not None for v in values) >= 5 and all(v is not None for v in values[-2:])
            quality = 0
            if accepted:
                cold = statistics.median(v for v in values if v is not None)
                parts = [1 / (1 + cold / 1500)]
                warm = [v for v in row.get('latency_samples', []) if _number(v) and v > 0]
                if warm:
                    parts += [1 / (1 + statistics.median(warm) / 300),
                              1 / (1 + statistics.pstdev(warm) / 100)]
                quality = .8 + .2 * statistics.fmean(parts)
            grouped[str(net)].append((float(accepted), quality))
        for prefix, values in grouped.items():
            history = [r for r in self.state['evidence'].get(prefix, []) if 0 <= self.now - r['at'] <= RETENTION]
            history.append({'at': self.now, 'accepted': statistics.fmean(v[0] for v in values),
                            'quality': statistics.fmean(v[1] for v in values)})
            self.state['evidence'][prefix] = history[-32:]

    def save(self):
        self.state['at'] = self.now
        self.contexts[self.key] = self.state
        contexts = dict(sorted(self.contexts.items(), key=lambda pair: pair[1]['at'])[-8:])
        atomic_json(self.path, {'schema': 1, 'contexts': contexts})
