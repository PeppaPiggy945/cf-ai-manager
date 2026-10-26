from __future__ import annotations
import math
import statistics
import copy
import time


class History:
    def __init__(self):
        self.samples = {}
        self.bandwidth = {}

    def record(self, name, delay, at, first_request=None):
        for value in (delay, first_request):
            if value is not None and (not math.isfinite(value) or value <= 0):
                raise ValueError('无效探测耗时')
        self.samples.setdefault(name, []).append({'at': at, 'delay': delay, 'first_request': first_request})
        self.samples[name] = self.samples[name][-2000:]

    def stats(self, name, s, now):
        rows = [r for r in self.samples.get(name, []) if now - s.window_seconds <= r['at'] <= now]
        successes = [r['delay'] for r in rows if r['delay'] is not None]
        first_values = [r['first_request'] for r in rows if r.get('first_request') is not None]
        def succeeded(row):
            return row['delay'] is not None or row.get('first_request') is not None
        median = statistics.median(successes) if successes else None
        jitter = statistics.median(abs(x - median) for x in successes) if successes else None
        streak = failed = 0
        for r in reversed(rows):
            if not succeeded(r):
                break
            streak += 1
        for r in reversed(rows):
            if succeeded(r):
                break
            failed += 1
        fresh = bool(rows) and now - rows[-1]['at'] <= s.fresh_seconds
        bw = self.bandwidth.get(name, {})
        mbps = bw.get('mbps') if 0 <= now - bw.get('at', -1e20) <= s.bandwidth_ttl else None
        return {'samples': len(rows), 'rate': sum(succeeded(r) for r in rows) / len(rows) if rows else 0,
                'latency_count': len(successes), 'first_request_count': len(first_values),
                'first_request': statistics.median(first_values) if first_values else None,
                'median': median, 'jitter': jitter, 'streak': streak, 'failed': failed, 'fresh': fresh,
                'last_at': rows[-1]['at'] if rows else 0, 'mbps': mbps}

    def dump(self):
        return {'samples': self.samples, 'bandwidth': self.bandwidth}

    @classmethod
    def restore(cls, value):
        h = cls()
        if not isinstance(value, dict):
            return h
        for name, rows in value.get('samples', {}).items():
            for row in rows[-2000:]:
                if isinstance(row, dict) and type(row.get('at')) in (int, float) and math.isfinite(row['at']):
                    try:
                        h.record(name, row.get('delay'), row['at'], row.get('first_request'))
                    except (ValueError, TypeError):
                        pass
        for name, row in value.get('bandwidth', {}).items():
            if isinstance(row, dict) and all(type(row.get(k)) in (int, float) and math.isfinite(row[k]) and row[k] > 0 for k in ('at', 'mbps')):
                h.bandwidth[name] = row
        return h


def scores(history, names, s, now):
    result = {name: history.stats(name, s, now) for name in names}
    eligible = [r for r in result.values() if r['fresh'] and r['samples'] >= s.recovery_rounds and r['rate'] > 0]
    use_latency = bool(eligible) and all(r['latency_count'] >= s.recovery_rounds for r in eligible)
    use_first = bool(eligible) and all(r['first_request_count'] >= s.recovery_rounds for r in eligible)
    use_bw = bool(eligible) and all(r['mbps'] is not None for r in eligible)
    for row in result.values():
        row.update(score=None, bandwidth_used=use_bw, latency_used=use_latency, first_request_used=use_first)
        if not row['fresh'] or row['samples'] < s.recovery_rounds or row['rate'] <= 0:
            continue
        parts = [(s.weight_success, row['rate'])]
        if use_latency:
            parts.extend([(s.weight_latency, 1 / (1 + row['median'] / s.latency_reference)),
                          (s.weight_jitter, 1 / (1 + row['jitter'] / s.jitter_reference))])
        if use_first:
            parts.append((s.weight_first_request, 1 / (1 + row['first_request'] / s.first_request_reference)))
        if use_bw:
            parts.append((s.weight_bandwidth, min(row['mbps'] / s.bandwidth_floor, 1)))
        total = sum(w for w, _ in parts)
        if total:
            row['score'] = round(100 * sum(w * x for w, x in parts) / total, 2)
    return result


def rank_results(rows, settings):
    """Reweight a saved batch without treating snapshot samples as live recovery evidence."""
    rows = copy.deepcopy(rows)
    history = History()
    times = [at for row in rows for at in row.get('sample_times', [row.get('validated_at', 0)])]
    anchor = max(times, default=0)
    snapshot = copy.deepcopy(settings)
    # Scan admission is fixed at three rounds / six URLs; live recovery can require more rounds.
    snapshot.recovery_rounds = 3
    span = anchor - min(times, default=anchor) + 1
    snapshot.fresh_seconds = max(snapshot.fresh_seconds, span)
    snapshot.window_seconds = max(snapshot.window_seconds, span)
    for row in rows:
        cold = row.get('first_request_samples', [])
        warm = row.get('latency_samples', [])
        for index, first in enumerate(cold):
            at = row.get('sample_times', [row.get('validated_at', anchor)] * len(cold))[index]
            history.record(row['ip'], warm[index] if index < len(warm) else None, at, first)
        bw = row.get('download', {}).get('mbps')
        bw_at = row.get('download', {}).get('at', row.get('validated_at', 0))
        if bw is not None and 0 <= time.time() - bw_at <= settings.bandwidth_ttl:
            history.bandwidth[row['ip']] = {'mbps': bw, 'at': anchor}
    ranked = scores(history, [r['ip'] for r in rows if r.get('accepted')], snapshot, anchor)
    for row in rows:
        raw = history.stats(row['ip'], snapshot, anchor)
        row.update(median=raw['median'], first_request=raw['first_request'], jitter=raw['jitter'], score=None)
        row.update({k: v for k, v in ranked.get(row['ip'], {}).items() if k != 'samples'})
    rows.sort(key=lambda r: (not r.get('accepted'), -(r.get('score') or 0)))
    return rows


class Policy:
    def __init__(self):
        self.pending = None
        self.wins = 0
        self.last_round = None
        self.last_optimization = -1e20

    def reset(self):
        self.pending, self.wins, self.last_round = None, 0, None

    def switched(self, now, reason):
        if reason == 'optimization':
            self.last_optimization = now
        self.reset()

    def decide(self, current, history, names, s, now, optimize, busy, hold):
        if hold:
            return None
        stats = scores(history, names, s, now)
        available = [(n, r) for n, r in stats.items() if n != current and r['score'] is not None and r['streak'] >= s.recovery_rounds]
        if not available:
            self.reset()
            return None
        target, best = max(available, key=lambda nr: nr[1]['score'])
        current_stats = stats.get(current, {})
        if current_stats.get('failed', 0) >= s.failure_rounds:
            return {'target': target, 'reason': 'failure'}
        if not optimize or current_stats.get('score') is None or best['score'] - current_stats['score'] < s.advantage_points:
            self.reset()
            return None
        # One vote per genuinely new candidate observation, never per UI/poll refresh.
        round_at = best['last_at']
        if target != self.pending:
            self.pending, self.wins, self.last_round = target, 1, round_at
        elif round_at != self.last_round:
            self.wins += 1
            self.last_round = round_at
        if self.wins < s.leading_rounds or busy or now - self.last_optimization < s.cooldown_seconds:
            return None
        return {'target': target, 'reason': 'optimization'}
