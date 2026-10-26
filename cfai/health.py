from __future__ import annotations
import math
import statistics


class History:
    def __init__(self):
        self.samples = {}
        self.bandwidth = {}

    def record(self, name, delay, at):
        if delay is not None and (not math.isfinite(delay) or delay <= 0):
            raise ValueError('无效探测耗时')
        self.samples.setdefault(name, []).append({'at': at, 'delay': delay})
        self.samples[name] = self.samples[name][-2000:]

    def stats(self, name, s, now):
        rows = [r for r in self.samples.get(name, []) if now - s.window_seconds <= r['at'] <= now]
        successes = [r['delay'] for r in rows if r['delay'] is not None]
        median = statistics.median(successes) if successes else None
        jitter = statistics.median(abs(x - median) for x in successes) if successes else None
        streak = failed = 0
        for r in reversed(rows):
            if r['delay'] is None:
                break
            streak += 1
        for r in reversed(rows):
            if r['delay'] is not None:
                break
            failed += 1
        fresh = bool(rows) and now - rows[-1]['at'] <= s.fresh_seconds
        bw = self.bandwidth.get(name, {})
        mbps = bw.get('mbps') if 0 <= now - bw.get('at', -1e20) <= s.bandwidth_ttl else None
        return {'samples': len(rows), 'rate': len(successes) / len(rows) if rows else 0,
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
                        h.record(name, row.get('delay'), row['at'])
                    except (ValueError, TypeError):
                        pass
        for name, row in value.get('bandwidth', {}).items():
            if isinstance(row, dict) and all(type(row.get(k)) in (int, float) and math.isfinite(row[k]) and row[k] > 0 for k in ('at', 'mbps')):
                h.bandwidth[name] = row
        return h


def scores(history, names, s, now):
    result = {name: history.stats(name, s, now) for name in names}
    use_bw = bool(result) and all(r['mbps'] is not None for r in result.values())
    for row in result.values():
        row.update(score=None, bandwidth_used=use_bw)
        if not row['fresh'] or row['samples'] < s.recovery_rounds or row['median'] is None:
            continue
        parts = [(s.weight_success, row['rate']), (s.weight_latency, 1 / (1 + row['median'] / s.latency_reference)),
                 (s.weight_jitter, 1 / (1 + row['jitter'] / s.jitter_reference))]
        if use_bw:
            parts.append((s.weight_bandwidth, min(row['mbps'] / s.bandwidth_floor, 1)))
        row['score'] = round(100 * sum(w * x for w, x in parts) / sum(w for w, _ in parts), 2)
    return result


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
