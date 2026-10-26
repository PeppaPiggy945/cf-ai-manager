"""Bounded downloads over a local test-core CONNECT proxy; no environment proxy use."""
import http.client
import random
import socket
import ssl
import statistics
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin


class Cancelled(Exception):
    pass


class Budget:
    def __init__(self, maximum):
        self.maximum, self.used, self.reserved = maximum, 0, 0

    def reserve(self, size):
        if size < 0 or self.used + self.reserved + size > self.maximum:
            raise ValueError('本次测速流量预算已用尽')
        self.reserved += size

    def consume(self, size):
        if size > self.reserved:
            raise ValueError('流量超过预留预算')
        self.used += size
        self.reserved -= size

    def release(self, size):
        if not 0 <= size <= self.reserved:
            raise ValueError('预算释放值无效')
        self.reserved -= size


def download(proxy_port, url, size, timeout, budget, cancelled=lambda: False):
    budget.reserve(size)
    received, started, ttfb = 0, time.perf_counter(), None
    code, error = 0, ''
    connection = None
    try:
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query))
        query.update(bytes=str(size), cfai=str(time.time_ns()))
        current = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ''))
        for redirects in range(4):
            if cancelled():
                raise Cancelled()
            p = urlsplit(current)
            if p.scheme != 'https' or not p.hostname or p.username or p.password:
                raise ValueError('测速重定向仅允许无凭据 HTTPS')
            remaining = timeout - (time.perf_counter() - started)
            if remaining <= 0:
                raise TimeoutError()
            connection = http.client.HTTPSConnection('127.0.0.1', proxy_port, timeout=min(remaining, 5), context=ssl.create_default_context())
            connection.set_tunnel(p.hostname, p.port or 443)
            connection.request('GET', urlunsplit(('', '', p.path or '/', p.query, '')),
                               headers={'Range': f'bytes=0-{size-1}', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache', 'Connection': 'close'})
            response = connection.getresponse()
            code = response.status
            if code in (301, 302, 303, 307, 308):
                current = urljoin(current, response.getheader('Location', ''))
                connection.close()  # Do not read redirect bodies or consume unbudgeted bytes.
                continue
            if code not in (200, 206):
                raise ValueError(f'HTTP {code}')
            while received < size:
                if cancelled():
                    raise Cancelled()
                remaining = timeout - (time.perf_counter() - started)
                if remaining <= 0:
                    raise TimeoutError()
                transport = connection.sock or getattr(getattr(response.fp, 'raw', None), '_sock', None)
                if transport:
                    transport.settimeout(min(remaining, 3))
                chunk = response.read1(min(16384, size - received))
                if not chunk:
                    break
                if ttfb is None:
                    ttfb = time.perf_counter() - started
                received += len(chunk)
                budget.consume(len(chunk))
            break
        else:
            raise ValueError('重定向次数过多')
        if received < size * .9:
            error = '响应体不足'
    except Cancelled:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        error = '下载失败或超时' if code in (0, 200, 206) else f'HTTP {code}'
    finally:
        if connection:
            connection.close()
        budget.release(size - received)
    elapsed = max(time.perf_counter() - started, .001)
    return {'ok': not error and received >= size * .9, 'bytes': received, 'mbps': received * 8 / elapsed / 1_000_000,
            'ttfb_ms': ttfb * 1000 if ttfb is not None else None, 'total_ms': elapsed * 1000, 'error': error}


def round_orders(names, rounds):
    base = list(dict.fromkeys(names))
    random.Random(42).shuffle(base)
    orders = []
    for index in range(rounds):
        offset = index * len(base) // rounds
        order = base[offset:] + base[:offset]
        orders.append(list(reversed(order)) if index % 2 else order)
    return orders


def summarize(rows, maximum_cv):
    good = [r['mbps'] for r in rows if r and r.get('ok')]
    mean = statistics.fmean(good) if good else 0
    cv = statistics.pstdev(good) / mean if mean else None
    valid = len(good) == len(rows) and len(rows) >= 2 and cv is not None and cv <= maximum_cv
    return {'mbps': mean if valid else None, 'cv': cv, 'rounds': rows,
            'successful': len(good), 'reason': '' if valid else '下载轮次失败或速度波动过大'}
