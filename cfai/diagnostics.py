"""Explicit user-owned stream diagnostic. Never sends AI credentials or prompts."""
import http.client
import socket
import ssl
import time
from urllib.parse import urlsplit

from .export import select_results
from .network import DirectNetwork
from .scanner import isolated_core
from .speed import Cancelled


def stream_diagnostic(p, rows, cancelled, event):
    selected = select_results(rows, 1, ttl=p.settings.export_ttl)
    network = DirectNetwork.discover()
    network.verify(None, selected[0]['ip'], p.port)
    deadline = time.monotonic() + p.settings.stream_seconds + 15
    with isolated_core([p.node(selected[0]['ip'])], network, cancelled, deadline) as (api, port):
        parts = urlsplit(p.settings.stream_url)
        connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=p.settings.stream_idle_seconds, context=ssl.create_default_context())
        connection.set_tunnel(parts.hostname, parts.port or 443)
        start, total = time.monotonic(), 0
        try:
            connection.request('GET', (parts.path or '/') + ('?' + parts.query if parts.query else ''), headers={'Accept': 'text/event-stream', 'Connection': 'close'})
            response = connection.getresponse()
            if response.status != 200:
                categories = {401: '需要授权', 403: '服务拒绝或挑战', 429: '服务限流'}
                return f"诊断端点：{categories.get(response.status, 'HTTP ' + str(response.status))}；未将此结果计为线路故障"
            streaming_type = 'text/event-stream' in response.getheader('Content-Type', '').lower()
            while time.monotonic() - start < p.settings.stream_seconds and total < 1_000_000:
                if cancelled():
                    raise Cancelled()
                chunk = response.read1(min(4096, 1_000_000 - total))
                if not chunk:
                    return f'端点在 {time.monotonic()-start:.1f} 秒后结束响应，读取 {total} 字节；不代表真实 AI 对话测试'
                total += len(chunk)
                event('scan', f'流式诊断 · 已保持 {time.monotonic()-start:.0f} 秒 · {total} 字节')
            if DirectNetwork.discover().identity != network.identity:
                raise ValueError('物理网络已变化，诊断结果无效')
            return f"{'SSE' if streaming_type else 'HTTP 响应流'}保持 {time.monotonic()-start:.1f} 秒，读取 {total} 字节；未发送模型请求"
        except (socket.timeout, TimeoutError):
            return '超过端点空闲时间限制；端点本身无数据与网络中断不能仅据此区分'
        finally:
            connection.close()
