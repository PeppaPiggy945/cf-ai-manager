"""Measure a cold HTTPS HEAD and a second HEAD on the very same TLS socket."""
import http.client
import ssl
import time
from urllib.parse import urlsplit

from .speed import Cancelled


def measure_pair(port, url, timeout_ms, cancelled=lambda: False):
    target = urlsplit(url)
    if target.scheme != 'https' or not target.hostname or target.username or target.password:
        raise ValueError('延迟探测须使用无内嵌凭据的 HTTPS 地址')
    result = {'latency': None, 'first_request': None}
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=timeout_ms / 1000, context=context)
    connection.set_tunnel(target.hostname, target.port or 443)
    path = target.path or '/'
    if target.query:
        path += '?' + target.query
    try:
        for metric in ('first_request', 'latency'):
            if cancelled():
                raise Cancelled()
            # A server closing the first connection gives no reusable-connection measurement.
            # Never let http.client silently reconnect and label that as a warm request.
            if metric == 'latency' and connection.sock is None:
                break
            previous_socket = connection.sock
            start = time.perf_counter()
            if previous_socket is not None:
                previous_socket.settimeout(timeout_ms / 1000)
            connection.request('HEAD', path, headers={'Host': target.netloc, 'Connection': 'keep-alive'})
            request_socket = connection.sock
            response = connection.getresponse()
            elapsed = (time.perf_counter() - start) * 1000
            response.read()
            response.close()
            if cancelled():
                raise Cancelled()
            if response.status != 204 or not 0 < elapsed <= timeout_ms:
                result['error'] = f'HTTP {response.status}（预期 204）' if response.status != 204 else '请求超过时限'
                break
            if metric == 'latency' and request_socket is not previous_socket:
                break
            result[metric] = elapsed
    except ConnectionRefusedError:
        raise
    except ssl.SSLCertVerificationError:
        result['error'] = 'TLS 证书校验失败'
    except TimeoutError:
        result['error'] = '请求超时'
    except (OSError, http.client.HTTPException) as exc:
        # Never persist exception text: CONNECT errors may include arbitrary server content.
        result['error'] = f'隧道或 HTTPS 请求失败（{type(exc).__name__}）'
    finally:
        connection.close()
    return result
