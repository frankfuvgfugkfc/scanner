import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import xray

PORT = int(os.environ.get('ZEUS_PORT') or (sys.argv[1] if len(sys.argv) > 1 else 8000))
MAX_IPS_PER_REQUEST = 200
SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=100)
# Measurements taken while 100 sockets fight over the same uplink are inflated, so
# precision mode trades throughput for numbers that reflect the IP, not our own queue.
PRECISION_EXECUTOR = ThreadPoolExecutor(max_workers=8)
# Each xray verification spawns a real process and a real tunnel, so keep it narrow.
XRAY_EXECUTOR = ThreadPoolExecutor(max_workers=3)

# Only the best candidates are worth the cost of a real tunnel + speedtest.
XRAY_TOP_N = 5

_socks_lock = threading.Lock()
_socks_counter = [0]


def next_socks_port():
    with _socks_lock:
        _socks_counter[0] = (_socks_counter[0] + 1) % 200
        return xray.SOCKS_BASE_PORT + _socks_counter[0]


ALLOWED_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
DEFAULT_PORTS = (443,)

# A Cloudflare edge that answers 403/409/429 for our SNI is reachable but refusing us,
# so it is useless as a clean IP even though it spoke valid HTTP.
BLOCKED_STATUSES = (403, 409, 429)

DISCOVERY_TIMEOUT = 2.0
SAMPLE_GAP_SEC = 0.12

SPEED_BUDGET_SEC = 3.0
SPEED_MAX_BYTES = 2 * 1024 * 1024
SPEED_MIN_BYTES = 64 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_PATH = os.path.join(BASE_DIR, 'index.html')

HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                         r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')


def load_ui():
    try:
        with open(UI_PATH, 'r', encoding='utf-8') as fh:
            return fh.read()
    except OSError as exc:
        return f'<h1>index.html not found next to server.py</h1><pre>{exc}</pre>'


HTML_CONTENT = load_ui()


def is_valid_host(value):
    if not value or len(value) > 253:
        return False
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        pass
    return bool(HOSTNAME_RE.match(value))


def _measure_speed(ssock, deadline):
    """Drain the response body to estimate throughput in KB/s."""
    received = 0
    started = time.monotonic()
    try:
        while received < SPEED_MAX_BYTES and time.monotonic() < deadline:
            chunk = ssock.recv(32768)
            if not chunk:
                break
            received += len(chunk)
    except Exception:
        pass
    elapsed = time.monotonic() - started
    if received < SPEED_MIN_BYTES or elapsed <= 0:
        return None
    return int(received / 1024 / elapsed)


def _probe(ip, port, sni, timeout, want_speed):
    """One full TCP+TLS+HTTP round trip. Raises on any failure."""
    started = time.monotonic()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        tcp_ms = int((time.monotonic() - started) * 1000)
        sock.settimeout(timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_started = time.monotonic()
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            tls_ms = int((time.monotonic() - tls_started) * 1000)
            req = (f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                   "User-Agent: Mozilla/5.0 (Zeus-Scanner)\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
            ssock.sendall(req.encode('ascii'))

            first = ssock.recv(8192)
            ttfb_ms = int((time.monotonic() - started) * 1000)
            if not first.startswith(b'HTTP/1.'):
                raise ValueError('not an HTTP response')

            head = first
            while b'\r\n\r\n' not in head and len(head) < 32768:
                chunk = ssock.recv(8192)
                if not chunk:
                    break
                head += chunk

            try:
                status = int(head.split(b' ', 2)[1])
            except (IndexError, ValueError):
                raise ValueError('malformed status line')

            lowered = head[:head.find(b'\r\n\r\n') if b'\r\n\r\n' in head else len(head)].lower()
            cloudflare = b'cf-ray' in lowered or b'server: cloudflare' in lowered

            speed = None
            if want_speed:
                speed = _measure_speed(ssock, time.monotonic() + SPEED_BUDGET_SEC)

            return {
                'tcp': tcp_ms,
                'tls': tls_ms,
                'ping': ttfb_ms,
                'status': status,
                'cloudflare': cloudflare,
                'speed': speed,
            }


def _percentile(sorted_values, fraction):
    if not sorted_values:
        return None
    pos = fraction * (len(sorted_values) - 1)
    low = int(pos)
    high = min(low + 1, len(sorted_values) - 1)
    return int(sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (pos - low))


def _stdev(values):
    if len(values) < 2:
        return 0
    mean = sum(values) / len(values)
    return int((sum((v - mean) ** 2 for v in values) / (len(values) - 1)) ** 0.5)


def _grade(loss, median, stdev, ok):
    """A single 0-100 score so the list can be ranked by real usability."""
    if not ok:
        return 0
    score = 100.0
    score -= loss * 0.9                                  # loss dominates
    score -= min(45.0, median / 1000.0 * 45.0)           # 1000ms latency costs 45
    score -= min(20.0, stdev / 200.0 * 20.0)             # instability costs up to 20
    return max(0, min(100, int(round(score))))


def scan_ip(ip, sni, ports=DEFAULT_PORTS, timeout=3.5, passes=3, deep=False):
    """Find a working port for `ip`, then re-probe it to measure loss, jitter and stability."""
    last_error = 'failed'
    chosen = None
    first_probe = None

    for port in ports:
        try:
            probe = _probe(ip, port, sni, min(timeout, DISCOVERY_TIMEOUT), want_speed=False)
        except Exception as exc:
            last_error = str(exc) or exc.__class__.__name__
            continue
        if probe['status'] in BLOCKED_STATUSES:
            last_error = f"blocked (HTTP {probe['status']})"
            continue
        chosen = port
        first_probe = probe
        break

    if chosen is None:
        return {'ip': ip, 'success': False, 'error': last_error}

    probes = [first_probe]
    attempted = 1
    for i in range(max(0, passes - 1)):
        attempted += 1
        # A back-to-back reconnect reuses a warm path and hides real loss.
        time.sleep(SAMPLE_GAP_SEC)
        want_speed = deep and i == passes - 2
        try:
            probe = _probe(ip, chosen, sni, timeout, want_speed=want_speed)
        except Exception as exc:
            last_error = str(exc) or exc.__class__.__name__
            continue
        if probe['status'] in BLOCKED_STATUSES:
            last_error = f"blocked (HTTP {probe['status']})"
            continue
        probes.append(probe)

    pings = sorted(p['ping'] for p in probes)
    tcps = [p['tcp'] for p in probes]
    speeds = [p['speed'] for p in probes if p['speed']]

    ok = len(probes)
    loss = round((attempted - ok) / attempted * 100)
    median = _percentile(pings, 0.5)
    stdev = _stdev(pings)

    return {
        'ip': ip,
        'success': True,
        'port': chosen,
        'ping': pings[0],
        'median': median,
        'avg': sum(pings) // ok,
        'worst': pings[-1],
        'jitter': pings[-1] - pings[0],
        'stdev': stdev,
        'loss': loss,
        'tcp': min(tcps),
        'tls': min(p['tls'] for p in probes),
        'ok': ok,
        'attempts': attempted,
        'score': _grade(loss, median, stdev, ok),
        'status': probes[-1]['status'],
        'cloudflare': any(p['cloudflare'] for p in probes),
        'speed': max(speeds) if speeds else None,
    }


def verify_with_xray(binary, spec, candidates, want_speed):
    """Prove each candidate actually carries the user's config, not just a TLS hello."""
    def one(item):
        result = xray.verify(binary, spec, item['ip'], next_socks_port(),
                             port=item.get('port'), want_speed=want_speed)
        payload = {'ip': item['ip'], 'ok': result['ok']}
        if result['ok']:
            payload['latency'] = result['latency']
            payload['speed'] = result.get('speed')
        else:
            payload['error'] = result['error']
        return payload

    return [f.result() for f in [XRAY_EXECUTOR.submit(one, c) for c in candidates]]


class ZeusRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ZeusScanner/1.5'

    def _send(self, status, body, content_type='application/json'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        try:
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, status, payload):
        self._send(status, json.dumps(payload))

    def do_OPTIONS(self):
        try:
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.send_header('Content-Length', '0')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path.startswith('/api/ping'):
            binary = xray.find_xray()
            self._send_json(200, {"status": "online",
                                  "xray": bool(binary),
                                  "xray_version": xray.xray_version(binary) if binary else None})
        elif self.path == '/' or self.path.startswith('/?'):
            self._send(200, HTML_CONTENT, 'text/html; charset=utf-8')
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_verify(self, data):
        binary = xray.find_xray()
        if not binary:
            self._send_json(400, {"error": "xray not installed"})
            return
        try:
            spec = xray.parse_link(data.get('config') or '')
        except ValueError as exc:
            self._send_json(400, {"error": f"invalid config: {exc}"})
            return

        candidates = []
        for item in (data.get('candidates') or [])[:XRAY_TOP_N]:
            if not isinstance(item, dict):
                continue
            ip = str(item.get('ip') or '').strip()
            if not is_valid_host(ip):
                continue
            port = item.get('port')
            candidates.append({'ip': ip,
                               'port': port if isinstance(port, int) and port in ALLOWED_PORTS else None})
        if not candidates:
            self._send_json(400, {"error": "no candidates"})
            return

        results = verify_with_xray(binary, spec, candidates, bool(data.get('speed')))
        self._send_json(200, {"results": results})

    def do_POST(self):
        if self.path.startswith('/api/verify'):
            try:
                length = int(self.headers.get('Content-Length') or 0)
                if length <= 0 or length > 1_000_000:
                    self._send_json(400, {"error": "invalid body size"})
                    return
                self._handle_verify(json.loads(self.rfile.read(length).decode('utf-8')))
            except json.JSONDecodeError:
                self._send_json(400, {"error": "malformed json"})
            except Exception as exc:
                print(f"[ERROR] /api/verify: {exc}", file=sys.stderr)
                self._send_json(500, {"error": "internal error"})
            return
        if not self.path.startswith('/api/scan'):
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get('Content-Length') or 0)
            if length <= 0 or length > 1_000_000:
                self._send_json(400, {"error": "invalid body size"})
                return
            data = json.loads(self.rfile.read(length).decode('utf-8'))
            sni = data.get('sni', '')
            ips = data.get('ips') or []
            if not isinstance(ips, list) or not isinstance(sni, str):
                self._send_json(400, {"error": "invalid payload"})
                return
            if not is_valid_host(sni):
                self._send_json(400, {"error": "invalid sni"})
                return
            ips = [ip for ip in ips if isinstance(ip, str) and is_valid_host(ip.strip())]
            if len(ips) > MAX_IPS_PER_REQUEST:
                self._send_json(400, {"error": "too many ips"})
                return

            ports = [p for p in (data.get('ports') or DEFAULT_PORTS)
                     if isinstance(p, int) and p in ALLOWED_PORTS]
            if not ports:
                ports = list(DEFAULT_PORTS)
            deep = bool(data.get('deep'))
            precise = bool(data.get('precise'))
            passes = data.get('passes')
            passes = passes if isinstance(passes, int) and 1 <= passes <= 10 else 3

            executor = PRECISION_EXECUTOR if precise else SCAN_EXECUTOR
            futures = [executor.submit(scan_ip, ip.strip(), sni, ports, 3.5, passes, deep)
                       for ip in ips]
            results = [f.result() for f in futures]
            self._send_json(200, {"results": results})
        except json.JSONDecodeError:
            self._send_json(400, {"error": "malformed json"})
        except Exception as exc:
            print(f"[ERROR] /api/scan: {exc}", file=sys.stderr)
            self._send_json(500, {"error": "internal error"})

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    httpd = ThreadingHTTPServer(('127.0.0.1', PORT), ZeusRequestHandler)
    print("\033[96m==========================================\033[0m")
    print("\033[92m  Zeus Scanner Core (Unified) is RUNNING!\033[0m")
    print(f"\033[93m  Open in Browser: http://127.0.0.1:{PORT}/\033[0m")
    print("\033[90m  Do NOT close this terminal during scan.\033[0m")
    print("\033[96m==========================================\033[0m")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()
        XRAY_EXECUTOR.shutdown(wait=False)
        SCAN_EXECUTOR.shutdown(wait=False)
        PRECISION_EXECUTOR.shutdown(wait=False)
