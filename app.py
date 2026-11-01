"""
app.py - Computer Networks Project: IP Address Validator
Pure Python HTTP Server (Zero External Dependencies)
Uses ONLY Python's built-in standard library: http.server, json, urllib, os.
No Flask, no third-party packages, no pip install required!
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from urllib.parse import urlparse

from validator import calculate_subnet, validate_ip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

EXAMPLES_DATA = {
    'ipv4': [
        {'ip': '192.168.1.1', 'label': 'Private Class C'},
        {'ip': '10.0.0.1', 'label': 'Private Class A'},
        {'ip': '172.16.0.1', 'label': 'Private Class B'},
        {'ip': '8.8.8.8', 'label': 'Google DNS (Public)'},
        {'ip': '127.0.0.1', 'label': 'Loopback'},
        {'ip': '255.255.255.255', 'label': 'Broadcast'},
        {'ip': '169.254.0.1', 'label': 'APIPA / Link-Local'},
        {'ip': '200.100.50.25', 'label': 'Public Class C'},
    ],
    'ipv6': [
        {'ip': '::1', 'label': 'Loopback'},
        {'ip': '2001:db8::1', 'label': 'Documentation'},
        {'ip': 'fe80::1', 'label': 'Link-Local'},
        {'ip': 'ff02::1', 'label': 'Multicast'},
        {'ip': '::ffff:192.0.2.1', 'label': 'IPv4-Mapped'},
        {'ip': 'fd00::1', 'label': 'Unique Local (ULA)'},
    ]
}


class PurePythonHandler(BaseHTTPRequestHandler):
    server_version = "IPValidator/2.0 PurePython"

    def _send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0:
                return {}
            raw = self.rfile.read(content_length)
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Main Page (Frontend)
        if path in ('/', '/index.html'):
            html_file = os.path.join(TEMPLATES_DIR, 'index.html')
            if os.path.exists(html_file):
                with open(html_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "index.html not found")
            return

        # 2. Examples API
        if path == '/api/examples':
            self._send_json(EXAMPLES_DATA)
            return

        # 3. Health Check
        if path == '/api/health':
            self._send_json({
                'status': 'ok',
                'server': 'Pure Python Standard Library (Zero Dependencies)',
                'project': 'Computer Networks - IP Address Validation',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            return

        # 4. Static Assets (if any)
        if path.startswith('/static/'):
            rel_path = path[8:]
            file_path = os.path.join(STATIC_DIR, rel_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                ext = os.path.splitext(file_path)[1].lower()
                mime = {
                    '.css': 'text/css',
                    '.js': 'application/javascript',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.svg': 'image/svg+xml'
                }.get(ext, 'application/octet-stream')
                with open(file_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Validate IP Endpoint
        if path == '/api/validate':
            data = self._read_json_body()
            ip = data.get('ip')
            if not ip or not isinstance(ip, str):
                self._send_json({'valid': False, 'error': 'Please provide a valid IP address string.'}, 400)
                return
            result = validate_ip(ip)
            self._send_json(result)
            return

        # Subnet Calculation Endpoint
        if path == '/api/subnet':
            data = self._read_json_body()
            cidr = data.get('cidr')
            if not cidr or not isinstance(cidr, str):
                self._send_json({'valid': False, 'error': 'Please provide CIDR notation (e.g. 192.168.1.0/24).'}, 400)
                return
            result = calculate_subnet(cidr)
            self._send_json(result)
            return

        self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Clean logging format
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]} - {args[1]}\n")


def run_server(port=5000):
    server_address = ('0.0.0.0', port)
    httpd = ThreadingHTTPServer(server_address, PurePythonHandler)
    print("\n" + "=" * 58)
    print("  IP Address Validator")
    print(f"  Listening on: http://localhost:{port}")
    print("=" * 58 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    run_server(port)
