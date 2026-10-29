#!/usr/bin/env python3
"""Run isolated secure-backend fixtures; Valkey is the default backend."""
import argparse
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['valkey', 'redis'], default='valkey')
    parser.add_argument('--full-suite', action='store_true')
    parser.add_argument('--prove-include', action='append', default=[])
    args = parser.parse_args()
    binary = shutil.which(args.backend + '-server')
    if not binary:
        parser.error(args.backend + '-server is required')
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    with tempfile.TemporaryDirectory(prefix='sslers-security-') as temporary, contextlib.ExitStack() as stack:
        folder = Path(temporary)
        def command(*parts):
            subprocess.run(parts, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=sslers-test-ca', '-keyout', str(folder/'ca.key'), '-out', str(folder/'ca.crt'))
        for name, purpose in [('server', 'serverAuth'), ('client', 'clientAuth')]:
            command('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=backend.test',
                    '-keyout', str(folder/(name+'.key')), '-out', str(folder/(name+'.csr')))
            extension = folder/(name+'.ext')
            extension.write_text('extendedKeyUsage='+purpose+'\nsubjectAltName=DNS:backend.test,IP:127.0.0.1\n')
            command('openssl', 'x509', '-req', '-in', str(folder/(name+'.csr')), '-CA', str(folder/'ca.crt'),
                    '-CAkey', str(folder/'ca.key'), '-CAcreateserial', '-days', '2', '-extfile', str(extension),
                    '-out', str(folder/(name+'.crt')))
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=backend.test', '-keyout', str(folder/'untrusted.key'), '-out', str(folder/'untrusted.crt'))
        for key in folder.glob('*.key'):
            key.chmod(0o600)
        ports = {}
        for name in ['plain', 'auth', 'tls', 'mtls', 'http', 'https', 'https_mtls', 'untrusted']:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            if port in ports.values():
                raise RuntimeError('duplicate ephemeral port; rerun fixture setup')
            ports[name] = port
        (folder/'ports.json').write_text(json.dumps(ports))
        def stop_process(process):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for name in ['plain', 'auth', 'tls', 'mtls']:
            config = ['bind 127.0.0.1', 'protected-mode yes', 'save ""', 'appendonly no',
                      'dir '+str(folder), 'port '+str(ports[name] if name in ('plain', 'auth') else 0)]
            if name in ('auth', 'tls'):
                config += ['requirepass test-password', 'user audit on >test-password ~* +@all']
            if name in ('tls', 'mtls'):
                config += ['tls-port '+str(ports[name]), 'tls-cert-file '+str(folder/'server.crt'),
                           'tls-key-file '+str(folder/'server.key'), 'tls-ca-cert-file '+str(folder/'ca.crt'),
                           'tls-auth-clients '+('yes' if name == 'mtls' else 'no')]
            path = folder/(name+'.conf')
            path.write_text('\n'.join(config)+'\n')
            log = stack.enter_context((folder/(name+'.log')).open('w+'))
            process = subprocess.Popen([binary, str(path)], stdout=log, stderr=log)
            stack.callback(stop_process, process)
            deadline = time.monotonic()+5
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1', ports[name]), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('backend startup timeout')
                    time.sleep(.02)
        certificate = (root/'t/cert/test.example.com.crt').read_text()
        private_key = (root/'t/cert/test.example.com.key').read_text()
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def handle(self):
                try:
                    super().handle()
                except (ConnectionResetError, BrokenPipeError):
                    pass
            def log_message(self, *unused):
                pass
            def do_GET(self):
                self.respond()
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                if body != b'domain_name=test.example.com' or self.headers.get_content_type() != 'application/x-www-form-urlencoded':
                    self.send_error(400)
                    return
                self.respond()
            def respond(self):
                expected = 'Bearer test-token' if self.path.startswith('/bearer/') else 'Basic '+base64.b64encode(b'audit:test-password').decode()
                if self.headers.get('Authorization') != expected:
                    self.send_error(401)
                    return
                body = json.dumps({'certificate_signed__latest_multi': {
                    'fullchain': {'pem': certificate}, 'private_key': {'pem': private_key}}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        for name in ['http', 'https', 'https_mtls', 'untrusted']:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', ports[name]), Handler)
            server.daemon_threads = True
            if name != 'http':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                cert = 'untrusted' if name == 'untrusted' else 'server'
                context.load_cert_chain(folder/(cert+'.crt'), folder/(cert+'.key'))
                if name == 'https_mtls':
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(folder/'ca.crt')
                server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
        environment = os.environ.copy()
        environment.update(TEST_SECURITY_DIR=str(folder), REDIS_HOST='127.0.0.1', REDIS_PORT=str(ports['plain']))
        command = ['prove'] + ['-I'+p for p in args.prove_include] + ['-r', 't' if args.full_suite else 't/security']
        print('Testing '+args.backend+' with password, TLS, mTLS, and authenticated Python HTTP fixtures', flush=True)
        result = subprocess.run(command, env=environment)
        if result.returncode:
            for log in folder.glob('*.log'):
                print(log.name+':\n'+log.read_text())
        return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
