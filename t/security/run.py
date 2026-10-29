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
import socketserver
import struct
import urllib.parse
import uuid
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
    parser.add_argument('--test', action='append', dest='tests', help='run selected test paths instead of the default suite')
    parser.add_argument('--parallel-fixtures', type=int, default=0, help='verify concurrent TLS fixture runs on one datastore')
    args = parser.parse_args()
    if args.parallel_fixtures < 0:
        parser.error('--parallel-fixtures must not be negative')
    if args.tests and args.full_suite:
        parser.error('--test and --full-suite are mutually exclusive')
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
        recovered_names = set()
        dns_lock = threading.Lock()
        dns_queries = {}
        class DNSHandler(socketserver.BaseRequestHandler):
            def handle(self):
                packet, sock = self.request
                try:
                    labels, offset = [], 12
                    while packet[offset]:
                        length = packet[offset]
                        if length > 63:
                            return
                        labels.append(packet[offset+1:offset+1+length].decode('ascii'))
                        offset += length+1
                    offset += 1
                    qtype, qclass = struct.unpack('!HH', packet[offset:offset+4])
                    name = '.'.join(labels).lower()
                    question = packet[12:offset+4]
                except (IndexError, ValueError, UnicodeError, struct.error):
                    return
                with dns_lock:
                    dns_queries[name] = dns_queries.get(name, 0)+1
                if name.startswith('drop-'):
                    return
                if name.startswith('malformed-'):
                    sock.sendto(packet[:2]+b'\x80', self.client_address)
                    return
                with dns_lock:
                    recovered = name in recovered_names
                code = 3 if name.startswith('nx-') else 2
                answer = b''
                if name.startswith('recover-') and recovered:
                    code = 0
                    if qtype == 1 and qclass == 1:
                        answer = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 0, 4)+socket.inet_aton('127.0.0.1')
                response = packet[:2]+struct.pack('!HHHHH', 0x8180 | code, 1, int(bool(answer)), 0, 0)+question+answer
                sock.sendto(response, self.client_address)
        class DNSServer(socketserver.ThreadingUDPServer):
            daemon_threads = True
        dns = DNSServer(('127.0.0.1', 0), DNSHandler)
        ports['dns'] = dns.server_address[1]
        threading.Thread(target=dns.serve_forever, daemon=True).start()
        stack.callback(dns.server_close)
        stack.callback(dns.shutdown)
        ports['fixture_id'] = uuid.uuid4().hex
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
        api_outage = {'failed': True, 'calls': 0}
        availability_lock = threading.Lock()
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
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path in ('/retry/reset', '/retry/recover', '/retry/stats'):
                    with availability_lock:
                        if parsed.path == '/retry/reset':
                            api_outage.update(failed=True, calls=0)
                        elif parsed.path == '/retry/recover':
                            api_outage['failed'] = False
                        body = json.dumps(api_outage).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if parsed.path.startswith('/retry/backend/'):
                    with availability_lock:
                        api_outage['calls'] += 1
                        unavailable = api_outage['failed']
                    if unavailable:
                        self.send_error(503)
                        return
                if parsed.path == '/dns/stats':
                    name = urllib.parse.parse_qs(parsed.query).get('name', [''])[0]
                    with dns_lock:
                        body = json.dumps({'queries': dns_queries.get(name, 0)}).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if parsed.path == '/dns/recover':
                    name = urllib.parse.parse_qs(parsed.query).get('name', [''])[0]
                    with dns_lock:
                        recovered_names.add(name)
                    self.send_response(204)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
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
        environment.update(TEST_SECURITY_DIR=str(folder), REDIS_HOST='127.0.0.1', REDIS_PORT=str(ports['plain']),
            TEST_NGINX_RESOLVER='127.0.0.1:'+str(ports['dns']))
        base_command = ['prove'] + ['-I'+p for p in args.prove_include]
        if args.parallel_fixtures:
            jobs = []
            used_ports = set(ports.values())
            for index in range(args.parallel_fixtures):
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); test_port = sock.getsockname()[1]
                if test_port in used_ports:
                    raise RuntimeError('parallel test port collision; rerun')
                used_ports.add(test_port)
                runtime = stack.enter_context(tempfile.TemporaryDirectory(prefix='sslers-parallel-', dir='/tmp'))
                child_env = environment.copy()
                child_env.update(TEST_NGINX_SERVER_PORT=str(test_port), TEST_NGINX_CLIENT_PORT=str(test_port),
                    TEST_NGINX_SERVROOT=runtime, TEST_NGINX_FIXTURE_ID=uuid.uuid4().hex)
                log = stack.enter_context((folder/('parallel-'+str(index)+'.log')).open('w+'))
                job = subprocess.Popen(base_command+['t/certificate_serving/03_redis_cache_prime_1.t',
                    't/certificate_serving/04_redis_cache_prime_2.t'], env=child_env, stdout=log, stderr=log)
                stack.callback(stop_process, job)
                jobs.append((job, log))
            failed = False
            for job, log in jobs:
                if job.wait() != 0:
                    log.seek(0); print(log.read()); failed = True
            if failed:
                return 1
            print('Parallel certificate fixtures passed on one shared datastore', flush=True)
        command = base_command + ['-r'] + (args.tests or ['t' if args.full_suite else 't/security'])
        print('Testing '+args.backend+' with password, TLS, mTLS, and authenticated Python HTTP fixtures', flush=True)
        result = subprocess.run(command, env=environment)
        if result.returncode == 0:
            # These instances are exclusively owned by this runner and begin
            # empty. Assert cleanup rather than silently deleting leaked keys.
            for name in ['plain', 'auth']:
                for database in [8, 9]:
                    with socket.create_connection(('127.0.0.1', ports[name])) as sock:
                        stream = sock.makefile('rb')
                        def send(*parts):
                            values = [str(value).encode() for value in parts]
                            message = b'*'+str(len(values)).encode()+b'\r\n'
                            for value in values:
                                message += b'$'+str(len(value)).encode()+b'\r\n'+value+b'\r\n'
                            sock.sendall(message)
                            return stream.readline()
                        if name == 'auth':
                            assert send('AUTH', 'test-password') == b'+OK\r\n'
                        assert send('SELECT', database) == b'+OK\r\n'
                        assert send('DBSIZE') == b':0\r\n', 'test fixture keys leaked in '+name+' DB '+str(database)
                        stream.close()
            print('Fixture key cleanup verified', flush=True)
        if result.returncode:
            for log in folder.glob('*.log'):
                print(log.name+':\n'+log.read_text())
        return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
