#!/usr/bin/env python3
"""Reproducible, isolated datastore connection/query benchmarks (Valkey default)."""
import argparse
import json
import hashlib
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['valkey', 'redis'], default='valkey')
    parser.add_argument('--iterations', type=int, default=1000)
    parser.add_argument('--resty', default=os.environ.get('RESTY_BINARY', 'resty'))
    parser.add_argument('--server-binary')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error('--iterations must be positive')
    binary = shutil.which(args.server_binary or args.backend+'-server')
    resty = shutil.which(args.resty)
    if not binary or not resty:
        parser.error('the chosen backend server and resty must be on PATH')
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='sslers-benchmark-') as temporary:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        log_path = Path(temporary)/'server.log'
        with log_path.open('w+') as log:
            server = subprocess.Popen([binary, '--bind', '127.0.0.1', '--port', str(port),
                '--save', '', '--appendonly', 'no', '--dir', temporary], stdout=log, stderr=log)
            try:
                deadline = time.monotonic()+5
                while True:
                    if server.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError:
                        if time.monotonic() >= deadline: raise RuntimeError('backend startup timed out')
                        time.sleep(.02)
                result = subprocess.run([resty, '--shdict', 'cert_cache 1m', '--shdict', 'cert_cache_ipc 100k',
                    '-I', str(root/'lib'), str(root/'benchmarks/datastore.lua'), '127.0.0.1', str(port), str(args.iterations)],
                    cwd=root, capture_output=True, text=True, env=os.environ.copy())
                if result.returncode:
                    raise RuntimeError('OpenResty benchmark failed:\n'+result.stderr.strip())
                report = json.loads(result.stdout)
                report.update(schema_version=1, backend=args.backend, platform=platform.platform(),
                    server_executable_version=subprocess.check_output([binary, '--version'], text=True).strip(),
                    library_sha256=hashlib.sha256((root/'lib/resty/peter_sslers.lua').read_bytes()).hexdigest(),
                    note='Loopback plaintext, one sequential client; exported backend queries bypass certificate caches.')
                output = json.dumps(report, indent=2)+'\n'
                if args.output: args.output.write_text(output)
                print(output, end='')
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()


if __name__ == '__main__':
    main()
