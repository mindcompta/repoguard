"""Windows-only end-to-end smoke test of an already-built portable ZIP.

Uses a fake browser that records the private launch URL; it never contacts OSV
and only scans a synthetic temporary folder. This is intended for CI.
"""
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import zipfile


def wait_for_url(capture: Path, process: subprocess.Popen, timeout: int = 25) -> tuple[int, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if capture.is_file():
            text = capture.read_text(encoding='utf-8')
            match = re.fullmatch(r'http://127\.0\.0\.1:(\d+)/#([A-Za-z0-9_-]+)', text.strip())
            if match:
                return int(match.group(1)), match.group(2)
        if process.poll() not in (None, 0):
            raise RuntimeError('Launcher exited before opening the browser')
        time.sleep(0.1)
    raise RuntimeError('Launcher did not hand a local URL to the browser')


def request(port: int, token: str, method: str, path: str, value: dict | None = None) -> tuple[int, bytes]:
    headers = {'X-RepoGuard-Token': token, 'Origin': f'http://127.0.0.1:{port}'}
    body = None
    if value is not None:
        headers['Content-Type'] = 'application/json'
        body = json.dumps(value).encode('utf-8')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def check_session(port: int, token: str, project: Path) -> None:
    deadline = time.monotonic() + 15
    while True:
        try:
            code, _ = request(port, token, 'GET', '/api/status')
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    if code != 200:
        raise RuntimeError('Local session refused its own token')
    code, _ = request(port, token, 'POST', '/api/scan',
                      {'directory': str(project), 'deep': True, 'osv': False})
    if code != 202:
        raise RuntimeError('Portable app did not start the synthetic scan')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        code, payload = request(port, token, 'GET', '/api/status')
        state = json.loads(payload)
        if code != 200:
            raise RuntimeError('Unable to check scan progress')
        if state['state'] != 'running':
            break
        time.sleep(0.1)
    else:
        raise RuntimeError('Synthetic scan did not finish')
    summary = state.get('summary') or {}
    if state['state'] != 'complete' or summary.get('files_scanned') != 2 or summary.get('public_information') != 1:
        raise RuntimeError('Unexpected synthetic scan summary')
    if summary.get('osv_status') != 'not_requested':
        raise RuntimeError('OSV must remain off without explicit consent')
    code, report = request(port, token, 'GET', '/api/report')
    if code != 200 or b'pub-1234567890123456' in report:
        raise RuntimeError('Report was missing or contained the synthetic matched value')
    if request(port, token, 'POST', '/api/shutdown', {})[0] != 200:
        raise RuntimeError('Unable to shut down the local session')


def main() -> None:
    if os.name != 'nt':
        raise SystemExit('Run this smoke test on Windows.')
    archive = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='RepoGuard portable test ') as temp:
        root = Path(temp)
        with zipfile.ZipFile(archive) as source:
            source.extractall(root)  # This is our freshly-built, pinned CI artifact.
        app = root / 'RepoGuard'
        project = root / 'Projet fictif avec espaces'
        project.mkdir()
        (project / 'ads.txt').write_text('google.com, pub-' + '1234567890123456, DIRECT\n', encoding='utf-8')
        (project / 'requirements.txt').write_text('requests==2.31.0\n', encoding='utf-8')
        capture_script = root / 'browser-capture.py'
        capture_script.write_text('import os,sys\nfrom pathlib import Path\n'
                                  "Path(os.environ['RG_SMOKE_URL']).write_text(sys.argv[1], encoding='utf-8')\n",
                                  encoding='utf-8')
        capture = root / 'browser-url.txt'
        env = dict(os.environ)
        env['RG_SMOKE_URL'] = str(capture)
        env['BROWSER'] = f'"{app / "runtime" / "python.exe"}" "{capture_script}" %s'
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        for launcher in ('Ouvrir-RepoGuard.bat', 'Diagnostic-RepoGuard.bat'):
            if capture.exists():
                capture.unlink()
            proc = subprocess.Popen(f'"{app / launcher}"', shell=True, cwd=app, env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=flags)
            try:
                port, token = wait_for_url(capture, proc)
                check_session(port, token, project)
                proc.wait(timeout=20)
                if proc.returncode != 0:
                    raise RuntimeError('Windows launcher did not exit cleanly')
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=10)
        print('Portable Windows launchers: local scan, report, opt-out and shutdown passed.')


if __name__ == '__main__':
    main()
