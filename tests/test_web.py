"""Local browser interface: real HTTP, synthetic fixtures, and no OSV network."""
import http.client
import json
import os
from pathlib import Path
import queue
import re
import runpy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from repoguard.models import ScanReport
from repoguard.osv import OsvResult
from repoguard import web


class WebServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='repoguard web test ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.secret = 'gh' + 'p_' + 'A1b2C3d4E5f6G7h8J9k0L1m2N3o4P5q6R7s8'
        (self.root / 'project.txt').write_text('token = "' + self.secret + '"\n', encoding='utf-8')
        (self.root / 'ads.txt').write_text('google.com, pub-' + '1234567890123456, DIRECT\n', encoding='utf-8')
        (self.root / 'requirements.txt').write_text('requests==2.31.0\n', encoding='utf-8')
        third_party = self.root / 'node_modules' / 'some-package'
        third_party.mkdir(parents=True)
        (third_party / 'example.js').write_text('const token = "' + self.secret + '";\n', encoding='utf-8')
        with patch('repoguard.web._picker_available', return_value=False):
            self.app = web.WebApp()
        self.server = web.RepoGuardServer(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.host = '127.0.0.1:' + str(self.server.server_port)
        self.origin = 'http://' + self.host

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, value=None, headers=None, authenticated=True, origin=None):
        all_headers = {} if headers is None else dict(headers)
        if authenticated:
            all_headers.setdefault('X-RepoGuard-Token', self.app.token)
        if origin is not False:
            all_headers.setdefault('Origin', self.origin if origin is None else origin)
        body = None
        if value is not None:
            body = json.dumps(value).encode('utf-8')
            all_headers.setdefault('Content-Type', 'application/json')
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=4)
        try:
            conn.request(method, path, body=body, headers=all_headers)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def post_scan(self, directory=None, deep=False, osv=False):
        return self.request('POST', '/api/scan', {'directory': str(directory or self.root), 'deep': deep, 'osv': osv})

    def wait_for_state(self, expected, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, _, data = self.request('GET', '/api/status')
            self.assertEqual(status, 200)
            payload = json.loads(data)
            if payload['state'] == expected:
                return payload
            if payload['state'] == 'error' and expected != 'error':
                self.fail('The scan failed: ' + payload['error'])
            time.sleep(0.01)
        self.fail('Timed out waiting for state ' + expected)

    def test_interface_is_not_an_api_token_and_cannot_be_framed(self):
        status, headers, body = self.request('GET', '/', authenticated=False, origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn(self.app.token.encode(), body)
        self.assertIn(b'Choisir un dossier', body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertIn("script-src 'sha256-", headers['Content-Security-Policy'])
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_api_rejects_missing_token_bad_host_and_cross_origin(self):
        for method, path, value, extra in (
            ('GET', '/api/status', None, {'authenticated': False}),
            ('GET', '/api/report', None, {'authenticated': False}),
            ('GET', '/api/status', None, {'headers': {'X-RepoGuard-Token': 'wrong'}}),
            ('GET', '/api/status', None, {'headers': {'Host': 'attacker.example:' + str(self.server.server_port)}}),
            ('GET', '/', None, {'headers': {'Host': 'attacker.example:' + str(self.server.server_port)}, 'authenticated': False}),
            ('GET', '/api/status', None, {'origin': 'https://attacker.example'}),
            ('POST', '/api/scan', {'directory': str(self.root), 'deep': False, 'osv': False}, {'origin': False}),
            ('POST', '/api/scan', {'directory': str(self.root), 'deep': False, 'osv': False}, {'origin': 'null'}),
            ('POST', '/api/scan', {'directory': str(self.root), 'deep': False, 'osv': False}, {'origin': 'https://attacker.example'}),
        ):
            with self.subTest(method=method, path=path, extra=extra):
                status, headers, _ = self.request(method, path, value, **extra)
                self.assertEqual(status, 403)
                self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertEqual(self.app.status()['state'], 'idle')
        status, _, _ = self.request('OPTIONS', '/api/scan', authenticated=False)
        self.assertEqual(status, 403)

    def test_api_rejects_duplicate_host_origin_and_token_headers(self):
        for duplicate in ('Host', 'Origin', 'X-RepoGuard-Token'):
            with self.subTest(header=duplicate):
                conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=4)
                try:
                    conn.putrequest('POST', '/api/scan', skip_host=True)
                    for key, value in [('Host', self.host), ('Origin', self.origin),
                                       ('X-RepoGuard-Token', self.app.token),
                                       ('Content-Type', 'application/json'), ('Content-Length', '2')]:
                        conn.putheader(key, value)
                        if key == duplicate:
                            conn.putheader(key, value)
                    conn.endheaders(b'{}')
                    response = conn.getresponse()
                    self.assertEqual(response.status, 403)
                    response.read()
                finally:
                    conn.close()

    def test_invalid_bodies_types_and_paths_do_not_start_scans(self):
        requests = [
            {'directory': '', 'deep': False, 'osv': False},
            {'directory': 'https://example.com/project', 'deep': False, 'osv': False},
            {'directory': str(self.root / 'does-not-exist'), 'deep': False, 'osv': False},
            {'directory': str(self.root / 'project.txt'), 'deep': False, 'osv': False},
            {'directory': str(self.root), 'deep': 'yes', 'osv': False},
            {'directory': str(self.root), 'deep': False, 'osv': 1},
            {'directory': str(self.root), 'deep': False},
            {'directory': str(self.root), 'deep': False, 'osv': False, 'extra': 1},
            {'directory': '\u0000', 'deep': False, 'osv': False},
            {'directory': 'x' * 4097, 'deep': False, 'osv': False},
        ]
        for value in requests:
            with self.subTest(value=value):
                self.assertEqual(self.request('POST', '/api/scan', value)[0], 400)
        self.assertEqual(self.request('POST', '/api/scan', requests[-1], headers={'Content-Type': 'text/plain'})[0], 400)
        huge = {'directory': 'é' * 3000, 'deep': False, 'osv': False}
        code, _, body = self.request('POST', '/api/scan', huge)
        self.assertEqual(code, 400)
        self.assertIn('Dossier introuvable', json.loads(body)['error'])
        self.assertEqual(self.app.status()['state'], 'idle')

    def test_copied_quoted_path_works_and_scan_is_offline_and_read_only(self):
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('repoguard.scanner.lookup', side_effect=AssertionError('OSV was called')):
            code, _, _ = self.post_scan(directory='  "' + str(self.root) + '"  ')
            self.assertEqual(code, 202)
            payload = self.wait_for_state('complete')
        summary = payload['summary']
        self.assertEqual(summary['scope'], 'standard')
        self.assertEqual(summary['files_scanned'], 3)
        self.assertEqual(summary['possible_secrets'], 1)
        self.assertEqual(summary['third_party_secrets'], 0)
        self.assertEqual(summary['public_information'], 1)
        self.assertEqual(summary['osv_status'], 'not_requested')
        code, _, report = self.request('GET', '/api/report')
        self.assertEqual(code, 200)
        self.assertNotIn(self.secret.encode(), report)
        self.assertNotIn(('pub-' + '1234567890123456').encode(), report)
        self.assertIn('Informations publiques et configurations'.encode('utf-8'), report)
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_deep_mode_includes_third_party_files(self):
        with patch('repoguard.scanner.lookup', side_effect=AssertionError('OSV was called')):
            self.assertEqual(self.post_scan(deep=True)[0], 202)
            summary = self.wait_for_state('complete')['summary']
        self.assertEqual(summary['scope'], 'deep')
        self.assertEqual(summary['files_scanned'], 4)
        self.assertEqual(summary['possible_secrets'], 2)
        self.assertEqual(summary['third_party_secrets'], 1)
        self.assertEqual(summary['osv_status'], 'not_requested')

    def test_osv_is_called_only_on_opt_in_and_partial_is_visible(self):
        coordinate = ('PyPI', 'requests', '2.31.0')
        fake = OsvResult(matches={coordinate: ['GHSA-demo-1234']}, status='complete', checked=1)
        with patch('repoguard.scanner.lookup', return_value=fake) as lookup:
            self.assertEqual(self.post_scan(osv=True)[0], 202)
            summary = self.wait_for_state('complete')['summary']
            lookup.assert_called_once()
            self.assertEqual([item.coordinate for item in lookup.call_args.args[0]], [coordinate])
        self.assertEqual((summary['osv_status'], summary['osv_queries'], summary['advisories']), ('complete', 1, 1))
        self.assertIn(b'GHSA-demo-1234', self.request('GET', '/api/report')[2])
        with patch('repoguard.scanner.lookup', return_value=OsvResult(status='partial', checked=0,
                   warnings=['OSV could not be reached or returned an invalid response; dependency results are incomplete.'])):
            self.assertEqual(self.post_scan(osv=True)[0], 202)
            summary = self.wait_for_state('complete')['summary']
        self.assertEqual(summary['osv_status'], 'partial')
        self.assertIn('OSV est inaccessible'.encode('utf-8'), self.request('GET', '/api/report')[2])

    def test_only_one_scan_runs_at_a_time(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def slow_scan(*_args, **_kwargs):
            started.set()
            if not release.wait(3):
                raise RuntimeError('test timed out')
            return ScanReport(project='fixture')
        with patch('repoguard.web.scan_directory', side_effect=slow_scan):
            self.assertEqual(self.post_scan()[0], 202)
            self.assertTrue(started.wait(2))
            self.assertEqual(self.post_scan()[0], 409)
            self.assertEqual(self.app.status()['state'], 'running')
            release.set()
            self.wait_for_state('complete')

    def test_scan_errors_do_not_disclose_exception_contents(self):
        with patch('repoguard.web.scan_directory', side_effect=RuntimeError('SENSITIVE fixture')):
            self.assertEqual(self.post_scan()[0], 202)
            payload = self.wait_for_state('error')
        self.assertNotIn('SENSITIVE', json.dumps(payload))
        self.assertEqual(self.request('GET', '/api/report')[0], 404)

    def test_native_folder_picker_is_optional_and_returns_selected_path(self):
        self.assertEqual(self.request('POST', '/api/folder', {})[0], 400)
        self.app.can_pick = True
        with patch('repoguard.web._pick_directory', return_value=str(self.root)):
            status, _, body = self.request('POST', '/api/folder', {})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['directory'], str(self.root))
        with patch('repoguard.web._pick_directory', return_value=None):
            status, _, body = self.request('POST', '/api/folder', {})
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body)['directory'])
        with patch('repoguard.web._pick_directory', side_effect=subprocess.TimeoutExpired('picker', 1)):
            self.assertEqual(self.request('POST', '/api/folder', {})[0], 400)
        self.assertFalse(self.app.picking)

    @unittest.skipIf(os.name == 'nt', 'HTML-like filenames are not valid on Windows')
    def test_untrusted_filenames_are_escaped_in_the_report(self):
        (self.root / '<img src=x onerror=alert(1)>.txt').write_text(self.secret, encoding='utf-8')
        self.assertEqual(self.post_scan()[0], 202)
        self.wait_for_state('complete')
        report = self.request('GET', '/api/report')[2].decode('utf-8')
        self.assertNotIn('<img src=x onerror=alert(1)>', report)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', report)

    def test_idle_watch_waits_for_scan_and_then_stops(self):
        stop = threading.Event()
        self.addCleanup(stop.set)
        with self.app.lock:
            self.app.state = 'running'
            self.app.last_activity = time.monotonic() - 10
        with patch.object(web, 'SESSION_IDLE_SECONDS', 0.05), patch.object(web, 'IDLE_CHECK_SECONDS', 0.02):
            watcher = threading.Thread(target=web._stop_when_idle, args=(self.server, stop), daemon=True)
            watcher.start()
            time.sleep(0.12)
            self.assertTrue(self.thread.is_alive(), 'An active scan must not be stopped for inactivity')
            with self.app.lock:
                self.app.state = 'idle'
            self.thread.join(timeout=2)
            watcher.join(timeout=2)
            self.assertFalse(self.thread.is_alive())

    def test_shutdown_is_authenticated_and_stops_server(self):
        self.assertEqual(self.request('POST', '/api/shutdown', {}, authenticated=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/shutdown', {})[0], 200)
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())


class WebSafetyTests(unittest.TestCase):
    def test_real_server_refuses_non_loopback_binding(self):
        for host in ('0.0.0.0', 'localhost', '::1', '192.168.1.1'):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, '127.0.0.1'):
                web.run_web(host=host, open_browser=False)
        with self.assertRaisesRegex(ValueError, 'Port'):
            web.run_web(port=65536, open_browser=False)

    def test_common_windows_network_paths_are_recognized(self):
        self.assertTrue(web._windows_network_path('\\\\server\\share\\project'))
        self.assertTrue(web._windows_network_path('//server/share/project'))
        if os.name == 'nt':
            self.assertFalse(web._windows_network_path(str(Path.cwd().anchor)))
            with self.assertRaisesRegex(ValueError, 'lecteur réseau'):
                web._local_directory('\\\\server\\share\\project')
        else:
            self.assertFalse(web._windows_network_path('C:\\Users\\Example'))

    def test_picker_subprocess_runs_only_fixed_isolated_code(self):
        class Completed:
            stdout = json.dumps('C:\\My Project')
        with patch('repoguard.web._picker_backend', return_value='tk'), \
             patch('repoguard.web.subprocess.run', return_value=Completed()) as run:
            self.assertEqual(web._pick_directory(), 'C:\\My Project')
        args, kwargs = run.call_args
        self.assertEqual(args[0], [sys.executable, '-I', '-c', web._PICKER_CODE])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['timeout'], 180)

    def test_windows_picker_uses_fixed_noninteractive_system_program(self):
        class Completed:
            stdout = json.dumps('C:\\Dossier avec espaces')
        executable = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        with patch('repoguard.web._picker_backend', return_value='windows'), \
             patch('repoguard.web._windows_powershell', return_value=executable), \
             patch('repoguard.web.subprocess.run', return_value=Completed()) as run:
            self.assertEqual(web._pick_directory(), 'C:\\Dossier avec espaces')
        self.assertEqual(run.call_args.args[0], [executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                                                '-STA', '-Command', web._WINDOWS_PICKER_CODE])
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_web_command_prints_a_private_browser_link_and_stops_on_request(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONIOENCODING='ascii')
        proc = subprocess.Popen([sys.executable, '-m', 'repoguard', 'web', '--no-browser'], cwd=root, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding='utf-8', errors='replace')
        self.addCleanup(lambda: proc.poll() is None and proc.terminate())
        lines = queue.Queue()
        def read_stdout():
            for line in proc.stdout:
                lines.put(line)
        threading.Thread(target=read_stdout, daemon=True).start()
        deadline = time.monotonic() + 15
        match = None
        guidance = []
        while time.monotonic() < deadline and match is None:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue
            guidance.append(line)
            match = re.search(r'http://127\.0\.0\.1:(\d+)/#([A-Za-z0-9_-]+)', line)
        self.assertIsNotNone(match, 'The web command did not show its browser link')
        self.assertTrue(any('navigateur' in line for line in guidance))
        port, token = int(match.group(1)), match.group(2)
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            origin = f'http://127.0.0.1:{port}'
            connection.request('POST', '/api/shutdown', body=b'{}',
                               headers={'Origin': origin, 'X-RepoGuard-Token': token,
                                        'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
        self.assertEqual(proc.wait(timeout=10), 0)
        proc.stdout.close()
        proc.stderr.close()

    def test_windows_launcher_invokes_web_without_extra_arguments(self):
        previous = sys.dont_write_bytecode
        try:
            with patch('repoguard.web.run_web') as start:
                runpy.run_path(str(Path(__file__).resolve().parents[1] / 'Lancer-RepoGuard.pyw'))
                start.assert_called_once_with()
                self.assertTrue(sys.dont_write_bytecode)
        finally:
            sys.dont_write_bytecode = previous

    def test_demo_never_scans_files_or_calls_osv_even_for_forged_input(self):
        app = web.WebApp(demo=True)
        with patch('repoguard.web.scan_directory', side_effect=AssertionError('File scan not permitted')) as scan, \
             patch('repoguard.scanner.lookup', side_effect=AssertionError('OSV not permitted')) as lookup:
            ok, error = app.start('/real/or/missing/project', True, True)
            self.assertTrue(ok, error)
            deadline = time.monotonic() + 5
            while app.status()['state'] == 'running' and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(app.status()['state'], 'complete')
            self.assertEqual(app.status()['summary']['osv_status'], 'demo')
            self.assertIn('DÉMONSTRATION — FICTIVE', app.report_html)
            self.assertFalse(app.can_pick)
            scan.assert_not_called()
            lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
