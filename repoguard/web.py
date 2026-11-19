"""Local browser interface for RepoGuard.

The real application binds to IPv4 loopback only. A per-process token, strict
Host and Origin checks, and a non-embeddable UI protect privileged endpoints
from other websites. The optional public-preview mode can only show synthetic
data and cannot browse, scan local files, or query OSV.
"""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources, util
import json
import ntpath
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import webbrowser

from .reports import html_report
from .scanner import scan_directory

MAX_BODY_BYTES = 32768  # UTF-8 paths may use several bytes per character.
DEMO_TOKEN = 'repoguard-synthetic-demo'
SESSION_IDLE_SECONDS = 30 * 60
IDLE_CHECK_SECONDS = 30
_PICKER_CODE = r'''import json, sys, tkinter as tk
from tkinter import filedialog
root = tk.Tk()
root.withdraw()
try:
    root.attributes('-topmost', True)
except tk.TclError:
    pass
try:
    choice = filedialog.askdirectory(parent=root, title='Choisir le dossier du projet')
finally:
    root.destroy()
sys.stdout.write(json.dumps(choice, ensure_ascii=True))
'''
_WINDOWS_PICKER_CODE = r'''$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.Width = 1
$owner.Height = 1
$owner.Opacity = 0
$owner.Show()
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Choisir le dossier du projet'
$dialog.ShowNewFolderButton = $false
try {
    $choice = if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $dialog.SelectedPath } else { '' }
    [Console]::Out.Write((ConvertTo-Json -InputObject $choice -Compress))
} finally {
    $dialog.Dispose()
    $owner.Dispose()
}
'''


def _windows_powershell() -> str | None:
    if os.name != 'nt':
        return None
    system_root = os.environ.get('SystemRoot')
    if not system_root:
        return None
    path = Path(system_root) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    return str(path) if path.is_file() else None


def _picker_backend() -> str | None:
    try:
        found = util.find_spec('tkinter') is not None
    except (ImportError, ValueError):
        found = False
    display = not sys.platform.startswith('linux') or bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
    if found and display:
        return 'tk'
    # Python's official Windows embeddable distribution omits Tk; use the
    # built-in Windows Forms picker when Windows PowerShell is present.
    if _windows_powershell():
        return 'windows'
    return None


def _picker_available() -> bool:
    return _picker_backend() is not None


def _pick_directory() -> str | None:
    """Run a fixed picker program in an isolated process, never in the target tree."""
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
    backend = _picker_backend()
    if backend == 'tk':
        command = [sys.executable, '-I', '-c', _PICKER_CODE]
    elif backend == 'windows':
        executable = _windows_powershell()
        if not executable:
            raise OSError('Windows folder picker unavailable')
        command = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-STA', '-Command', _WINDOWS_PICKER_CODE]
    else:
        raise OSError('Folder picker unavailable')
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=180, check=True, encoding='utf-8', errors='strict', creationflags=flags)
    value = json.loads(result.stdout)
    if not isinstance(value, str):
        raise ValueError('Invalid picker response')
    return value or None


def _windows_network_path(value: str) -> bool:
    """Recognize explicit UNC paths and Windows drives identified as remote.

    This is a convenience safeguard, not a guarantee about a filesystem. A
    local-looking directory can still be mounted, redirected, or synchronized.
    """
    if value.startswith(('\\\\', '//')):
        return True
    if os.name != 'nt':
        return False
    drive = ntpath.splitdrive(ntpath.abspath(value))[0]
    if not re.fullmatch(r'[A-Za-z]:', drive):
        return True
    try:
        import ctypes
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive + '\\')
        return drive_type in {0, 1, 4}  # Unknown, no root, or DRIVE_REMOTE.
    except (AttributeError, OSError):
        # If the drive type cannot be determined, do not claim it is local.
        return True


def _local_directory(value: str) -> Path:
    """Accept a pasted Explorer 'copy as path', then resolve an existing folder."""
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value:
        raise ValueError('Choisissez un dossier ou indiquez son chemin.')
    if '://' in value:
        raise ValueError('Indiquez le chemin d’un dossier sur cet ordinateur, pas un lien Internet.')
    if os.name == 'nt' and _windows_network_path(value):
        raise ValueError('Choisissez un dossier local, pas un partage ou lecteur réseau.')
    try:
        path = Path(value).expanduser().resolve(strict=True)
        if os.name == 'nt' and _windows_network_path(str(path)):
            raise ValueError('Choisissez un dossier local, pas un partage ou lecteur réseau.')
        if not path.is_dir():
            raise ValueError('Dossier introuvable ou inaccessible. Vérifiez son chemin.')
    except (OSError, RuntimeError):
        raise ValueError('Dossier introuvable ou inaccessible. Vérifiez son chemin.') from None
    return path


def _synthetic_report():
    # Imported lazily to avoid a cli/web import cycle. It never reads a project.
    from .cli import _demo_report
    return _demo_report()


def _template(demo: bool) -> str:
    text = resources.files('repoguard').joinpath('web_assets').joinpath('index.html').read_text(encoding='utf-8')
    return text.replace('__REPOGUARD_MODE__', 'demo' if demo else 'local')


def _csp(template: str, demo: bool) -> str:
    def digest(content: str) -> str:
        return base64.b64encode(hashlib.sha256(content.encode('utf-8')).digest()).decode('ascii')
    style = re.search(r'<style>(.*?)</style>', template, re.DOTALL)
    script = re.search(r'<script>(.*?)</script>', template, re.DOTALL)
    report_style = re.search(r'<style>(.*?)</style>', html_report(_synthetic_report(), language='fr'), re.DOTALL)
    if not (style and script and report_style):
        raise RuntimeError('Static interface assets are incomplete')
    frame_ancestors = '' if demo else "; frame-ancestors 'none'"
    return ("default-src 'none'; "
            f"script-src 'sha256-{digest(script.group(1))}'; "
            f"style-src 'sha256-{digest(style.group(1))}' 'sha256-{digest(report_style.group(1))}'; "
            "connect-src 'self'; frame-src blob:; img-src data:; base-uri 'none'; form-action 'none'"
            + frame_ancestors)


class WebApp:
    def __init__(self, demo: bool = False):
        self.demo = demo
        self.token = DEMO_TOKEN if demo else secrets.token_urlsafe(32)
        self.can_pick = not demo and _picker_available()
        self.lock = threading.RLock()
        self.state = 'idle'
        self.progress = {'entries': 0, 'files': 0}
        self.summary: dict | None = None
        self.report_html: str | None = None
        self.error = ''
        self.picking = False
        self.last_activity = time.monotonic()
        self.template = _template(demo)
        self.csp = _csp(self.template, demo)

    def touch(self) -> None:
        with self.lock:
            self.last_activity = time.monotonic()

    def status(self) -> dict:
        with self.lock:
            return {'state': self.state, 'progress': dict(self.progress), 'summary': self.summary,
                    'error': self.error, 'can_pick': self.can_pick, 'demo': self.demo}

    def start(self, directory: object, deep: object, osv: object) -> tuple[bool, str]:
        if not isinstance(directory, str) or not isinstance(deep, bool) or not isinstance(osv, bool):
            return False, 'Les paramètres du scan sont invalides.'
        if len(directory) > 4096 or '\x00' in directory:
            return False, 'Le chemin du dossier est invalide.'
        if not self.demo:
            try:
                directory = str(_local_directory(directory))
            except ValueError as error:
                return False, str(error)
        with self.lock:
            if self.state == 'running':
                return False, 'Une analyse est déjà en cours.'
            self.state = 'running'
            self.progress = {'entries': 0, 'files': 0}
            self.summary = None
            self.report_html = None
            self.error = ''
        threading.Thread(target=self._scan, args=(directory, deep, osv), daemon=True,
                         name='repoguard-web-scan').start()
        return True, ''

    def _scan(self, directory: str, deep: bool, osv: bool) -> None:
        def progress(entries: int, files: int) -> None:
            with self.lock:
                self.progress = {'entries': entries, 'files': files}
        try:
            if self.demo:
                report = _synthetic_report()  # Never inspect path or contact OSV in demo.
            else:
                report = scan_directory(directory, deep=deep, use_osv=osv, progress=progress)
            summary = report.to_dict()['summary']
            rendered = html_report(report, language='fr')
            with self.lock:
                self.summary = summary
                self.progress = {'entries': report.file_entries_seen, 'files': report.files_scanned}
                self.report_html = rendered
                self.state = 'complete'
                self.last_activity = time.monotonic()
        except Exception:
            # Do not expose exception strings: they may include paths or source data.
            with self.lock:
                self.state = 'error'
                self.last_activity = time.monotonic()
                self.error = 'L’analyse n’a pas pu se terminer. Vérifiez le dossier et ses autorisations, puis réessayez.'

    def choose_folder(self) -> tuple[str | None, str]:
        if not self.can_pick:
            return None, 'La sélection de dossier n’est pas disponible ici. Colle le chemin dans le champ.'
        with self.lock:
            if self.picking:
                return None, 'Une fenêtre de sélection est déjà ouverte.'
            self.picking = True
        try:
            return _pick_directory(), ''
        except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError):
            return None, 'Impossible d’ouvrir la fenêtre de sélection. Colle le chemin dans le champ.'
        finally:
            with self.lock:
                self.picking = False


class RepoGuardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: WebApp):
        self.app = app
        super().__init__(address, _Handler)

    def handle_error(self, _request: object, _client_address: object) -> None:
        # A disconnected client or malformed input should not expose paths in logs.
        return


class _Handler(BaseHTTPRequestHandler):
    server: RepoGuardServer
    server_version = 'RepoGuard'
    sys_version = ''

    def log_message(self, _format: str, *args: object) -> None:
        # Never log request headers, path parameters, tokens or project names.
        return

    def _host_ok(self) -> bool:
        hosts = self.headers.get_all('Host', [])
        if len(hosts) != 1:
            return False
        raw = hosts[0].strip().lower()
        try:
            parsed = urlsplit('//' + raw)
            name, port = parsed.hostname, parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return False
        if name in {'localhost', '127.0.0.1'} and port == self.server.server_port:
            return True
        # The hosted preview is public but only runs the strictly synthetic demo.
        return bool(self.server.app.demo and name and name.endswith('.e2b.app') and port in (None, 443))

    def _origin_ok(self, required: bool) -> bool:
        origins = self.headers.get_all('Origin', [])
        if not origins:
            return not required
        if len(origins) != 1:
            return False
        raw = origins[0].strip().lower()
        if self.server.app.demo and raw == 'null':
            return True  # Sandboxed preview is synthetic and exposes no filesystem.
        try:
            parsed = urlsplit(raw)
            name, port = parsed.hostname, parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return False
        if parsed.scheme == 'http' and name in {'127.0.0.1', 'localhost'} and port == self.server.server_port:
            return True
        return bool(self.server.app.demo and parsed.scheme == 'https' and name and name.endswith('.e2b.app') and port in (None, 443))

    def _authorized(self) -> bool:
        tokens = self.headers.get_all('X-RepoGuard-Token', [])
        if len(tokens) != 1 or len(tokens[0]) > 128:
            return False
        try:
            valid = secrets.compare_digest(tokens[0].encode('ascii'), self.server.app.token.encode('ascii'))
        except (UnicodeError, TypeError):
            return False
        if valid:
            self.server.app.touch()
        return valid

    def _send(self, code: int, data: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', self.server.app.csp)
        if not self.server.app.demo:
            self.send_header('X-Frame-Options', 'DENY')
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, value: dict) -> None:
        self._send(code, json.dumps(value, ensure_ascii=True).encode('utf-8'), 'application/json; charset=utf-8')

    def _body(self) -> dict | None:
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
            return None
        try:
            length = int(lengths[0])
        except (ValueError, TypeError):
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        if self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
            return None
        try:
            self.connection.settimeout(10)
            body = self.rfile.read(length)
            if len(body) != length:
                return None
            value = json.loads(body.decode('utf-8'))
        except (OSError, ValueError, UnicodeError):
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self) -> None:
        if not self._host_ok() or not self._origin_ok(required=False):
            self._json(403, {'error': 'Accès refusé.'})
            return
        if self.path == '/':
            self._send(200, self.server.app.template.encode('utf-8'), 'text/html; charset=utf-8')
            return
        if not self._authorized():
            self._json(403, {'error': 'Session non autorisée. Relance RepoGuard sur cet ordinateur.'})
            return
        if self.path == '/api/status':
            self._json(200, self.server.app.status())
        elif self.path == '/api/report':
            with self.server.app.lock:
                report = self.server.app.report_html
            if report is None:
                self._json(404, {'error': 'Aucun rapport disponible.'})
            else:
                self._send(200, report.encode('utf-8'), 'text/html; charset=utf-8')
        else:
            self._json(404, {'error': 'Page introuvable.'})

    def do_POST(self) -> None:
        if not self._host_ok() or not self._origin_ok(required=True) or not self._authorized():
            self._json(403, {'error': 'Accès refusé.'})
            return
        data = self._body()
        if data is None:
            self._json(400, {'error': 'Requête invalide.'})
            return
        app = self.server.app
        if self.path == '/api/scan':
            if set(data) != {'directory', 'deep', 'osv'}:
                self._json(400, {'error': 'Les paramètres du scan sont invalides.'})
                return
            success, error = app.start(data['directory'], data['deep'], data['osv'])
            self._json(202 if success else 409 if 'déjà en cours' in error else 400,
                       {'ok': success, 'error': error})
        elif self.path == '/api/folder':
            if data:
                self._json(400, {'error': 'Requête invalide.'})
                return
            chosen, error = app.choose_folder()
            self._json(400 if error else 200, {'directory': chosen, 'error': error})
        elif self.path == '/api/shutdown':
            if data or app.demo:
                self._json(403, {'error': 'Arrêt indisponible dans la démonstration.'})
                return
            self._json(200, {'ok': True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._json(404, {'error': 'Page introuvable.'})

    def do_OPTIONS(self) -> None:
        # No CORS support; cross-origin JavaScript must never reach local APIs.
        self._json(403, {'error': 'Accès refusé.'})


def _stop_when_idle(server: RepoGuardServer, stop: threading.Event) -> None:
    """Stop abandoned local sessions; never interrupt an active scan or picker."""
    while not stop.wait(IDLE_CHECK_SECONDS):
        app = server.app
        with app.lock:
            idle = (app.state != 'running' and not app.picking
                    and time.monotonic() - app.last_activity >= SESSION_IDLE_SECONDS)
        if idle:
            server.shutdown()  # Called from this watcher, not the serve_forever thread.
            return


def _console(message: str) -> None:
    """Write French guidance even when a terminal has a legacy encoding."""
    if sys.stdout is None:
        return
    encoding = getattr(sys.stdout, 'encoding', None)
    if encoding:
        message = message.encode(encoding, errors='backslashreplace').decode(encoding)
    print(message, file=sys.stdout, flush=True)


def run_web(host: str = '127.0.0.1', port: int = 0, demo: bool = False,
            open_browser: bool = True) -> None:
    if not 0 <= port <= 65535:
        raise ValueError('Port must be between 0 and 65535.')
    if not demo and host != '127.0.0.1':
        raise ValueError('For safety, the real interface only binds to 127.0.0.1.')
    if demo and host not in {'127.0.0.1', '0.0.0.0'}:
        raise ValueError('Demo host must be 127.0.0.1 or 0.0.0.0.')
    app = WebApp(demo=demo)
    server = RepoGuardServer((host, port), app)
    local_url = f'http://127.0.0.1:{server.server_port}/'
    url = local_url if demo else local_url + '#' + app.token
    _console('RepoGuard : démonstration fictive.' if demo else 'RepoGuard est prêt.')
    _console('Ouvrez ce lien dans votre navigateur :')
    _console(url)
    if not demo:
        _console('Gardez ce lien privé et laissez ce terminal ouvert pendant l’utilisation.')
        _console('Pour arrêter RepoGuard, cliquez sur « Quitter » dans la page.')
    if open_browser:
        try:
            opened = webbrowser.open(url, new=1)
        except Exception:
            opened = False
        if not opened and sys.stdout is None:
            message = 'Ouvrez cette adresse dans votre navigateur sans la partager :\n\n' + url
            try:
                import tkinter.messagebox
                tkinter.messagebox.showinfo('RepoGuard', message)
            except Exception:
                if os.name == 'nt':
                    try:
                        import ctypes
                        ctypes.windll.user32.MessageBoxW(0, message, 'RepoGuard', 0x40)
                    except Exception:
                        pass
    stop_watcher = threading.Event()
    if not demo:
        threading.Thread(target=_stop_when_idle, args=(server, stop_watcher), daemon=True,
                         name='repoguard-idle-watcher').start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        stop_watcher.set()
        server.server_close()
