#!/usr/bin/env python3
"""Build a Windows x64 portable ZIP using a pinned official Python runtime.

Only an explicit list of application files is packaged. The embedded Python
ZIP is verified against the SHA-256 published on python.org before use.
Building is a developer task; users of the finished archive need no Python.
"""
import argparse
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PYTHON_URL = 'https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip'
PYTHON_SHA256 = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
MAX_DOWNLOAD = 20_000_000
MAX_UNPACKED = 100_000_000


def _zip_write(archive: zipfile.ZipFile, name: str, contents: bytes, store: bool = False) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, contents, compress_type=zipfile.ZIP_STORED if store else zipfile.ZIP_DEFLATED,
                     compresslevel=None if store else 6)


def build(output: Path, embedded_zip: bytes) -> None:
    actual = hashlib.sha256(embedded_zip).hexdigest()
    if actual != PYTHON_SHA256:
        raise ValueError('Embedded Python archive SHA-256 does not match the official pinned value')
    application = ['Ouvrir-RepoGuard.bat', 'Diagnostic-RepoGuard.bat', 'Lancer-RepoGuard.pyw',
                   'LISEZ-MOI-WINDOWS.txt', 'LICENSE', 'repoguard/web_assets/index.html']
    application += [path.relative_to(ROOT).as_posix() for path in sorted((ROOT / 'repoguard').glob('*.py'))]
    with zipfile.ZipFile(io.BytesIO(embedded_zip)) as python, zipfile.ZipFile(output, 'w') as bundle:
        entries = python.infolist()
        if sum(entry.file_size for entry in entries) > MAX_UNPACKED:
            raise ValueError('Embedded Python archive exceeds the unpacked size limit')
        names = {entry.filename for entry in entries}
        required = {'python.exe', 'pythonw.exe', 'python314.zip', 'python314._pth', 'LICENSE.txt'}
        if not required.issubset(names):
            raise ValueError('Embedded Python archive is missing required files')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if entry.is_dir() or path.is_absolute() or '..' in path.parts or '\\' in entry.filename:
                raise ValueError('Unexpected path in embedded Python archive')
            data = python.read(entry)
            if entry.filename == 'python314._pth':
                # Isolated mode keeps installed modules out. The application is
                # the parent of runtime/, never the directory being scanned.
                data = b'python314.zip\r\n.\r\n..\r\n'
            _zip_write(bundle, 'RepoGuard/runtime/' + entry.filename, data)
        provenance = ('Official Python 3.14.10 embeddable distribution for Windows x86-64\n'
                      + PYTHON_URL + '\nSHA-256 of the original archive: ' + PYTHON_SHA256
                      + '\npython314._pth was adjusted to include the RepoGuard application directory.\n')
        _zip_write(bundle, 'RepoGuard/runtime/PYTHON-SOURCE.txt', provenance.encode('utf-8'))
        for item in application:
            _zip_write(bundle, 'RepoGuard/' + item, (ROOT / item).read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('RepoGuard-Windows-v0.3.0.zip'))
    parser.add_argument('--python-archive', type=Path, help='Previously downloaded official embedded Python ZIP')
    args = parser.parse_args()
    if args.python_archive:
        data = args.python_archive.read_bytes()
    else:
        with urllib.request.urlopen(PYTHON_URL, timeout=60) as response:
            data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError('Embedded Python archive exceeds the download size limit')
    build(args.output, data)
    print('Created:', args.output)
    print('SHA-256:', hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
