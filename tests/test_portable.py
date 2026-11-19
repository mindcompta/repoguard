"""Test the portable builder offline with a tiny synthetic runtime archive."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('repoguard_portable_builder', ROOT / 'scripts' / 'build-windows-portable.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def fake_runtime(extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name in ('python.exe', 'pythonw.exe', 'python314.zip', 'python314._pth', 'LICENSE.txt'):
            archive.writestr(name, b'fake-runtime')
        if extra:
            archive.writestr(extra, b'fake-runtime')
    return stream.getvalue()


class PortableBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'bundle.zip'

    def test_unverified_runtime_is_rejected_before_writing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            builder.build(self.output, fake_runtime())
        self.assertFalse(self.output.exists())

    def test_bundle_contains_launcher_assets_license_and_isolated_path(self):
        data = fake_runtime()
        with patch.object(builder, 'PYTHON_SHA256', hashlib.sha256(data).hexdigest()):
            builder.build(self.output, data)
        with zipfile.ZipFile(self.output) as archive:
            self.assertIsNone(archive.testzip())
            names = set(archive.namelist())
            for name in ('RepoGuard/Ouvrir-RepoGuard.bat', 'RepoGuard/Diagnostic-RepoGuard.bat',
                         'RepoGuard/Lancer-RepoGuard.pyw', 'RepoGuard/LISEZ-MOI-WINDOWS.txt',
                         'RepoGuard/LICENSE', 'RepoGuard/runtime/LICENSE.txt',
                         'RepoGuard/runtime/PYTHON-SOURCE.txt', 'RepoGuard/repoguard/web.py',
                         'RepoGuard/repoguard/web_assets/index.html'):
                self.assertIn(name, names)
            self.assertEqual(archive.read('RepoGuard/runtime/python314._pth'), b'python314.zip\r\n.\r\n..\r\n')
            self.assertFalse(any('Briefly' in name or '/tests/' in name for name in names))

    def test_unsafe_runtime_paths_are_rejected_even_after_hash_check(self):
        data = fake_runtime('../outside.txt')
        with patch.object(builder, 'PYTHON_SHA256', hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'Unexpected path'):
                builder.build(self.output, data)


if __name__ == '__main__':
    unittest.main()
