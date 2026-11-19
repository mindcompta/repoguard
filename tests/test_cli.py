from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from repoguard.cli import main
from repoguard.models import ScanReport

ROOT = Path(__file__).resolve().parents[1]
VALUE = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5bC7'


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def command(self, *args):
        return subprocess.run([sys.executable, '-m', 'repoguard', *map(str, args)], cwd=ROOT,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def test_default_scan_and_json(self):
        (self.root / 'hello.txt').write_text('no credentials here', encoding='utf-8')
        result = self.command('scan', self.root, '--format', 'json')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['summary']['files_scanned'], 1)
        self.assertEqual(report['summary']['osv_status'], 'not_requested')
        self.assertFalse(report['summary']['file_scan_incomplete'])

    def test_finding_exit_threshold_and_redaction_all_formats(self):
        secret = 'gh' + 'p_' + VALUE[:36]
        (self.root / 'a.txt').write_text(secret, encoding='utf-8')
        for fmt in ('text', 'json', 'html', 'sarif'):
            with self.subTest(format=fmt):
                result = self.command('scan', self.root, '--format', fmt, '--fail-on', 'high')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn('GitHub token', result.stdout)
        self.assertEqual(self.command('scan', self.root).returncode, 0)

    def test_invalid_root_exits_two(self):
        result = self.command('scan', self.root / 'missing')
        self.assertEqual(result.returncode, 2)
        self.assertIn('existing directory', result.stderr)

    def test_partial_scan_has_precedence_over_findings(self):
        report = ScanReport(project='x', scan_incomplete=True)
        with patch('repoguard.cli.scan_directory', return_value=report), redirect_stdout(io.StringIO()):
            self.assertEqual(main(['scan', str(self.root), '--fail-on', 'high']), 2)
        report = ScanReport(project='x', osv_status='partial')
        with patch('repoguard.cli.scan_directory', return_value=report), redirect_stdout(io.StringIO()):
            self.assertEqual(main(['scan', str(self.root), '--osv']), 2)

    def test_output_does_not_overwrite_without_force(self):
        output = self.root / 'result.json'
        first = self.command('demo', '--format', 'json', '-o', output)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(output.stat().st_mode & 0o077, 0)
        original = output.read_text(encoding='utf-8')
        second = self.command('demo', '--format', 'json', '-o', output)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(output.read_text(encoding='utf-8'), original)
        if hasattr(os, 'O_NOFOLLOW'):
            third = self.command('demo', '--format', 'text', '-o', output, '--force')
            self.assertEqual(third.returncode, 0, third.stderr)
            self.assertIn('SYNTHETIC', output.read_text(encoding='utf-8'))

    def test_never_overwrites_symlink(self):
        target = self.root / 'target.txt'
        target.write_text('do not touch', encoding='utf-8')
        link = self.root / 'report.json'
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('symlinks not available')
        result = self.command('demo', '--format', 'json', '-o', link, '--force')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(target.read_text(encoding='utf-8'), 'do not touch')

    def test_demo_is_clearly_synthetic_and_sarif_is_parseable(self):
        demo = json.loads(self.command('demo', '--format', 'json').stdout)
        self.assertTrue(demo['demo'])
        self.assertEqual(demo['summary']['osv_status'], 'demo')
        self.assertEqual(demo['summary']['osv_queries'], 0)
        sarif = json.loads(self.command('demo', '--format', 'sarif').stdout)
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertTrue(sarif['runs'][0]['properties']['demo'])
        self.assertTrue(sarif['runs'][0]['results'])
        html = self.command('demo', '--format', 'html').stdout
        self.assertIn('Synthetic data', html)
        self.assertIn('no OSV request was made', html)


if __name__ == '__main__':
    unittest.main()
