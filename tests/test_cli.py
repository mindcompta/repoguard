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

from repoguard.cli import _write, main
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
                              text=True, encoding='utf-8', env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

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
        if os.name != 'nt':  # Windows permissions are governed by ACLs, not POSIX mode bits.
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

    def test_french_report_and_informational_result_do_not_fail_threshold(self):
        publisher = 'pub-' + '1234567890123456'
        (self.root / 'ads.txt').write_text('google.com, ' + publisher + ', DIRECT', encoding='utf-8')
        result = self.command('scan', self.root, '--deep', '--lang', 'fr', '--fail-on', 'low', '--format', 'html')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Informations publiques et configurations', result.stdout)
        self.assertIn('ne sont pas automatiquement des secrets ou des failles', result.stdout)
        self.assertIn('Identifiant éditeur Google publicitaire', result.stdout)
        self.assertIn('Liste des fichiers analysés', result.stdout)
        self.assertNotIn(publisher, result.stdout)
        data = json.loads(self.command('scan', self.root, '--format', 'json').stdout)
        self.assertEqual(data['schema_version'], 2)
        self.assertEqual(data['summary']['public_information'], 1)
        self.assertEqual(data['summary']['possible_secrets'], 0)
        sarif = json.loads(self.command('scan', self.root, '--format', 'sarif').stdout)
        item = sarif['runs'][0]['results'][0]
        self.assertEqual((item['level'], item['kind'], item['properties']['category']), ('note', 'informational', 'information'))
        self.assertIn('coverage', sarif['runs'][0]['properties'])

    def test_legacy_console_encodings_do_not_crash_html_or_json(self):
        sink = io.TextIOWrapper(io.BytesIO(), encoding='cp1252')
        with redirect_stdout(sink):
            _write('Hello ' + chr(0x1F600), None, False, report_format='html')
            sink.flush()
        self.assertIn(b'&#128512;', sink.buffer.getvalue())
        report = ScanReport(project='project-' + chr(0x1F600))
        from repoguard.reports import json_report, sarif_report
        for render in (json_report, sarif_report):
            payload = render(report)
            self.assertTrue(payload.isascii())
            json.loads(payload)

    def test_invalid_custom_limits_exit_two(self):
        for arguments in (('--max-file-mib', '0'), ('--max-file-mib', '129'),
                          ('--max-total-mib', '0'), ('--max-files', '0')):
            result = self.command('scan', self.root, *arguments)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('limits', result.stderr.lower())

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
