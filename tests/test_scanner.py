from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from repoguard.models import Dependency, Finding, ScanReport
from repoguard.osv import OsvResult
from repoguard.reports import html_report, json_report, sarif_report, text_report
from repoguard.scanner import scan_directory

VALUE = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5bC7'


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def test_local_scan_is_read_only_and_never_calls_network(self):
        secret = 'gh' + 'p_' + VALUE[:36]
        path = self.write('config.env', 'TOKEN=' + secret + '\n')
        before = path.read_bytes()
        with patch('repoguard.scanner.lookup', side_effect=AssertionError('network called')):
            report = scan_directory(self.root)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(report.osv_status, 'not_requested')
        self.assertIn('RG-SEC-001', [f.rule_id for f in report.findings])
        for render in (text_report, json_report, sarif_report, html_report):
            self.assertNotIn(secret, render(report))

    def test_binary_git_and_symlink_are_skipped(self):
        secret = 'gh' + 'p_' + VALUE[:36]
        self.write('.git/config', secret)
        self.write('node_modules/dep/file.txt', secret)
        (self.root / 'image.bin').write_bytes(b'\x00binary')
        self.write('real.txt', 'safe')
        try:
            (self.root / 'link.txt').symlink_to(self.root / '.git/config')
        except OSError:
            pass  # Symlink creation may require privileges on Windows.
        report = scan_directory(self.root)
        self.assertEqual(report.findings, [])
        self.assertGreaterEqual(report.skipped_items, 3)
        self.assertEqual(report.binary_or_encoding_skipped, 1)

    def test_finding_path_is_escaped_in_html_and_control_chars_are_sanitized(self):
        name = '<img onerror=x>.txt'
        if os.name == 'nt':  # Angle brackets are not valid Windows filenames.
            report = ScanReport(project='fixture', findings=[Finding('RG-SEC-001', 'secret', 'high', 'Example', name, 1, 'Example', 'Review')])
        else:
            self.write(name, 'gh' + 'p_' + VALUE[:36])
            report = scan_directory(self.root)
        html = html_report(report)
        self.assertIn('&lt;img onerror=x&gt;', html)
        self.assertNotIn('<img onerror=x>', html)
        if os.name != 'nt':
            self.write('evil\x1b[31m.txt', 'gh' + 'p_' + VALUE[:36])
            self.assertNotIn('\x1b', text_report(scan_directory(self.root)))

    def test_missing_or_invalid_root(self):
        with self.assertRaises(ValueError):
            scan_directory(self.root / 'missing')
        with self.assertRaises(ValueError):
            scan_directory(self.write('regular.txt', 'x'))

    def test_size_and_file_count_limits_mark_scan_incomplete(self):
        self.write('a.txt', 'x' * 80)
        self.write('b.txt', 'hello')
        with patch('repoguard.scanner.MAX_FILE_BYTES', 64):
            report = scan_directory(self.root)
        self.assertTrue(report.scan_incomplete)
        self.assertTrue(any('limit' in item for item in report.warnings))
        with patch('repoguard.scanner.MAX_FILES', 1):
            report = scan_directory(self.root)
        self.assertTrue(report.scan_incomplete)
        self.assertTrue(any('stopped' in item for item in report.warnings))

    def test_unsupported_inventory_does_not_claim_complete_osv(self):
        self.write('package.json', '{"dependencies":{"x":"^1.0.0"}}')
        with patch('repoguard.scanner.lookup', return_value=OsvResult(status='no_supported_dependencies')):
            report = scan_directory(self.root, use_osv=True)
        self.assertTrue(report.inventory_incomplete)
        self.assertEqual(report.osv_status, 'partial')
        self.assertTrue(any('not inventoried' in item for item in report.warnings))

    def test_excluded_or_symlinked_lockfile_marks_inventory_incomplete(self):
        self.write('package.json', '{"dependencies":{"x":"^1.0.0"}}')
        lock = self.write('package-lock.json', '{"lockfileVersion":3,"packages":{}}')
        with patch('repoguard.scanner.lookup', return_value=OsvResult(status='no_supported_dependencies')):
            excluded = scan_directory(self.root, use_osv=True, excludes=('package-lock.json',))
        self.assertEqual(excluded.osv_status, 'partial')
        self.assertTrue(excluded.inventory_incomplete)
        lock.unlink()
        try:
            lock.symlink_to(self.root / 'somewhere-else.json')
        except OSError:
            self.skipTest('symlinks not available')
        with patch('repoguard.scanner.lookup', return_value=OsvResult(status='no_supported_dependencies')):
            symlinked = scan_directory(self.root, use_osv=True)
        self.assertEqual(symlinked.osv_status, 'partial')
        self.assertTrue(symlinked.inventory_incomplete)

    def test_osv_results_map_back_to_file_and_unknown_severity(self):
        self.write('requirements.txt', 'requests==2.31.0\n')
        coordinate = ('PyPI', 'requests', '2.31.0')
        mock_result = OsvResult(matches={coordinate: ['GHSA-demo']}, status='complete', checked=1)
        with patch('repoguard.scanner.lookup', return_value=mock_result):
            report = scan_directory(self.root, use_osv=True)
        self.assertEqual(report.osv_status, 'complete')
        finding = report.findings[0]
        self.assertEqual((finding.path, finding.line, finding.severity), ('requirements.txt', 1, 'unknown'))
        self.assertEqual(finding.reference, 'https://osv.dev/vulnerability/GHSA-demo')

    def test_exclusions_and_opt_in_inline_ignores(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('config.env', token + ' # repoguard:ignore\n')
        self.write('private/also.env', token)
        report = scan_directory(self.root, excludes=('private',))
        self.assertEqual(len(report.findings), 1)
        report = scan_directory(self.root, excludes=('private',), respect_inline_ignores=True)
        self.assertEqual(report.findings, [])
        self.assertTrue(report.inline_ignores_enabled)
        self.assertTrue(any('ignored lines' in item for item in report.warnings))

    def test_output_file_is_not_reingested(self):
        report_file = self.write('report.html', 'gh' + 'p_' + VALUE[:36])
        report = scan_directory(self.root, output_path=str(report_file))
        self.assertFalse(report.findings)
        self.assertEqual(report.skipped_items, 1)

    def test_finding_cap_marks_file_scan_incomplete(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('a.txt', (token + '\n') * 5)
        with patch('repoguard.scanner.MAX_FINDINGS', 2):
            report = scan_directory(self.root)
        self.assertTrue(report.scan_incomplete)
        self.assertEqual(len(report.findings), 2)


if __name__ == '__main__':
    unittest.main()
