import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from repoguard.models import Dependency
from repoguard.osv import OsvResult
from repoguard.reports import html_report, json_report, sarif_report, text_report
from repoguard.scanner import scan_directory

VALUE = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5bC7'


class DeepCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding='utf-8')
        return path

    def hidden_lock(self):
        return json.dumps({'lockfileVersion': 3, 'packages': {
            'node_modules/example': {'version': '1.2.3'},
        }})

    def test_standard_includes_dist_and_hidden_lock_but_not_vendored_sources(self):
        publisher = 'pub-' + '1234567890123456'
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('dist/ads.txt', 'google.com, ' + publisher + ', DIRECT\n')
        self.write('node_modules/.package-lock.json', self.hidden_lock())
        self.write('node_modules/example/file.txt', token)
        self.write('.git/config', token)
        report = scan_directory(self.root)
        self.assertEqual([x.rule_id for x in report.observations], ['RG-INFO-001'])
        self.assertEqual(report.findings, [])
        self.assertEqual([x.coordinate for x in report.dependencies], [('npm', 'example', '1.2.3')])
        self.assertEqual({x.path for x in report.scanned_files}, {'dist/ads.txt', 'node_modules/.package-lock.json'})
        self.assertEqual(report.skipped_by_reason['standard_excluded_directory'], 1)
        self.assertEqual(report.skipped_by_reason['vcs_metadata'], 1)
        self.assertIn('node_modules', [item.path for item in report.skipped_details])
        for render in (text_report, json_report, sarif_report, html_report):
            rendered = render(report)
            self.assertNotIn(publisher, rendered)
            self.assertNotIn(token, rendered)

    def test_deep_scans_third_party_and_inventories_installed_manifest(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('node_modules/.package-lock.json', self.hidden_lock())
        self.write('node_modules/example/package.json', json.dumps({'name': 'example', 'version': '1.2.3'}))
        self.write('node_modules/example/file.txt', token)
        self.write('node_modules/example/test/package.json', json.dumps({'name': 'not-installed', 'version': '9.9.9'}))
        self.write('.git/config', token)
        report = scan_directory(self.root, deep=True)
        self.assertEqual(report.scope, 'deep')
        self.assertEqual(len(report.findings), 1)
        self.assertEqual((report.findings[0].origin, report.findings[0].path), ('third_party', 'node_modules/example/file.txt'))
        self.assertEqual(len(report.dependencies), 2)
        self.assertEqual(len({d.coordinate for d in report.dependencies}), 1)
        self.assertFalse(report.inventory_incomplete)
        self.assertEqual(report.skipped_by_reason['vcs_metadata'], 1)
        self.assertIn('node_modules/example/file.txt', [item.path for item in report.scanned_files])

    def test_duplicate_osv_matches_for_same_version_are_reported_once(self):
        self.write('node_modules/.package-lock.json', self.hidden_lock())
        self.write('node_modules/example/package.json', json.dumps({'name': 'example', 'version': '1.2.3'}))
        coord = ('npm', 'example', '1.2.3')
        mock = OsvResult(matches={coord: ['GHSA-example']}, status='complete', checked=1)
        with patch('repoguard.scanner.lookup', return_value=mock) as lookup:
            report = scan_directory(self.root, deep=True, use_osv=True)
        self.assertEqual(len(report.dependencies), 2)
        self.assertEqual(len([f for f in report.findings if f.category == 'dependency']), 1)
        self.assertEqual(report.osv_status, 'complete')
        self.assertEqual(len(lookup.call_args.args[0]), 2)

    def test_excluding_node_modules_also_excludes_its_hidden_lock(self):
        self.write('node_modules/.package-lock.json', self.hidden_lock())
        for deep in (False, True):
            report = scan_directory(self.root, excludes=('node_modules',), deep=deep)
            self.assertEqual(report.dependencies, [])
            self.assertEqual(report.files_scanned, 0)
            self.assertEqual(report.skipped_by_reason['user_excluded_directory'], 1)

    def test_utf16_utf32_and_windows_1252_text_and_skipped_binary(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('u16.txt', ('clé=' + token).encode('utf-16'))
        self.write('u32.txt', ('clé=' + token).encode('utf-32'))
        self.write('windows.txt', ('café=' + token).encode('cp1252'))
        self.write('image.bin', b'\x00not text')
        report = scan_directory(self.root)
        self.assertEqual(len(report.findings), 3)
        self.assertEqual(report.encoding_counts, {'UTF-16 BOM': 1, 'UTF-32 BOM': 1, 'Windows-1252 heuristic': 1})
        self.assertEqual(report.skipped_by_reason['binary_or_non_text'], 1)
        self.assertEqual(report.binary_or_encoding_skipped, 1)

    def test_archive_content_not_claimed_as_scanned(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('backup.zip', token)  # Even an archive-named text file is not opened.
        report = scan_directory(self.root, deep=True)
        self.assertFalse(report.findings)
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(report.skipped_by_reason['archive_or_document_not_opened'], 1)

    def test_large_file_prefix_is_scanned_but_tail_is_explicitly_incomplete(self):
        token = 'gh' + 'p_' + VALUE[:36]
        self.write('big.txt', token + '\n' + 'x' * 200)
        with patch('repoguard.scanner.MAX_FILE_BYTES', 64):
            report = scan_directory(self.root)
        self.assertEqual([f.rule_id for f in report.findings], ['RG-SEC-001'])
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.files_partially_scanned, 1)
        self.assertTrue(report.scan_incomplete)
        self.assertEqual(report.skipped_by_reason['file_size_limit'], 1)
        self.assertTrue(report.scanned_files[0].partial)
        self.assertEqual(report.scanned_files[0].bytes_scanned, 64)
        self.assertTrue(any('first 64 bytes' in warning for warning in report.warnings))

    def test_utf8_cut_mid_codepoint_still_scans_the_valid_prefix(self):
        self.write('unicode.txt', ('x' * 31 + '€' + 'tail').encode('utf-8'))
        report = scan_directory(self.root, max_file_bytes=33)
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.encoding_counts, {'UTF-8': 1})
        self.assertTrue(report.scan_incomplete)
        self.assertEqual(report.files_partially_scanned, 1)

    def test_total_limit_and_detail_caps_are_visible(self):
        self.write('a.txt', 'x' * 20)
        self.write('b.txt', 'y' * 100)
        self.write('c.txt', 'z' * 20)
        report = scan_directory(self.root, max_total_bytes=50)
        self.assertEqual(report.bytes_examined, 50)
        self.assertTrue(report.scan_incomplete)
        self.assertEqual(report.skipped_by_reason['total_byte_limit'], 1)
        self.write('d.zip', 'unused')
        self.write('e.zip', 'unused')
        with patch('repoguard.scanner.MAX_SCANNED_DETAILS', 1), patch('repoguard.scanner.MAX_SKIPPED_DETAILS', 1):
            report = scan_directory(self.root)
        coverage = report.to_dict()['coverage']
        self.assertEqual(len(coverage['scanned_files']), 1)
        self.assertEqual(coverage['scanned_file_details_omitted'], 2)
        self.assertEqual(coverage['skipped_details_omitted'], 1)
        self.assertFalse(report.scan_incomplete)  # Only the listing was truncated.
        self.assertIn('entrées supplémentaires omises', html_report(report, language='fr'))

    def test_malformed_installed_manifest_and_unsupported_lock_are_visible(self):
        self.write('node_modules/foo/package.json', '{bad-json')
        self.write('yarn.lock', 'format not parsed')
        with patch('repoguard.scanner.lookup', return_value=OsvResult(status='no_supported_dependencies')):
            report = scan_directory(self.root, deep=True, use_osv=True)
        self.assertTrue(report.inventory_incomplete)
        self.assertEqual(report.osv_status, 'partial')
        self.assertEqual(len(report.warnings), 3)
        html = html_report(report, language='fr')
        self.assertIn('format de dépendances n’est pas inventorié', html)
        self.assertIn('impossible à lire', html)


if __name__ == '__main__':
    unittest.main()
