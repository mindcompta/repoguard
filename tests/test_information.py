import json
import unittest
from dataclasses import asdict

from repoguard.information import MAX_OBSERVATIONS_PER_FILE, scan_information
from repoguard.rules import scan_text


class InformationTests(unittest.TestCase):
    def test_public_configuration_is_separate_and_redacted(self):
        publisher = 'pub-' + '1234567890123456'
        key = 'AI' + 'za' + 'Ab3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA'[:35]
        endpoint = 'project-example' + '.firebaseapp.com'
        analytics = 'GTM-' + 'A1B2C3D'
        content = '\n'.join([publisher, 'ads' + 'bygoogle', key, endpoint, analytics])
        results = scan_information('dist/index.js', content, origin='generated')
        self.assertEqual({x.rule_id for x in results},
                         {'RG-INFO-001', 'RG-INFO-002', 'RG-INFO-003', 'RG-INFO-004', 'RG-INFO-005'})
        self.assertTrue(all(x.category == 'information' and x.severity == 'info' and x.origin == 'generated' for x in results))
        serialized = json.dumps([asdict(x) for x in results])
        for value in (publisher, key, endpoint, analytics):
            self.assertNotIn(value, serialized)
        self.assertEqual([item.line for item in results], [1, 2, 3, 4, 5])

    def test_browser_api_key_is_not_automatically_a_secret(self):
        key = 'AI' + 'za' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r'[:35]
        source = 'api_key="' + key + '"'
        self.assertEqual(scan_text('config.js', source), [])
        self.assertEqual([x.rule_id for x in scan_information('config.js', source)], ['RG-INFO-003'])

    def test_observations_one_per_rule_and_line_and_ignore_is_opt_in(self):
        publisher = 'pub-' + '1234567890123456'
        text = publisher + ' ' + publisher + ' # repoguard:ignore\n'
        found = scan_information('ads.txt', text)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, 1)
        self.assertEqual(scan_information('ads.txt', text, respect_inline_ignores=True), [])

    def test_per_file_information_cap(self):
        publisher = 'pub-' + '1234567890123456'
        found = scan_information('ads.txt', (publisher + '\n') * (MAX_OBSERVATIONS_PER_FILE + 1))
        self.assertEqual(len(found), MAX_OBSERVATIONS_PER_FILE)

    def test_incomplete_or_wrong_advertising_identifier_is_not_a_match(self):
        self.assertEqual(scan_information('ads.txt', 'pub-' + '123456789012345' + '\n'), [])
        self.assertEqual(scan_information('ads.txt', 'pub-' + '12345678901234567' + '\n'), [])


if __name__ == '__main__':
    unittest.main()
