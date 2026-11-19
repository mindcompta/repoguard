import json
import unittest
from dataclasses import asdict

from repoguard.rules import scan_text

# All credentials below are fabricated at runtime. They do not grant access to anything.
VALUE = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5bC7'


class RuleTests(unittest.TestCase):
    def assert_rule(self, rule_id, content):
        findings = scan_text('sample.conf', content)
        self.assertIn(rule_id, [item.rule_id for item in findings])
        self.assertNotIn(content, json.dumps([asdict(item) for item in findings]))
        return findings

    def test_supported_provider_patterns(self):
        examples = {
            'RG-SEC-001': 'gh' + 'p_' + VALUE[:36],
            'RG-SEC-002': 'github_' + 'pat_' + VALUE[:30],
            'RG-SEC-003': '-----BEGIN ' + 'RSA PRIVATE KEY-----',
            'RG-SEC-004': 'sk_' + 'live_' + VALUE[:28],
            'RG-SEC-005': 'xox' + 'b-' + VALUE[:30],
            'RG-SEC-006': 'AK' + 'IA' + '1234567890ABCDEF',
            'RG-SEC-009': 'gl' + 'pat-' + VALUE[:25],
            'RG-SEC-010': 'np' + 'm_' + VALUE[:36],
            'RG-SEC-011': 'GOC' + 'SPX-' + VALUE[:30],
            'RG-SEC-012': 'ya' + '29.' + VALUE[:32],
            'RG-SEC-013': 'S' + 'G.' + VALUE[:22] + '.' + (VALUE * 2)[:43],
            'RG-SEC-014': 's' + 'k-proj-' + VALUE[:36],
        }
        for rule, example in examples.items():
            with self.subTest(rule=rule):
                result = self.assert_rule(rule, example)
                self.assertNotIn(example, repr(result))

    def test_generic_assignment_variants(self):
        for prefix, suffix in [
            ('API_KEY=', ''), ('AWS_SECRET_ACCESS_KEY=', ''),
            ('"password": "', '"'), ('db_password = \'', "'"),
            ('client_secret: ', ''), ('ACCESS_TOKEN="', '"'),
        ]:
            with self.subTest(prefix=prefix):
                items = scan_text('file.env', prefix + VALUE + suffix)
                self.assertIn('RG-SEC-007', [item.rule_id for item in items])
                self.assertNotIn(VALUE, repr(items))

    def test_placeholders_and_env_references_are_not_reported_by_generic_rule(self):
        for value in ('example-secret-value', 'changeme123456', '${PASSWORD_FROM_ENV}', 'aaaaaaaaaaaaaaaa', 'sample-key-1234567', 'wrong-password', 'invalid-id-token'):
            with self.subTest(value=value):
                self.assertNotIn('RG-SEC-007', [f.rule_id for f in scan_text('a', 'password="' + value + '"')])

    def test_multiple_assignments_on_one_line_do_not_hide_a_real_match(self):
        line = 'password="sample-password"; api_key="' + VALUE + '"'
        self.assertIn('RG-SEC-007', [f.rule_id for f in scan_text('a', line)])

    def test_specific_token_is_not_double_counted_as_generic_assignment(self):
        token = 'gh' + 'p_' + VALUE[:36]
        result = scan_text('config', 'TOKEN=' + token)
        self.assertEqual([f.rule_id for f in result], ['RG-SEC-001'])
        result = scan_text('config', 'TOKEN=' + token + '; password="' + VALUE + '"')
        self.assertEqual({f.rule_id for f in result}, {'RG-SEC-001', 'RG-SEC-007'})

    def test_connection_url_without_returning_its_password(self):
        url = 'postgresql://' + 'admin:' + VALUE + '@db.example.test/app'
        result = self.assert_rule('RG-SEC-008', url)
        self.assertNotIn(VALUE, repr(result))

    def test_line_numbers_and_suppression_is_opt_in(self):
        token = 'gh' + 'p_' + VALUE[:36]
        text = 'line one\n' + token + '  # repoguard:ignore\n'
        result = scan_text('config', text)
        self.assertEqual(result[0].line, 2)
        self.assertEqual(scan_text('config', text, respect_inline_ignores=True), [])

    def test_file_finding_limit(self):
        token = 'gh' + 'p_' + VALUE[:36]
        findings = scan_text('a', (token + '\n') * 1100)
        self.assertEqual(len(findings), 1000)


if __name__ == '__main__':
    unittest.main()
