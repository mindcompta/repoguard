import unittest
from unittest.mock import patch

from repoguard.models import Dependency
from repoguard.osv import lookup


def dep(name, version='1.0.0', path='requirements.txt'):
    return Dependency('PyPI', name, version, path)


class OsvTests(unittest.TestCase):
    def test_no_supported_dependencies_makes_no_request(self):
        def fail(_payload):
            raise AssertionError('network should not be called')
        result = lookup([], post=fail)
        self.assertEqual(result.status, 'no_supported_dependencies')
        self.assertEqual(result.checked, 0)

    def test_deduplication_pagination_and_payload_privacy(self):
        calls = []
        def post(payload):
            calls.append(payload)
            if len(calls) == 1:
                return {'results': [
                    {'vulns': [{'id': 'GHSA-first'}], 'next_page_token': 'next-page'},
                    {'vulns': []},
                ]}
            return {'results': [{'vulns': [{'id': 'GHSA-first'}, {'id': 'CVE-2024-1000'}]}]}
        result = lookup([dep('alpha'), dep('alpha', path='other.txt'), dep('beta')], post=post)
        self.assertEqual(result.status, 'complete')
        self.assertEqual(result.checked, 2)
        self.assertEqual(result.matches[('PyPI', 'alpha', '1.0.0')], ['GHSA-first', 'CVE-2024-1000'])
        self.assertEqual(len(calls[0]['queries']), 2)
        self.assertEqual(len(calls[1]['queries']), 1)
        self.assertEqual(calls[1]['queries'][0]['page_token'], 'next-page')
        self.assertNotIn('requirements.txt', str(calls))
        self.assertEqual(set(calls[0]['queries'][0]), {'package', 'version'})

    def test_network_failure_is_partial(self):
        def post(_payload):
            raise OSError('offline')
        result = lookup([dep('alpha')], post=post)
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.checked, 0)
        self.assertTrue(result.warnings)

    def test_bad_response_is_partial(self):
        bad_responses = (None, {}, {'results': []}, {'results': ['oops']},
                         {'results': [{'vulns': 'oops'}]},
                         {'results': [{'vulns': [{'id': '<script>'}]}]},
                         {'results': [{'next_page_token': 123}]})
        for response in bad_responses:
            with self.subTest(response=response):
                result = lookup([dep('alpha')], post=lambda _: response)
                self.assertEqual(result.status, 'partial')
                self.assertEqual(result.checked, 0)
                self.assertTrue(result.warnings)

    def test_pagination_cap_is_partial_and_not_counted_as_checked(self):
        result = lookup([dep('alpha')], post=lambda _: {'results': [{'next_page_token': 'again'}]})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.checked, 0)
        self.assertIn('pagination', result.warnings[0].lower())

    def test_coordinate_cap_is_explicit(self):
        with patch('repoguard.osv.MAX_COORDINATES', 2):
            result = lookup([dep('one'), dep('two'), dep('three')],
                            post=lambda payload: {'results': [{} for _ in payload['queries']]})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.checked, 2)
        self.assertTrue(result.warnings)

    def test_advisory_cap_is_explicit(self):
        with patch('repoguard.osv.MAX_MATCHES', 2):
            result = lookup([dep('one')], post=lambda _: {'results': [{'vulns': [{'id': 'ONE'}, {'id': 'TWO'}, {'id': 'THREE'}]}]})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.matches[('PyPI', 'one', '1.0.0')], ['ONE', 'TWO'])
        self.assertEqual(result.checked, 0)


if __name__ == '__main__':
    unittest.main()
