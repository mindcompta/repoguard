import json
import unittest

from repoguard.dependencies import extract_dependencies, is_dependency_file


class DependencyTests(unittest.TestCase):
    def test_requirements_exact_versions_and_markers(self):
        text = '# comment\nRequests==2.31.0\nMy_Package[cli]==1.2.3; python_version < "4"\nloose>=1.0\n-r extras.txt\n'
        deps, warnings = extract_dependencies('requirements.txt', text)
        self.assertEqual([(d.name, d.version, d.line) for d in deps], [('requests', '2.31.0', 2), ('my-package', '1.2.3', 3)])
        self.assertEqual(len(warnings), 1)
        self.assertIn('2 non-exact or unsupported', warnings[0])

    def test_other_requirements_paths(self):
        self.assertTrue(is_dependency_file('config/requirements/dev.txt'))
        self.assertTrue(is_dependency_file('requirements-test.txt'))
        self.assertFalse(is_dependency_file('notes.txt'))
        deps, warnings = extract_dependencies('config/requirements/dev.txt', 'Django==4.2.1\n')
        self.assertEqual(deps[0].name, 'django')
        self.assertFalse(warnings)

    def test_npm_lock_v3_scoped_nested_and_skipped_links(self):
        text = json.dumps({'lockfileVersion': 3, 'packages': {
            '': {'name': 'root'},
            'node_modules/lodash': {'version': '4.17.20'},
            'node_modules/@scope/name': {'version': '1.2.3-beta.1'},
            'node_modules/a/node_modules/lodash': {'version': '4.17.21'},
            'node_modules/workspace': {'link': True},
            'node_modules/file-package': {'version': 'file:../x'},
        }})
        deps, warnings = extract_dependencies('package-lock.json', text)
        self.assertEqual([(d.name, d.version) for d in deps], [('lodash', '4.17.20'), ('@scope/name', '1.2.3-beta.1'), ('lodash', '4.17.21')])
        self.assertIn('2 dependency', warnings[0])
        self.assertTrue(all(d.line == 1 for d in deps))

    def test_npm_lock_v1_nested(self):
        text = json.dumps({'lockfileVersion': 1, 'dependencies': {
            'alpha': {'version': '1.0.0', 'dependencies': {'@scope/beta': {'version': '2.0.0'}}},
        }})
        deps, warnings = extract_dependencies('package-lock.json', text)
        self.assertEqual([(d.name, d.version) for d in deps], [('alpha', '1.0.0'), ('@scope/beta', '2.0.0')])
        self.assertEqual(warnings, [])

    def test_invalid_or_unsupported_lock_is_not_silently_clean(self):
        for text in ('{', '[]', '{}', '{"lockfileVersion": 9}', '{"lockfileVersion": 3}'):
            with self.subTest(text=text):
                deps, warnings = extract_dependencies('package-lock.json', text)
                self.assertEqual(deps, [])
                self.assertTrue(warnings)

    def test_requirements_pins_only_and_no_execution(self):
        deps, warnings = extract_dependencies('requirements.txt', 'git+https://example.test/repo\npackage==1.*\n-e ./local\n')
        self.assertFalse(deps)
        self.assertTrue(warnings)


if __name__ == '__main__':
    unittest.main()
