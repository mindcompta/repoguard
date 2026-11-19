# Contributing

Thank you for helping improve RepoGuard. This is an early security aid: changes should make limitations visible rather than imply complete coverage.

1. Open an issue describing the problem or proposed change; do not include actual credentials or private source code.
2. Use Python 3.10+ and run `python -m unittest discover -s tests -v`.
3. Add focused tests for new rules, parsers, network errors, partial results and redaction as appropriate. Build fake credential strings at runtime from separate pieces; never commit live credentials, private source, or real reports.
4. Keep runtime dependencies at zero unless a change is explicitly discussed. Do not execute code from scanned projects.
5. Preserve opt-in network behavior, bounded reads, safe HTML escaping and clear coverage warnings. Check that a report does not deliberately copy source snippets or matched values.
6. Update both the README and the French guide when changing privacy, supported formats, or exit-code behavior.

Please follow the [security policy](SECURITY.md) for vulnerabilities in RepoGuard itself rather than posting exploit details publicly.
