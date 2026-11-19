# Changelog

## 0.2.0

- Standard scans now include generated `dist` and `build` folders and can inspect the hidden npm lock even when `node_modules` is otherwise skipped.
- `--deep` additionally scans dependency, vendor and cache directories with higher, configurable bounds; reports distinguish project, generated and third-party results.
- Reports show analyzed-file inventories, skipped paths and reasons, encoding counts, partial files, actual limits and omitted-detail counts.
- Public/configuration indicators are separate from security findings: Google advertising identifiers and integration markers, Google API-key-shaped values, Firebase endpoints, and Google Analytics/Tag Manager IDs. They never trigger `--fail-on` and are not proof of vulnerabilities. Matched values are not deliberately copied.
- Added support for npm shrinkwrap files and exact versions in installed npm package manifests; hidden npm locks may be stale. Duplicate OSV advisories for the same coordinate are consolidated.
- Added UTF-16/32 BOM and heuristic Windows-1252 text support, bounded prefix analysis of large text files, French text/HTML reports, progress, new credential-pattern rules and a Windows PowerShell helper.
- Added Windows CI and expanded synthetic tests. JSON schema version is now `2`; the existing summary fields remain, with new coverage and observation fields.

**Limits remain:** Git history, other branches, binary/image/PDF and archive contents are not analyzed. Rules are heuristic and incomplete, line-based reporting can merge matches, OSV and inventory coverage can be partial, and third-party sources often contain examples. Review sensitive report metadata before sharing.

## 0.1.0

- Initial local-first working-tree credential scanner, optional OSV lookup, HTML/JSON/SARIF/text reports and synthetic demonstration.
