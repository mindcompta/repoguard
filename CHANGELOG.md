# Changelog

## 0.3.0

- Added a real French-language browser interface. Start `python -m repoguard web --no-browser`, open the private local link printed in the terminal, then choose or paste a local project folder, select standard or deep coverage, explicitly decide whether to query OSV, and view/download the resulting HTML report in the browser.
- Added an x86-64 Windows portable archive and double-click launcher. It bundles the verified official Python 3.14.10 embeddable runtime and its license; a folder-picker fallback uses the Windows Forms component when Tk is not included. A pasted local path works if the picker is unavailable.
- The real server binds to `127.0.0.1` with a per-session token, Host/Origin checks, a restrictive content security policy and no CORS. Reports remain in memory unless downloaded. A Quit button and 30-minute inactivity shutdown limit abandoned sessions. These are not protections against malicious local software.
- The separately enabled public-preview mode serves only synthetic data and cannot scan files or query OSV. It is not a hosted version of the real scanner.
- Added HTTP/security, path, concurrency, opt-in, portable-build and launcher tests; existing CLI formats and schema version 2 remain supported. Human-readable OSV status no longer instructs browser users to type a command.

**Limits remain:** An empty report is not proof of safety; project code is not executed, Git history and binary/archive contents are not scanned, and OSV is optional and bounded. Network-mounted and synchronized folders can transfer data independently of RepoGuard and may not all be detected. Downloaded reports can contain sensitive metadata.

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
