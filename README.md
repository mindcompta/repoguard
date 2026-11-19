# RepoGuard

**A local-first, explainable first look at repository security.** RepoGuard checks working files for some credential patterns, inventories selected exact dependency versions, and can query [OSV.dev](https://osv.dev/). It also separately identifies a few public configuration indicators, including Google advertising publisher IDs and Google API-key-shaped values. Reports do not deliberately copy matched source lines or values.

[Français](README.fr.md) · [Website](https://mindcompta.github.io/repoguard/) · [Synthetic report demo](https://mindcompta.github.io/repoguard/demo/) · [Security policy](SECURITY.md)

![Example RepoGuard report, using synthetic data](assets/report-demo.png)

> **Scope matters:** RepoGuard is a limited security aid, not a full audit. It can miss issues or flag harmless examples. An empty report is **not** proof that a project is safe. A publicly visible publisher ID, Firebase endpoint or browser API key is not automatically a secret or a vulnerability; verify the relevant configuration.

## What it does

- Scans supported text in a working tree without executing the scanned project. Fourteen explainable rules look for some GitHub, GitLab, Slack, Stripe, npm, Google OAuth, SendGrid and other API credential patterns, private-key markers, generic assignments, and passwords in connection URLs. An AWS access key ID is not the corresponding secret key.
- Reports some **informational** indicators separately: Google advertising publisher IDs and integration markers, Google API-key-shaped strings, Firebase endpoints, and Google Analytics/Tag Manager identifiers. These are not vulnerability verdicts. Key restrictions, Firebase security rules and whether services are active are **not checked**. Some Google API keys, including Gemini Developer API keys, must be kept secret; consult the [Firebase API-key guidance](https://firebase.google.com/docs/projects/api-keys).
- Inventories exact versions in supported npm/PyPI files. With explicit `--osv`, checks those versions against OSV. It does not assess advisory severity or exploitability or select an automatic fix.
- Produces standalone HTML, text, JSON and SARIF 2.1.0 reports, including file inventories, omissions, reason counts, limits and coverage warnings. Human-readable HTML and text support English and French.
- Defaults to local analysis: source files and reports are not transmitted. `--osv` is an explicit network opt-in. Python 3.10+ and no third-party **runtime** dependencies are required.

## Start the browser interface from a terminal

With Python 3.10+ installed, extract the source archive and open a terminal in its folder. As with a local development server, start RepoGuard and then use the interface in your browser:

```bash
python3 -m repoguard web --no-browser
```

On Windows use `py -3` or `python` instead of `python3`; on Termux, `python` also works. No npm installation or third-party runtime library is needed when running directly from the source directory. The terminal prints a private local URL beginning with `http://127.0.0.1:`. Open the **entire** URL, including its `#` fragment, on the same device; the address and token change on every start. Keep the terminal open and the link private. Omit `--no-browser` to try opening it automatically.

Choose or paste a local project path in the interface, select standard or deep scope, decide whether to query OSV, and read or download the report. The **Quitter** button stops the server. Some platforms, notably Termux, may not have a folder picker; paste an accessible path instead and ensure the operating system grants access. As an optional installation step, `python3 -m pip install .` installs the package and may download build tools; the web command can then run outside the source folder.

## Alternative: portable Windows browser interface without typing commands

1. Download **`RepoGuard-Windows-v0.3.0.zip`** accompanying this version, or check the [published releases](https://github.com/mindcompta/repoguard/releases). The portable build is for **Windows 10/11 x86-64** and bundles Python 3.14.10; no separate Python installation is required. Windows may warn that this software is unsigned: check its source.
2. Right-click the ZIP and **Extract All** into a folder separate from your projects. Do not run the launcher from inside the ZIP.
3. Double-click **`Ouvrir-RepoGuard.bat`**. The local browser interface opens. Choose a local folder or paste its path, choose standard or deep scope, and explicitly choose whether to query OSV. Quoted paths copied from Windows Explorer are accepted. If the folder picker is unavailable, paste the path instead.
4. Read the report directly in the page, download the HTML if you want to keep it, and click **Quitter** to stop the app. The interface and this portable launcher are in French.

The report is held in memory until the app stops unless you download it. Closing a tab does not stop the app immediately: it exits after 30 minutes with no communication from the page, but not while a scan or folder picker is active. Browser-suspended tabs can be treated as inactive. Keep the opening address private; it contains a per-session token. The server binds only to `127.0.0.1` and checks the token, Host and Origin, but is not a security boundary against malicious local software or other processes under your account. Windows network shares and mapped network drives are rejected where detected, but local-looking mounts and synchronization services cannot all be identified: they may transfer files independently of RepoGuard. Downloaded reports can contain sensitive paths and package names.

If your browser does not open, double-click `Diagnostic-RepoGuard.bat` and paste its private address into the browser. The source archive, unlike the portable Windows ZIP, requires Python 3.10+. On Linux, macOS and Termux, `python3 -m repoguard web` opens the same interface when Python is available; the bundled double-click launcher targets Windows.

## Command-line quick start

```bash
git clone https://github.com/mindcompta/repoguard.git
cd repoguard
python3 -m repoguard scan /path/to/your-project
```

Create a deeper offline HTML report, preferably outside the scanned project:

```bash
python3 -m repoguard scan /path/to/your-project --deep --progress \
  --format html -o ~/repoguard-report.html
```

Add `--lang fr` for a French text or HTML report. Open the HTML file in a browser; it is not published online. Deep scans can take minutes and produce many unverified findings in third-party libraries. To preview the design without scanning or making a network request:

```bash
python3 -m repoguard demo --lang fr --format html -o ~/repoguard-demo.html
```

The demo is explicitly labelled **synthetic**. To install the `repoguard` command, run `python3 -m pip install .` from this repository; installation may download build tools. On Windows, use `py -3` or `python` instead of `python3`, or run the included PowerShell helper:

```powershell
.\scripts\analyser-projet.ps1 -Projet "C:\path\to\your-project"
```

The helper creates a unique local report filename, uses `--deep --lang fr` and does not use `--force`. Add `-OSV` only to opt in to the network lookup. If Windows PowerShell blocks the script, the French guide shows a process-only execution-policy option.

### Optional: check dependencies with OSV

```bash
python3 -m repoguard scan /path/to/your-project --deep --osv \
  --format html -o ~/repoguard-osv-report.html
```

**Opt-in disclosure:** `--osv` sends the inventoried **package names, ecosystems and exact versions** to `https://api.osv.dev/v1/querybatch`; it does not send source files, paths, snippets or matched values as such. Package coordinates may themselves be sensitive, and OSV and network intermediaries may see connection metadata such as your IP address. A failed or incomplete lookup is shown as partial, not as clean.

## Commands and exit codes

```text
repoguard scan [directory] [--deep] [--lang en|fr] [--progress]
               [--format text|json|html|sarif] [-o FILE] [--osv]
               [--max-file-mib N] [--max-total-mib N] [--max-files N]
               [--exclude GLOB] [--respect-inline-ignores]
               [--fail-on none|low|medium|high] [--force]
repoguard demo [--lang en|fr] [--format text|json|html|sarif] [-o FILE] [--force]
repoguard web [--port PORT] [--no-browser]
```

`repoguard web` starts the real interface on the IPv4 loopback interface only; `--port 0` chooses a free port. Its synthetic-only `--demo` mode can also bind to `0.0.0.0` for a public preview; demo mode cannot inspect the filesystem, select a folder, query OSV or shut down through the API. Never expose the real local interface through a reverse proxy.

- Without `-o`, the report goes to standard output; notices and progress go to standard error. Output is created with restrictive permissions where supported. Existing output is not overwritten without `--force`. The final component cannot be a symlink; `--force` is unavailable on systems without the necessary no-follow protection, commonly including Windows. Directory components may still be symlinks.
- If the output is inside the scan directory, it is excluded from that scan. Filenames, project names and package metadata can themselves be sensitive; a secret could even be part of a filename. **Review and protect reports before sharing or uploading them.**
- `--lang` localizes text and HTML; machine-readable JSON and SARIF keep their stable English field names/messages. JSON schema version is `2` for this release.
- `--exclude` is repeatable and matches a relative path or a file/directory basename using shell-style globs; quote patterns so the shell does not expand them. Excluded directories are not descended into. Explicitly excluding `node_modules` also prevents the standard-mode hidden-lock exception.
- Inline `repoguard:ignore` markers do nothing by default. With `--respect-inline-ignores`, any line containing the marker is skipped, including informational checks; this can hide secrets. Comment syntax is not parsed.
- Findings do not cause failure by default. `--fail-on` opts in to a severity threshold. Unknown-severity dependency advisories count as high for threshold purposes; this is not a severity assessment. **Informational observations never trigger `--fail-on`.**

| Exit | Meaning |
| --- | --- |
| `0` | Execution finished within the configured scope and the selected threshold was not reached. Expected exclusions can still apply. This does not mean the project is secure. |
| `1` | A security or dependency finding reached the requested `--fail-on` threshold. |
| `2` | Invalid input/output, a limit or read failure left the file scan incomplete, or an explicitly requested OSV check/inventory was incomplete. Exit `2` takes precedence over `1`. |

Uploading SARIF or any real report is a separate disclosure; review its paths and metadata first. npm inventory locations and advisory results point to line 1 of the relevant JSON file, not necessarily the exact entry.

## Coverage and limitations

### Files and informational indicators

| Mode | Scope and default limits |
| --- | --- |
| Standard | Includes working files and generated directories such as `dist` and `build`. Skips common dependency/vendor/cache directories such as `node_modules` and `vendor`, **except** `node_modules/.package-lock.json` when present. Up to 2 MiB per file, 20,000 file entries and 256 MiB total examined. |
| `--deep` | Also walks dependency, vendor and cache directories. Up to 16 MiB per file, 100,000 file entries and 2 GiB total examined. Results identify project, generated and third-party origins. |

Override the limits with `--max-file-mib` (1–128 MiB), `--max-files` (1–500,000 entries), and `--max-total-mib` (1–16,384 MiB). When a text file exceeds a per-file or total byte limit, only its prefix can be checked; this is reported as incomplete. Scanning continues after reaching a finding-detail cap when possible, but results remain incomplete.

`.git`, `.hg` and `.svn` metadata are excluded in both modes. **Git history, commits, other branches, binary files, images, PDFs and archive contents are not analyzed.** Nested symbolic links are not followed. UTF-8, UTF-16/32 with a BOM, and a heuristic Windows-1252 fallback are supported; binary detection and legacy encoding detection can be wrong. Escaped/encoded content inside source maps or other text formats is not fully interpreted. Protection against concurrent malicious file or directory swaps is best effort; on platforms without `O_NOFOLLOW` even final-component protection is weaker. Do not scan actively changing untrusted trees as a security boundary.

Reports count excluded directories as **one item each**, without counting their unvisited descendants. They record at most 25,000 analyzed-file paths and 1,000 skipped-item details; omitted detail counts are displayed. Text output prints only the first 100 recorded paths per list; HTML and JSON show all recorded paths. Additional bounds include 1,000 secret and 200 informational results per file, 10,000 report findings, 10,000 informational results, 5,000 dependencies per file, 10,000 inventory entries and 100 detailed warnings. The scanner reports at most one match per rule per line: a minified line may contain multiple distinct values. Details are limited intentionally; paths and metadata can contain sensitive information.

### Dependency inventory

| File | What is inventoried |
| --- | --- |
| `requirements*.txt`, or `.txt` files inside a `requirements/` directory | Exact `package==version` pins. Extras and environment markers are accepted, but markers are **not evaluated**. Non-exact pins, includes, hashes and unsupported syntax produce a warning. |
| `package-lock.json`, `npm-shrinkwrap.json`, `node_modules/.package-lock.json` | npm lockfile versions 1–3, including supported nested entries. The npm hidden lock describes installed packages and **may be stale**. Links, some aliases, unsupported versions and workspace cases may be omitted. |
| Installed `node_modules/<package>/package.json` | In `--deep` mode, an installed package root's supported exact name and version. This is package metadata, not proof of actual runtime use. Other nested `package.json` files are not treated as installed package roots. |

Common unsupported files such as Yarn, pnpm, Poetry, uv, Pipfile, Go, Cargo, Maven and Composer manifests/locks are reported as incomplete; unknown formats may not be detected. A first-party `package.json` without an adjacent npm lock is flagged, not parsed for version ranges. The same advisory for the same exact coordinate is shown once even if a lock and installed package both list it; different advisory identifiers may describe the same issue. A successful OSV result covers only inventoried coordinates, never the whole dependency universe. OSV is bounded to 1,000 unique coordinates, 100 per batch, five pages per coordinate, 10,000 advisory matches and 4 MiB per response.

Pattern-based checks do not validate whether a credential is real or active; generic rules can miss weak or unusual values and flag examples. If a real credential was exposed, **revoke or rotate it first**, then remove it from files and history and assess the incident; rewriting history alone does not revoke a credential.

## Development and license

```bash
python3 -m unittest discover -s tests -v
python3 -m repoguard --help
```

Tests use synthetic values and mock network failures and pagination. CI runs across supported Python versions. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). License: [MIT](LICENSE). RepoGuard is independent; the name is also used by other projects.
