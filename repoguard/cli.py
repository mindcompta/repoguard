"""RepoGuard command-line interface."""
import argparse
import os
from pathlib import Path
import sys

from . import __version__
from .models import Dependency, Finding, ScanReport, ScannedFile, SkippedItem
from .reports import html_report, json_report, sarif_report, text_report
from .scanner import scan_directory


_FORMATTERS = {'text': text_report, 'json': json_report, 'html': html_report, 'sarif': sarif_report}
_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'unknown': 3}


def _demo_report() -> ScanReport:
    """Synthetic demo only: no repository is read and no network request is made."""
    report = ScanReport(project='demo-service (synthetic)', scope='deep', files_scanned=148,
                        file_entries_seen=150, skipped_items=3, binary_or_encoding_skipped=1,
                        demo=True, osv_status='demo', osv_queries=0,
                        limits={'file_bytes': 16777216, 'file_entries': 100000, 'total_bytes': 2147483648},
                        encoding_counts={'UTF-8': 148},
                        skipped_by_reason={'vcs_metadata': 1, 'binary_or_non_text': 1, 'archive_or_document_not_opened': 1},
                        scanned_files=[ScannedFile('dist/ads.txt', 58, 58, 'UTF-8', 'generated'),
                                       ScannedFile('config/settings.py', 512, 512, 'UTF-8', 'project')],
                        scanned_file_details_omitted=146,
                        skipped_details=[SkippedItem('.git', 'vcs_metadata', 'directory'),
                                         SkippedItem('assets/image.png', 'binary_or_non_text', 'file'),
                                         SkippedItem('backup.zip', 'archive_or_document_not_opened', 'file')])
    report.dependencies = [
        Dependency('npm', 'example-package', '1.2.3', 'package-lock.json'),
        Dependency('npm', 'sample-library', '2.4.0', 'package-lock.json'),
        Dependency('PyPI', 'demo-package', '1.0.0', 'requirements.txt', 2),
        Dependency('PyPI', 'sample-utils', '3.1.0', 'requirements.txt', 3),
    ]
    report.findings = [
        Finding('RG-SEC-001', 'secret', 'high', 'Possible GitHub token', 'config/settings.py', 18,
                'A synthetic example of a token-like value. No secret is shown.',
                'Verify the finding; revoke and rotate a real exposed token.'),
        Finding('RG-DEP-OSV', 'dependency', 'unknown', 'Example advisory (synthetic)', 'package-lock.json', 1,
                'A fictional dependency advisory shown for demonstration.',
                'Review the real advisory and apply its recommended update.'),
        Finding('RG-SEC-006', 'secret', 'medium', 'Possible AWS access key ID', 'examples/config.env', 7,
                'A synthetic example of an access key ID; an ID is not the corresponding secret.',
                'Review the associated credentials if exposure is confirmed.'),
    ]
    report.observations = [
        Finding('RG-INFO-001', 'information', 'info', 'Google advertising publisher identifier', 'dist/ads.txt', 1,
                'A synthetic example of an advertising publisher identifier. Its presence is not a vulnerability.',
                'Check the original file and advertising account configuration.', origin='generated'),
    ]
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='repoguard', description='Local-first checks for exposed credentials and vulnerable dependencies.')
    parser.add_argument('--version', action='version', version=f'RepoGuard {__version__}')
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='Scan an existing directory without executing its code.')
    scan.add_argument('directory', nargs='?', default='.', help='Directory to scan (default: current directory).')
    scan.add_argument('--format', choices=_FORMATTERS, default='text', help='Report format (default: text).')
    scan.add_argument('-o', '--output', help='Write report to a new file instead of standard output.')
    scan.add_argument('--force', action='store_true', help='Overwrite an existing output file (refuses a symlink as the final path component).')
    scan.add_argument('--osv', action='store_true', help='Opt in to OSV.dev: send dependency names, ecosystems and exact versions.')
    scan.add_argument('--deep', action='store_true', help='Also scan vendored and dependency directories, with higher bounded limits.')
    scan.add_argument('--lang', choices=['en', 'fr'], default='en', help='Language for text and HTML reports (default: en).')
    scan.add_argument('--max-file-mib', type=int, metavar='N', help='Limit analyzed bytes per file to 1–128 MiB (larger files are partly analyzed).')
    scan.add_argument('--max-total-mib', type=int, metavar='N', help='Limit total bytes examined to 1–16384 MiB.')
    scan.add_argument('--max-files', type=int, metavar='N', help='Maximum file entries to inspect, from 1 to 500000.')
    scan.add_argument('--progress', action='store_true', help='Show progress on stderr; no filenames or values are printed.')
    scan.add_argument('--exclude', action='append', default=[], metavar='GLOB', help='Exclude a relative path or file/directory name. Repeatable.')
    scan.add_argument('--respect-inline-ignores', action='store_true', help='Opt in to repoguard:ignore markers; ignored lines may hide real secrets.')
    scan.add_argument('--fail-on', choices=['none', 'low', 'medium', 'high'], default='none', help='Exit 1 on findings at or above this level. Unknown severity counts as high.')
    demo = sub.add_parser('demo', help='Generate a clearly labelled report with synthetic data.')
    demo.add_argument('--format', choices=_FORMATTERS, default='html')
    demo.add_argument('--lang', choices=['en', 'fr'], default='en', help='Language for text and HTML reports.')
    demo.add_argument('-o', '--output', help='Write report to a new file instead of standard output.')
    demo.add_argument('--force', action='store_true', help='Overwrite an existing output file.')
    web = sub.add_parser('web', help='Open the local browser interface (no scan is run until you choose a folder).')
    web.add_argument('--port', type=int, default=0, help='Local port (0 chooses a free port).')
    web.add_argument('--host', default='127.0.0.1', help='Listen address; non-loopback is allowed only for the synthetic demo.')
    web.add_argument('--no-browser', action='store_true', help='Do not open a browser automatically.')
    web.add_argument('--demo', action='store_true', help='Serve a synthetic preview that cannot scan files or query OSV.')
    return parser


def _write(content: str, output: str | None, force: bool, report_format: str = 'text') -> None:
    if not output:
        # Windows pipes may use a legacy encoding. JSON/SARIF are ASCII-escaped;
        # preserve unrepresentable HTML characters as entities and text as escapes.
        encoding = getattr(sys.stdout, 'encoding', None)
        if encoding:
            errors = 'xmlcharrefreplace' if report_format == 'html' else 'backslashreplace'
            content = content.encode(encoding, errors=errors).decode(encoding)
        sys.stdout.write(content)
        return
    path = Path(output).expanduser()
    if path.is_symlink():
        raise ValueError('Refusing to write through a symlink.')
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    if force:
        if not hasattr(os, 'O_NOFOLLOW'):
            raise ValueError('--force is unavailable on this platform; choose a new output filename.')
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL
    # Restrict permissions on new reports: filenames and dependencies may be sensitive.
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(content)


def _stderr(message: str) -> None:
    encoding = getattr(sys.stderr, 'encoding', None)
    if encoding:
        message = message.encode(encoding, errors='backslashreplace').decode(encoding)
    print(message, file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == 'web':
            from .web import run_web
            run_web(host=args.host, port=args.port, demo=args.demo, open_browser=not args.no_browser)
            return 0
        if args.command == 'demo':
            report = _demo_report()
        else:
            if args.osv:
                notice = ('OSV activé : noms, écosystèmes et versions des dépendances seront envoyés à api.osv.dev.'
                          if args.lang == 'fr' else
                          'OSV lookup enabled; dependency names, ecosystems and versions will be sent to api.osv.dev.')
                _stderr('RepoGuard: ' + notice)
            def show_progress(seen: int, scanned: int) -> None:
                message = (f'Fichiers examinés : {seen} ; fichiers texte analysés : {scanned}' if args.lang == 'fr'
                           else f'File entries examined: {seen}; text files scanned: {scanned}')
                _stderr(f'RepoGuard: {message}')
            report = scan_directory(args.directory, use_osv=args.osv, excludes=tuple(args.exclude),
                                    respect_inline_ignores=args.respect_inline_ignores, output_path=args.output,
                                    deep=args.deep,
                                    max_file_bytes=args.max_file_mib * 1024 * 1024 if args.max_file_mib is not None else None,
                                    max_files=args.max_files,
                                    max_total_bytes=args.max_total_mib * 1024 * 1024 if args.max_total_mib is not None else None,
                                    progress=show_progress if args.progress else None)
        rendered = (_FORMATTERS[args.format](report, language=args.lang)
                    if args.format in {'text', 'html'} else _FORMATTERS[args.format](report))
        _write(rendered, args.output, args.force, report_format=args.format)
    except (OSError, ValueError) as error:
        # Avoid control characters in paths supplied by the caller.
        message = ''.join(ch if ch.isprintable() else '�' for ch in str(error))
        _stderr(f'RepoGuard: {message}')
        return 2
    if args.command == 'scan':
        if report.scan_incomplete or report.osv_status == 'partial':
            return 2
        if args.fail_on != 'none' and any(_RANK.get(finding.severity, 3) >= _RANK[args.fail_on] for finding in report.findings):
            return 1
    return 0
