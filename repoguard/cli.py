"""RepoGuard command-line interface."""
import argparse
import os
from pathlib import Path
import sys

from . import __version__
from .models import Dependency, Finding, ScanReport
from .reports import html_report, json_report, sarif_report, text_report
from .scanner import scan_directory


_FORMATTERS = {'text': text_report, 'json': json_report, 'html': html_report, 'sarif': sarif_report}
_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'unknown': 3}


def _demo_report() -> ScanReport:
    """Synthetic demo only: no repository is read and no network request is made."""
    report = ScanReport(project='demo-service (synthetic)', files_scanned=148, skipped_items=3, demo=True, osv_status='demo', osv_queries=0)
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
    scan.add_argument('--exclude', action='append', default=[], metavar='GLOB', help='Exclude a relative path or file/directory name. Repeatable.')
    scan.add_argument('--respect-inline-ignores', action='store_true', help='Opt in to repoguard:ignore markers; ignored lines may hide real secrets.')
    scan.add_argument('--fail-on', choices=['none', 'low', 'medium', 'high'], default='none', help='Exit 1 on findings at or above this level. Unknown severity counts as high.')
    demo = sub.add_parser('demo', help='Generate a clearly labelled report with synthetic data.')
    demo.add_argument('--format', choices=_FORMATTERS, default='html')
    demo.add_argument('-o', '--output', help='Write report to a new file instead of standard output.')
    demo.add_argument('--force', action='store_true', help='Overwrite an existing output file.')
    return parser


def _write(content: str, output: str | None, force: bool) -> None:
    if not output:
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


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            report = _demo_report()
        else:
            if args.osv:
                print('RepoGuard: OSV lookup enabled; dependency names, ecosystems and versions will be sent to api.osv.dev.', file=sys.stderr)
            report = scan_directory(args.directory, use_osv=args.osv, excludes=tuple(args.exclude),
                                    respect_inline_ignores=args.respect_inline_ignores, output_path=args.output)
        _write(_FORMATTERS[args.format](report), args.output, args.force)
    except (OSError, ValueError) as error:
        # Avoid control characters in paths supplied by the caller.
        message = ''.join(ch if ch.isprintable() else '�' for ch in str(error))
        print(f'RepoGuard: {message}', file=sys.stderr)
        return 2
    if args.command == 'scan':
        if report.scan_incomplete or report.osv_status == 'partial':
            return 2
        if args.fail_on != 'none' and any(_RANK.get(finding.severity, 3) >= _RANK[args.fail_on] for finding in report.findings):
            return 1
    return 0
