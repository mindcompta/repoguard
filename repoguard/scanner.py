"""Bounded, read-only working-tree scans. Nested symbolic links are not followed."""
import fnmatch
import os
from pathlib import Path
import stat
import unicodedata

from .dependencies import extract_dependencies, is_dependency_file
from .models import Finding, ScanReport
from .osv import lookup
from .rules import MAX_FINDINGS_PER_FILE, scan_text

SKIP_DIRECTORIES = frozenset({'.git', '.hg', '.svn', '.venv', 'venv', 'node_modules', '__pycache__', '.cache', '.mypy_cache', '.pytest_cache', '.tox', 'build', 'dist', 'coverage', 'target', 'vendor'})
# Common dependency files that are NOT supported in this version. Flag them instead
# of implying the OSV inventory covers everything. A package.json with an npm lock
# in the same directory is covered by that lock (not by package.json itself).
UNSUPPORTED_LOCKS = frozenset({'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'poetry.lock', 'pipfile.lock', 'uv.lock', 'cargo.lock', 'go.sum', 'gemfile.lock', 'composer.lock', 'packages.lock.json'})
UNSUPPORTED_MANIFESTS = frozenset({'pyproject.toml', 'pipfile', 'go.mod', 'cargo.toml', 'gemfile', 'pom.xml', 'composer.json'})
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20000
MAX_FINDINGS = 10000
MAX_DEPENDENCIES = 10000
MAX_WARNINGS = 100


def _safe_display(value: str) -> str:
    # Paths can be untrusted; do not permit control or bidi characters in terminals.
    cleaned = ''.join(ch if not unicodedata.category(ch).startswith('C') else '�' for ch in value)
    return cleaned if len(cleaned) <= 500 else cleaned[:245] + '…' + cleaned[-245:]


def _excluded(path: str, patterns: tuple[str, ...]) -> bool:
    name = path.rsplit('/', 1)[-1]
    return any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _read_bounded(path: Path) -> bytes | None:
    """Read regular files only, bounded even if a file grows; do not follow a leaf symlink."""
    if not stat.S_ISREG(path.lstat().st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_FILE_BYTES:
            raise OverflowError('File exceeds scan limit')
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise OverflowError('File exceeds scan limit')
    return raw


def scan_directory(directory: str | Path, use_osv: bool = False, excludes: tuple[str, ...] = (),
                   respect_inline_ignores: bool = False, output_path: str | None = None) -> ScanReport:
    root = Path(directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError('The scan target must be an existing directory.')
    report = ScanReport(project=_safe_display(root.name or 'project'), inline_ignores_enabled=respect_inline_ignores)
    scanned_items = 0
    stop = False
    warnings_dropped = False
    output_relative = None
    if output_path:
        try:
            output_relative = Path(output_path).expanduser().absolute().relative_to(root).as_posix()
        except ValueError:
            pass

    def warn(message: str) -> None:
        nonlocal warnings_dropped
        if len(report.warnings) < MAX_WARNINGS:
            report.warnings.append(_safe_display(message))
        else:
            warnings_dropped = True

    if respect_inline_ignores:
        warn('Inline ignores are enabled: ignored lines are not scanned and may hide real secrets.')

    def on_error(_error: OSError) -> None:
        report.skipped_items += 1
        report.scan_incomplete = True
        report.inventory_incomplete = True
        warn('A directory could not be read; coverage is incomplete.')

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=on_error):
        current_path = Path(current)
        accepted_dirs = []
        for name in sorted(dirs):
            candidate = current_path / name
            rel = candidate.relative_to(root).as_posix()
            try:
                if name in SKIP_DIRECTORIES or candidate.is_symlink() or _excluded(rel, excludes):
                    report.skipped_items += 1
                else:
                    accepted_dirs.append(name)
            except OSError:
                report.skipped_items += 1
                report.scan_incomplete = True
                report.inventory_incomplete = True
                warn('A directory entry could not be inspected.')
        dirs[:] = accepted_dirs
        local_names = {name.lower() for name in files}
        for name in sorted(files):
            scanned_items += 1
            if scanned_items > MAX_FILES:
                warn(f'Scan stopped after {MAX_FILES} file entries; coverage is incomplete.')
                report.scan_incomplete = report.inventory_incomplete = True
                stop = True
                break
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            display = _safe_display(relative)
            lower_name = name.lower()
            unsupported = (lower_name in UNSUPPORTED_LOCKS or lower_name in UNSUPPORTED_MANIFESTS
                           or (lower_name == 'package.json' and 'package-lock.json' not in local_names))
            if relative == output_relative or _excluded(relative, excludes):
                report.skipped_items += 1
                if is_dependency_file(relative) or unsupported:
                    report.inventory_incomplete = True
                    warn(f'{display}: dependency file was excluded from the inventory.')
                continue
            try:
                raw = _read_bounded(path)
                if raw is None:
                    report.skipped_items += 1
                    if is_dependency_file(relative) or unsupported:
                        report.inventory_incomplete = True
                        warn(f'{display}: dependency file is a symlink or is not a regular file and was skipped.')
                    continue
                if b'\x00' in raw[:8192]:
                    report.skipped_items += 1
                    report.binary_or_encoding_skipped += 1
                    if is_dependency_file(relative) or unsupported:
                        report.inventory_incomplete = True
                        warn(f'{display}: dependency file is binary or has an unsupported encoding.')
                    continue
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    report.skipped_items += 1
                    report.binary_or_encoding_skipped += 1
                    if is_dependency_file(relative) or unsupported:
                        report.inventory_incomplete = True
                        warn(f'{display}: dependency file is not UTF-8.')
                    continue
            except OverflowError:
                report.skipped_items += 1
                report.scan_incomplete = True
                if is_dependency_file(relative) or unsupported:
                    report.inventory_incomplete = True
                warn(f'{display}: file exceeded the 2 MiB limit and was skipped.')
                continue
            except OSError:
                report.skipped_items += 1
                report.scan_incomplete = True
                if is_dependency_file(relative) or unsupported:
                    report.inventory_incomplete = True
                warn(f'{display}: file could not be read safely.')
                continue
            report.files_scanned += 1
            findings = scan_text(display, text, respect_inline_ignores=respect_inline_ignores)
            report.findings.extend(findings)
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                report.scan_incomplete = True
                warn(f'{display}: secret findings were capped at {MAX_FINDINGS_PER_FILE}.')
            if len(report.findings) >= MAX_FINDINGS:
                report.findings = report.findings[:MAX_FINDINGS]
                report.scan_incomplete = report.inventory_incomplete = True
                warn(f'Scan stopped after {MAX_FINDINGS} findings; coverage is incomplete.')
                stop = True
                break
            if is_dependency_file(relative):
                deps, messages = extract_dependencies(display, text)
                remaining = MAX_DEPENDENCIES - len(report.dependencies)
                report.dependencies.extend(deps[:max(remaining, 0)])
                if len(deps) > remaining:
                    report.inventory_incomplete = True
                    warn(f'Dependency inventory is limited to {MAX_DEPENDENCIES} entries.')
                if messages:
                    report.inventory_incomplete = True
                for message in messages:
                    warn(message)
            elif unsupported:
                report.inventory_incomplete = True
                warn(f'{display}: this dependency file format is not inventoried by RepoGuard.')
        if stop:
            break

    # Deduplicate identical coordinates at the same location, not distinct locations.
    report.dependencies = list(dict.fromkeys(report.dependencies))
    if use_osv:
        osv = lookup(report.dependencies)
        report.osv_status = 'partial' if report.inventory_incomplete else osv.status
        report.osv_queries = osv.checked
        for warning in osv.warnings:
            warn(warning)
        if report.inventory_incomplete:
            warn('The dependency inventory is incomplete; OSV results cannot cover all dependencies.')
        finding_limit_reached = False
        for dependency in report.dependencies:
            for advisory in osv.matches.get(dependency.coordinate, []):
                if len(report.findings) >= MAX_FINDINGS:
                    finding_limit_reached = True
                    break
                report.findings.append(Finding(
                    rule_id='RG-DEP-OSV', category='dependency', severity='unknown',
                    title=f'Known advisory: {advisory}', path=dependency.path, line=dependency.line,
                    detail=f'{dependency.ecosystem} package {dependency.name} {dependency.version} matched an OSV advisory. Severity is not assessed by this version.',
                    remediation='Read the advisory, verify applicability, and update or mitigate as recommended.',
                    reference=f'https://osv.dev/vulnerability/{advisory}',
                ))
            if finding_limit_reached:
                break
        if finding_limit_reached:
            report.osv_status = 'partial'
            warn(f'Report findings were capped at {MAX_FINDINGS}; advisory results are incomplete.')
    if warnings_dropped:
        report.warnings.append('Additional warnings omitted.')
    severity_order = {'critical': 0, 'high': 1, 'unknown': 2, 'medium': 3, 'low': 4}
    report.findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.path, f.line, f.rule_id, f.title))
    return report
