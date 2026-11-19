"""Bounded, read-only working-tree scans. Nested symbolic links are not followed."""
import codecs
from collections import Counter
import fnmatch
import os
from pathlib import Path
import stat
import unicodedata
from typing import Callable

from .dependencies import extract_dependencies, is_dependency_file
from .information import MAX_OBSERVATIONS_PER_FILE, scan_information
from .models import Finding, ScanReport, ScannedFile, SkippedItem
from .osv import lookup
from .rules import MAX_FINDINGS_PER_FILE, scan_text

# Standard includes generated dist/build by default; --deep also visits vendored
# trees and caches. VCS databases are never walked or treated as Git history.
VCS_DIRECTORIES = frozenset({'.git', '.hg', '.svn'})
SKIP_DIRECTORIES = VCS_DIRECTORIES | frozenset({'.venv', 'venv', 'node_modules', '__pycache__', '.cache', '.mypy_cache', '.pytest_cache', '.tox', 'coverage', 'target', 'vendor'})
UNSUPPORTED_LOCKS = frozenset({'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'pipfile.lock', 'uv.lock', 'cargo.lock', 'go.sum', 'gemfile.lock', 'composer.lock', 'packages.lock.json'})
UNSUPPORTED_MANIFESTS = frozenset({'pyproject.toml', 'pipfile', 'go.mod', 'cargo.toml', 'gemfile', 'pom.xml', 'composer.json'})
ARCHIVE_SUFFIXES = ('.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz', '.7z', '.rar', '.jar', '.war', '.ear', '.whl', '.apk', '.aab', '.docx', '.xlsx', '.pptx', '.pdf')
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20000
MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEEP_MAX_FILE_BYTES = 16 * 1024 * 1024
DEEP_MAX_FILES = 100000
DEEP_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_USER_FILE_BYTES = 128 * 1024 * 1024
MAX_USER_FILES = 500000
MAX_USER_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_FINDINGS = 10000
MAX_OBSERVATIONS = 10000
MAX_DEPENDENCIES = 10000
MAX_WARNINGS = 100
MAX_SCANNED_DETAILS = 25000
MAX_SKIPPED_DETAILS = 1000


def _safe_display(value: str) -> str:
    # Paths can be untrusted; do not permit control or bidi characters in terminals.
    cleaned = ''.join(ch if not unicodedata.category(ch).startswith('C') else '�' for ch in value)
    return cleaned if len(cleaned) <= 500 else cleaned[:245] + '…' + cleaned[-245:]


def _excluded(path: str, patterns: tuple[str, ...]) -> bool:
    name = path.rsplit('/', 1)[-1]
    return any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _origin(path: str) -> str:
    parts = {part.lower() for part in path.split('/')[:-1]}
    if parts & {'node_modules', 'vendor', '.venv', 'venv'}:
        return 'third_party'
    if parts & {'dist', 'build', 'coverage', 'target'}:
        return 'generated'
    return 'project'


def _read_bounded(path: Path, limit: int) -> tuple[bytes, int, bool] | None:
    """Read a regular leaf without intentionally following symlinks, up to limit+1."""
    if not stat.S_ISREG(path.lstat().st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None
        raw = handle.read(limit + 1)
    truncated = info.st_size > limit or len(raw) > limit
    return raw[:limit], info.st_size, truncated


def _decode_text(raw: bytes, partial: bool) -> tuple[str | None, str]:
    """Recognize Unicode BOMs and UTF-8, with a conservative CP1252 fallback."""
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding, label = 'utf-32', 'UTF-32 BOM'
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding, label = 'utf-16', 'UTF-16 BOM'
    elif b'\x00' in raw[:8192]:
        return None, 'binary_or_non_text'
    else:
        encoding, label = 'utf-8-sig', 'UTF-8'
    try:
        text = codecs.getincrementaldecoder(encoding)(errors='strict').decode(raw, final=not partial)
        return text, label
    except UnicodeError:
        # Never reinterpret malformed UTF-16/32 as a different encoding.
        if encoding != 'utf-8-sig':
            return None, 'unsupported_encoding'
    try:
        text = raw.decode('cp1252')
    except UnicodeError:
        return None, 'unsupported_encoding'
    sample = text[:8192]
    printable = sum(ch.isprintable() or ch in '\r\n\t\f' for ch in sample)
    if sample and printable / len(sample) < 0.95:
        return None, 'binary_or_non_text'
    return text, 'Windows-1252 heuristic'


def scan_directory(directory: str | Path, use_osv: bool = False, excludes: tuple[str, ...] = (),
                   respect_inline_ignores: bool = False, output_path: str | None = None,
                   deep: bool = False, max_file_bytes: int | None = None,
                   max_files: int | None = None, max_total_bytes: int | None = None,
                   progress: Callable[[int, int], None] | None = None) -> ScanReport:
    root = Path(directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError('The scan target must be an existing directory.')
    file_limit = max_file_bytes if max_file_bytes is not None else (DEEP_MAX_FILE_BYTES if deep else MAX_FILE_BYTES)
    entry_limit = max_files if max_files is not None else (DEEP_MAX_FILES if deep else MAX_FILES)
    total_limit = max_total_bytes if max_total_bytes is not None else (DEEP_MAX_TOTAL_BYTES if deep else MAX_TOTAL_BYTES)
    if not 1 <= file_limit <= MAX_USER_FILE_BYTES or not 1 <= entry_limit <= MAX_USER_FILES or not 1 <= total_limit <= MAX_USER_TOTAL_BYTES:
        raise ValueError('Scan limits are outside the supported range.')
    report = ScanReport(project=_safe_display(root.name or 'project'), scope='deep' if deep else 'standard',
                        inline_ignores_enabled=respect_inline_ignores,
                        limits={'file_bytes': file_limit, 'file_entries': entry_limit, 'total_bytes': total_limit,
                                'finding_details': MAX_FINDINGS, 'information_details': MAX_OBSERVATIONS,
                                'dependency_entries': MAX_DEPENDENCIES, 'scanned_file_details': MAX_SCANNED_DETAILS,
                                'skipped_item_details': MAX_SKIPPED_DETAILS})
    encoding_counts: Counter[str] = Counter()
    skipped_counts: Counter[str] = Counter()
    stop = False
    warnings_dropped = False
    finding_cap_warned = False
    info_cap_warned = False
    dependency_cap_warned = False
    hidden_lock_warned = False
    output_relative = None
    if output_path:
        try:
            # Canonicalize parent aliases, junctions and .. consistently with root.
            # In particular, Windows temporary directories may use 8.3 short names.
            output_relative = Path(output_path).expanduser().resolve(strict=False).relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError):
            pass

    def warn(message: str) -> None:
        nonlocal warnings_dropped
        if len(report.warnings) < MAX_WARNINGS:
            report.warnings.append(_safe_display(message))
        else:
            warnings_dropped = True

    def skip(path: str, reason: str, kind: str) -> None:
        report.skipped_items += 1
        skipped_counts[reason] += 1
        if len(report.skipped_details) < MAX_SKIPPED_DETAILS:
            report.skipped_details.append(SkippedItem(_safe_display(path), reason, kind))
        else:
            report.skipped_details_omitted += 1

    if respect_inline_ignores:
        warn('Inline ignores are enabled: ignored lines are not scanned and may hide real secrets.')

    def on_error(error: OSError) -> None:
        try:
            relative = Path(error.filename).relative_to(root).as_posix() if error.filename else '(directory)'
        except (ValueError, TypeError):
            relative = '(directory)'
        skip(relative, 'unreadable_directory', 'directory')
        report.scan_incomplete = report.inventory_incomplete = True
        warn(f'{_safe_display(relative)}: a directory could not be read; coverage is incomplete.')

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=on_error):
        current_path = Path(current)
        accepted_dirs = []
        selective_files: list[Path] = []
        for name in sorted(dirs):
            candidate = current_path / name
            rel = candidate.relative_to(root).as_posix()
            lower = name.lower()
            try:
                if candidate.is_symlink():
                    skip(rel, 'symlink_directory', 'directory')
                elif _excluded(rel, excludes):
                    skip(rel, 'user_excluded_directory', 'directory')
                elif lower in VCS_DIRECTORIES:
                    skip(rel, 'vcs_metadata', 'directory')
                elif not deep and lower in SKIP_DIRECTORIES:
                    skip(rel, 'standard_excluded_directory', 'directory')
                    # npm's hidden v7+ lock can be valuable even when the rest
                    # of node_modules is excluded. Never follow the directory link.
                    if lower == 'node_modules':
                        lock = candidate / '.package-lock.json'
                        try:
                            lock.lstat()
                        except FileNotFoundError:
                            pass
                        except OSError:
                            report.inventory_incomplete = True
                            warn(f'{_safe_display(rel)}: hidden npm lock could not be inspected.')
                        else:
                            selective_files.append(lock)
                else:
                    accepted_dirs.append(name)
            except OSError:
                skip(rel, 'unreadable_directory', 'directory')
                report.scan_incomplete = report.inventory_incomplete = True
                warn(f'{_safe_display(rel)}: a directory entry could not be inspected.')
        dirs[:] = accepted_dirs
        local_names = {name.lower() for name in files}
        candidates = [current_path / name for name in sorted(files)] + selective_files
        for path in candidates:
            if report.file_entries_seen >= entry_limit:
                warn(f'Scan stopped after {entry_limit} file entries; coverage is incomplete.')
                report.scan_incomplete = report.inventory_incomplete = True
                stop = True
                break
            if report.bytes_examined >= total_limit:
                warn(f'Scan stopped at the {total_limit} byte total limit; coverage is incomplete.')
                report.scan_incomplete = report.inventory_incomplete = True
                stop = True
                break
            report.file_entries_seen += 1
            if progress and report.file_entries_seen % 500 == 0:
                progress(report.file_entries_seen, report.files_scanned)
            relative = path.relative_to(root).as_posix()
            display = _safe_display(relative)
            lower_name = path.name.lower()
            in_node_modules = 'node_modules' in (part.lower() for part in path.relative_to(root).parts[:-1])
            supported = is_dependency_file(relative)
            unsupported = (lower_name in UNSUPPORTED_LOCKS or lower_name in UNSUPPORTED_MANIFESTS
                           or (lower_name == 'package.json' and not in_node_modules
                               and not ({'package-lock.json', 'npm-shrinkwrap.json'} & local_names)))
            if relative == output_relative:
                skip(relative, 'report_output', 'file')
                if supported or unsupported:
                    report.inventory_incomplete = True
                    warn(f'{display}: dependency file was excluded from the inventory.')
                continue
            if _excluded(relative, excludes):
                skip(relative, 'user_excluded_file', 'file')
                if supported or unsupported:
                    report.inventory_incomplete = True
                    warn(f'{display}: dependency file was excluded from the inventory.')
                continue
            try:
                leaf_info = path.lstat()
                if not stat.S_ISREG(leaf_info.st_mode):
                    skip(relative, 'symlink_or_non_regular_file', 'file')
                    if supported or unsupported:
                        report.inventory_incomplete = True
                        warn(f'{display}: dependency file is a symlink or is not a regular file and was skipped.')
                    continue
                if lower_name.endswith(ARCHIVE_SUFFIXES):
                    skip(relative, 'archive_or_document_not_opened', 'file')
                    if supported or unsupported:
                        report.inventory_incomplete = True
                    continue
                available = total_limit - report.bytes_examined
                actual_limit = min(file_limit, available)
                result = _read_bounded(path, actual_limit)
                if result is None:
                    skip(relative, 'symlink_or_non_regular_file', 'file')
                    if supported or unsupported:
                        report.inventory_incomplete = True
                        warn(f'{display}: dependency file is a symlink or is not a regular file and was skipped.')
                    continue
                raw, size_bytes, partial = result
                report.bytes_examined += len(raw)
            except OSError:
                skip(relative, 'unreadable_file', 'file')
                report.scan_incomplete = True
                if supported or unsupported:
                    report.inventory_incomplete = True
                warn(f'{display}: file could not be read safely.')
                continue
            if partial:
                reason = 'total_byte_limit' if actual_limit < file_limit else 'file_size_limit'
                skip(relative, reason, 'file_part')
                report.scan_incomplete = True
                if supported or unsupported:
                    report.inventory_incomplete = True
                warn(f'{display}: only the first {actual_limit} bytes were examined; the rest exceeded a scan limit.')
            text, encoding = _decode_text(raw, partial)
            if text is None:
                skip(relative, encoding, 'file')
                report.binary_or_encoding_skipped += 1
                if supported or unsupported:
                    report.inventory_incomplete = True
                    warn(f'{display}: dependency file is binary or has an unsupported encoding.')
                continue
            report.files_scanned += 1
            if partial:
                report.files_partially_scanned += 1
            origin = _origin(relative)
            encoding_counts[encoding] += 1
            if len(report.scanned_files) < MAX_SCANNED_DETAILS:
                report.scanned_files.append(ScannedFile(display, size_bytes, len(raw), encoding, origin, partial))
            else:
                report.scanned_file_details_omitted += 1

            findings = scan_text(display, text, respect_inline_ignores=respect_inline_ignores, origin=origin)
            remaining = max(0, MAX_FINDINGS - len(report.findings))
            report.findings.extend(findings[:remaining])
            if len(findings) > remaining and not finding_cap_warned:
                finding_cap_warned = True
                report.scan_incomplete = True
                warn(f'Secret findings were capped at {MAX_FINDINGS}; remaining files are still examined.')
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                report.scan_incomplete = True
                warn(f'{display}: secret findings were capped at {MAX_FINDINGS_PER_FILE}.')
            observations = scan_information(display, text, respect_inline_ignores=respect_inline_ignores, origin=origin)
            remaining_info = max(0, MAX_OBSERVATIONS - len(report.observations))
            report.observations.extend(observations[:remaining_info])
            if len(observations) > remaining_info and not info_cap_warned:
                info_cap_warned = True
                report.scan_incomplete = True
                warn(f'Information observations were capped at {MAX_OBSERVATIONS}; remaining files are still examined.')
            if len(observations) >= MAX_OBSERVATIONS_PER_FILE:
                report.scan_incomplete = True
                warn(f'{display}: information observations were capped at {MAX_OBSERVATIONS_PER_FILE}.')
            if supported:
                # Do not parse a truncated JSON or requirements file as a complete inventory.
                if partial:
                    continue
                deps, messages = extract_dependencies(display, text)
                remaining_deps = max(0, MAX_DEPENDENCIES - len(report.dependencies))
                report.dependencies.extend(deps[:remaining_deps])
                if len(deps) > remaining_deps and not dependency_cap_warned:
                    dependency_cap_warned = True
                    report.inventory_incomplete = True
                    warn(f'Dependency inventory is limited to {MAX_DEPENDENCIES} entries.')
                if messages:
                    report.inventory_incomplete = True
                for message in messages:
                    warn(message)
                if lower_name == '.package-lock.json' and not hidden_lock_warned:
                    hidden_lock_warned = True
                    warn('The hidden npm lock describes installed packages and may be stale; it is not a complete dependency guarantee.')
            elif unsupported:
                report.inventory_incomplete = True
                warn(f'{display}: this dependency file format is not inventoried by RepoGuard.')
        if stop:
            break

    report.encoding_counts = dict(sorted(encoding_counts.items()))
    report.skipped_by_reason = dict(sorted(skipped_counts.items()))
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
        seen_coordinates: set[tuple[str, str, str]] = set()
        for dependency in report.dependencies:
            # The lock and installed manifest can describe the same version; one
            # advisory per coordinate avoids reporting the same match twice.
            if dependency.coordinate in seen_coordinates:
                continue
            seen_coordinates.add(dependency.coordinate)
            for advisory in osv.matches.get(dependency.coordinate, []):
                if len(report.findings) >= MAX_FINDINGS:
                    finding_limit_reached = True
                    break
                report.findings.append(Finding(
                    rule_id='RG-DEP-OSV', category='dependency', severity='unknown',
                    title=f'Known advisory: {advisory}', path=dependency.path, line=dependency.line,
                    detail=f'{dependency.ecosystem} package {dependency.name} {dependency.version} matched an OSV advisory. Severity is not assessed by this version.',
                    remediation='Read the advisory, verify applicability, and update or mitigate as recommended.',
                    reference=f'https://osv.dev/vulnerability/{advisory}', origin=_origin(dependency.path),
                ))
            if finding_limit_reached:
                break
        if finding_limit_reached:
            report.osv_status = 'partial'
            warn(f'Report findings were capped at {MAX_FINDINGS}; advisory results are incomplete.')
    if warnings_dropped:
        report.warnings.append('Additional warnings omitted.')
    severity_order = {'critical': 0, 'high': 1, 'unknown': 2, 'medium': 3, 'low': 4}
    origin_order = {'project': 0, 'generated': 1, 'third_party': 2}
    report.findings.sort(key=lambda f: (origin_order.get(f.origin, 3), severity_order.get(f.severity, 5), f.path, f.line, f.rule_id, f.title))
    report.observations.sort(key=lambda f: (origin_order.get(f.origin, 3), f.path, f.line, f.rule_id))
    return report
