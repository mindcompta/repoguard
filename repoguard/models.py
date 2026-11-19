"""Report types. Source snippets and matched values are deliberately not stored."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import __version__


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    path: str
    line: int = 1

    @property
    def coordinate(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    path: str
    line: int
    detail: str
    remediation: str
    reference: str = ''
    column: int = 1  # Character offset, not necessarily a byte offset.
    origin: str = 'project'  # project, generated, or third_party


@dataclass(frozen=True)
class ScannedFile:
    path: str
    size_bytes: int
    bytes_scanned: int
    encoding: str
    origin: str
    partial: bool = False


@dataclass(frozen=True)
class SkippedItem:
    path: str
    reason: str
    kind: str  # file, directory, or file_part


@dataclass
class ScanReport:
    project: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
    scope: str = 'standard'
    files_scanned: int = 0
    file_entries_seen: int = 0
    bytes_examined: int = 0
    files_partially_scanned: int = 0
    skipped_items: int = 0
    binary_or_encoding_skipped: int = 0
    scan_incomplete: bool = False
    inventory_incomplete: bool = False
    inline_ignores_enabled: bool = False
    limits: dict[str, int] = field(default_factory=dict)
    encoding_counts: dict[str, int] = field(default_factory=dict)
    skipped_by_reason: dict[str, int] = field(default_factory=dict)
    scanned_files: list[ScannedFile] = field(default_factory=list)
    skipped_details: list[SkippedItem] = field(default_factory=list)
    scanned_file_details_omitted: int = 0
    skipped_details_omitted: int = 0
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    observations: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    osv_status: str = 'not_requested'
    osv_queries: int = 0
    demo: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema_version': 2,
            'tool': {'name': 'RepoGuard', 'version': __version__},
            'project': self.project,
            'created_at': self.created_at,
            'demo': self.demo,
            'summary': {
                'scope': self.scope,
                'files_scanned': self.files_scanned,
                'file_entries_seen': self.file_entries_seen,
                'bytes_examined': self.bytes_examined,
                'files_partially_scanned': self.files_partially_scanned,
                'skipped_items': self.skipped_items,
                'binary_or_encoding_skipped': self.binary_or_encoding_skipped,
                'file_scan_incomplete': self.scan_incomplete,
                'dependency_inventory_incomplete': self.inventory_incomplete,
                'inline_ignores_enabled': self.inline_ignores_enabled,
                'dependencies': len(self.dependencies),
                'unique_dependencies': len({d.coordinate for d in self.dependencies}),
                'possible_secrets': sum(f.category == 'secret' for f in self.findings),
                'third_party_secrets': sum(f.category == 'secret' and f.origin == 'third_party' for f in self.findings),
                'third_party_findings': sum(f.origin == 'third_party' for f in self.findings),
                'advisories': sum(f.category == 'dependency' for f in self.findings),
                'public_information': len(self.observations),
                'osv_status': self.osv_status,
                'osv_queries': self.osv_queries,
            },
            'coverage': {
                'limits': dict(self.limits),
                'encoding_counts': dict(self.encoding_counts),
                'skipped_by_reason': dict(self.skipped_by_reason),
                'scanned_files': [asdict(item) for item in self.scanned_files],
                'skipped_items': [asdict(item) for item in self.skipped_details],
                'scanned_file_details_omitted': self.scanned_file_details_omitted,
                'skipped_details_omitted': self.skipped_details_omitted,
                'note': ('Skipped directories count as one item each; their unvisited descendants are not counted. '
                         'Git history, archive contents and binary files are not analyzed.'),
            },
            'findings': [asdict(item) for item in self.findings],
            'observations': [asdict(item) for item in self.observations],
            'dependencies': [asdict(item) for item in self.dependencies],
            'warnings': list(self.warnings),
        }
