"""Report types. Findings intentionally have no field for source text or secret values."""
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


@dataclass
class ScanReport:
    project: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
    files_scanned: int = 0
    skipped_items: int = 0
    binary_or_encoding_skipped: int = 0
    scan_incomplete: bool = False
    inventory_incomplete: bool = False
    inline_ignores_enabled: bool = False
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    osv_status: str = 'not_requested'
    osv_queries: int = 0
    demo: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema_version': 1,
            'tool': {'name': 'RepoGuard', 'version': __version__},
            'project': self.project,
            'created_at': self.created_at,
            'demo': self.demo,
            'summary': {
                'files_scanned': self.files_scanned,
                'skipped_items': self.skipped_items,
                'binary_or_encoding_skipped': self.binary_or_encoding_skipped,
                'file_scan_incomplete': self.scan_incomplete,
                'dependency_inventory_incomplete': self.inventory_incomplete,
                'inline_ignores_enabled': self.inline_ignores_enabled,
                'dependencies': len(self.dependencies),
                'possible_secrets': sum(f.category == 'secret' for f in self.findings),
                'advisories': sum(f.category == 'dependency' for f in self.findings),
                'osv_status': self.osv_status,
                'osv_queries': self.osv_queries,
            },
            'findings': [asdict(item) for item in self.findings],
            'dependencies': [asdict(item) for item in self.dependencies],
            'warnings': list(self.warnings),
        }
