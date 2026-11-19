"""Optional OSV.dev lookups. Only dependency coordinates (not source text) are sent."""
from dataclasses import dataclass, field
import json
import re
from typing import Callable
import urllib.error
import urllib.request

from .models import Dependency

API_URL = 'https://api.osv.dev/v1/querybatch'
BATCH_SIZE = 100
MAX_COORDINATES = 1000
MAX_PAGES = 5
MAX_MATCHES = 10000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')


@dataclass
class OsvResult:
    matches: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    status: str = 'not_requested'
    checked: int = 0  # Coordinates whose full response, including pagination, was processed.
    warnings: list[str] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _post_json(payload: dict) -> dict:
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload, separators=(',', ':')).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'RepoGuard/0.1'},
        method='POST',
    )
    # Do not follow redirects: a malicious redirect must not receive inventory data.
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=15) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError('OSV response too large')
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError('Invalid OSV response')
    return parsed


def lookup(dependencies: list[Dependency], post: Callable[[dict], dict] | None = None) -> OsvResult:
    """Query bounded batches and per-item pagination. Any missing result is marked partial."""
    send = post or _post_json
    coordinates = list(dict.fromkeys(dep.coordinate for dep in dependencies))
    if not coordinates:
        return OsvResult(status='no_supported_dependencies')
    result = OsvResult(status='complete')
    if len(coordinates) > MAX_COORDINATES:
        coordinates = coordinates[:MAX_COORDINATES]
        result.status = 'partial'
        result.warnings.append(f'OSV checks are limited to {MAX_COORDINATES} unique dependency versions per scan.')
    total_matches = 0
    seen_matches: dict[tuple[str, str, str], set[str]] = {}
    invalid: set[tuple[str, str, str]] = set()
    for offset in range(0, len(coordinates), BATCH_SIZE):
        batch = coordinates[offset:offset + BATCH_SIZE]
        pending: list[tuple[tuple[str, str, str], str | None]] = [(item, None) for item in batch]
        page = 0
        while pending and page < MAX_PAGES:
            page += 1
            queries = []
            for (ecosystem, name, version), page_token in pending:
                query = {'package': {'name': name, 'ecosystem': ecosystem}, 'version': version}
                if page_token:
                    query['page_token'] = page_token
                queries.append(query)
            try:
                response = send({'queries': queries})
                if not isinstance(response, dict):
                    raise ValueError('Unexpected response')
                rows = response.get('results')
                if not isinstance(rows, list) or len(rows) != len(pending):
                    raise ValueError('Unexpected batch size')
            except (OSError, ValueError, TypeError, urllib.error.URLError):
                result.status = 'partial'
                result.warnings.append('OSV could not be reached or returned an invalid response; dependency results are incomplete.')
                return result
            next_pending = []
            for (coordinate, _old_token), row in zip(pending, rows):
                if not isinstance(row, dict) or not isinstance(row.get('vulns', []), list):
                    invalid.add(coordinate)
                    result.status = 'partial'
                    continue
                bucket = result.matches.setdefault(coordinate, [])
                seen = seen_matches.setdefault(coordinate, set())
                for advisory in row.get('vulns', []):
                    identifier = advisory.get('id') if isinstance(advisory, dict) else None
                    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                        invalid.add(coordinate)
                        result.status = 'partial'
                        continue
                    if identifier not in seen:
                        if total_matches >= MAX_MATCHES:
                            result.status = 'partial'
                            result.warnings.append(f'OSV results were limited to {MAX_MATCHES} advisory matches.')
                            return result
                        bucket.append(identifier)
                        seen.add(identifier)
                        total_matches += 1
                token = row.get('next_page_token')
                if token is None or token == '':
                    if coordinate not in invalid:
                        result.checked += 1
                elif isinstance(token, str) and len(token) <= 4096:
                    next_pending.append((coordinate, token))
                else:
                    invalid.add(coordinate)
                    result.status = 'partial'
            pending = next_pending
        if pending:
            result.status = 'partial'
            result.warnings.append(f'OSV pagination stopped after {MAX_PAGES} pages for at least one dependency.')
    if result.status == 'partial' and not result.warnings:
        result.warnings.append('Some OSV responses were incomplete or invalid.')
    return result
