"""Conservative, explainable credential checks. Matched source values are never returned."""
from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Pattern

from .models import Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: Pattern[str]
    detail: str
    remediation: str
    generic: bool = False


_ROTATE = ('Verify the finding. If it is real, revoke or rotate the credential first; '
           'then remove it from the repository and its history.')
_RULES = (
    Rule('RG-SEC-001', 'Possible GitHub token', 'high',
         re.compile(r'(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])'),
         'A string resembles a GitHub token. The matched value is not included in this report.', _ROTATE),
    Rule('RG-SEC-002', 'Possible fine-grained GitHub token', 'high',
         re.compile(r'(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])'),
         'A string resembles a fine-grained GitHub token.', _ROTATE),
    Rule('RG-SEC-003', 'Private key block', 'high',
         re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'),
         'A private-key block marker was found; key contents are not shown.',
         'Verify whether the key is real. Replace compromised keys and remove them from repository history.'),
    Rule('RG-SEC-004', 'Possible Stripe live key', 'high',
         re.compile(r'(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{16,255}(?![A-Za-z0-9_])'),
         'A string resembles a live Stripe secret or restricted key.', _ROTATE),
    Rule('RG-SEC-005', 'Possible Slack token', 'high',
         re.compile(r'(?<![A-Za-z0-9_])xox[baprs]-[A-Za-z0-9-]{20,255}(?![A-Za-z0-9_])'),
         'A string resembles a Slack token.', _ROTATE),
    Rule('RG-SEC-006', 'Possible AWS access key ID', 'medium',
         re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
         'An AWS access key ID was found. An ID alone is not the corresponding secret key.',
         'Review the associated IAM principal and rotate credentials if exposure is confirmed.'),
    Rule('RG-SEC-007', 'Possible hard-coded credential', 'medium',
         re.compile(r'''(?i)(?<![A-Za-z0-9_])["']?(?:[A-Za-z0-9]+[_-])*(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret(?:[_-]access[_-]key|[_-]key)?|token)["']?\s*[:=]\s*(?:["'](?P<quoted>[^"'\r\n]{12,256})["']|(?P<bare>[A-Za-z0-9+/_=.!@#$%&*~^:-]{12,256})(?=\s|$|[,;\]}]))'''),
         'An assignment contains a credential-like value. This heuristic can produce false positives and miss weak or unusual values.',
         'Check whether it is a real credential; rotate it if exposed and use a secrets manager.', True),
    Rule('RG-SEC-008', 'Possible credential in connection URL', 'high',
         re.compile(r'(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s/@]{4,}@[A-Za-z0-9]'),
         'A connection URL appears to contain a username and password.', _ROTATE),
    Rule('RG-SEC-009', 'Possible GitLab token', 'high',
         re.compile(r'(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])'),
         'A string resembles a GitLab personal access token.', _ROTATE),
    Rule('RG-SEC-010', 'Possible npm token', 'high',
         re.compile(r'(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])'),
         'A string resembles an npm access token.', _ROTATE),
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower().strip()
    prefixes = ('example', 'sample', 'dummy', 'placeholder', 'changeme', 'change-me', 'replace-me', 'your_', 'your-', '<', '${')
    return lowered.startswith(prefixes) or len(set(value)) < 5 or _entropy(value) < 3.0


MAX_FINDINGS_PER_FILE = 1000
_IGNORE = re.compile(r'\brepoguard\s*:\s*ignore\b', re.IGNORECASE)


def scan_text(path: str, text: str, respect_inline_ignores: bool = False) -> list[Finding]:
    """Report at most one finding per rule per line, with no matched text."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        # Off by default: a contributor could otherwise hide a real secret in a PR.
        if respect_inline_ignores and _IGNORE.search(line):
            continue
        for rule in _RULES:
            for match in rule.pattern.finditer(line):
                if rule.generic:
                    value = match.group('quoted') or match.group('bare')
                    if _looks_like_placeholder(value):
                        continue
                    # Avoid counting the same credential twice when a more specific
                    # provider rule already covers the value of this assignment.
                    if any(specific.pattern.search(value) for specific in _RULES if not specific.generic):
                        continue
                findings.append(Finding(
                    rule_id=rule.rule_id, category='secret', severity=rule.severity,
                    title=rule.title, path=path, line=number, detail=rule.detail,
                    remediation=rule.remediation,
                ))
                if len(findings) >= MAX_FINDINGS_PER_FILE:
                    return findings
                break
    return findings
