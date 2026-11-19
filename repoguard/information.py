"""Public or possibly public configuration indicators, not vulnerability verdicts.

No matched values or source snippets are returned. These patterns are deliberately
narrow: they are not a general inventory of all external services or configuration.
"""
from dataclasses import dataclass
import re
from typing import Pattern

from .models import Finding


@dataclass(frozen=True)
class InformationRule:
    rule_id: str
    title: str
    pattern: Pattern[str]
    hints: tuple[str, ...]  # Lower-case cheap prefilter; the regex still decides.
    detail: str
    action: str


_INFO_RULES = (
    InformationRule('RG-INFO-001', 'Google advertising publisher identifier',
        re.compile(r'(?<![A-Za-z0-9])(?:ca-)?pub-[0-9]{16}(?![0-9])', re.IGNORECASE), ('pub-',),
        'A string resembles a Google publisher identifier, often intended to appear publicly in ads.txt or site code. Its presence is not a vulnerability.',
        'Check the original file if you need the identifier; compare its configuration in your advertising account.'),
    InformationRule('RG-INFO-002', 'Google advertising integration marker',
        re.compile(r'adsbygoogle|pagead2\.googlesyndication\.com', re.IGNORECASE), ('adsbygoogle', 'pagead2.googlesyndication.com'),
        'The file refers to a Google advertising integration. A reference alone does not prove that ads are active.',
        'Check the site and advertising account configuration if this integration is expected.'),
    InformationRule('RG-INFO-003', 'Google API key-shaped configuration',
        re.compile(r'(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])'), ('aiza',),
        'A string has the format of a Google API key. Browser or Firebase client keys may be intentionally public; this is not proof of a secret leak or a vulnerability. Restrictions were not checked.',
        'Review the key restrictions, quotas and allowed APIs in Google Cloud; also verify server-side authorization and Firebase rules where applicable.'),
    InformationRule('RG-INFO-004', 'Possible Firebase project endpoint',
        re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9-]{2,100}\.(?:firebaseapp\.com|firebaseio\.com|firebasestorage\.app)(?![A-Za-z0-9_-])', re.IGNORECASE),
        ('.firebaseapp.com', '.firebaseio.com', '.firebasestorage.app'),
        'A string resembles a Firebase project endpoint. Its presence does not prove the service or its data is publicly accessible.',
        'Review access controls and security rules in the relevant Firebase project.'),
    InformationRule('RG-INFO-005', 'Possible Google Analytics or Tag Manager identifier',
        re.compile(r'(?<![A-Za-z0-9_-])(?:G-[A-Z0-9]{8,20}|GTM-[A-Z0-9]{4,12}|UA-[0-9]{4,}-[0-9]{1,4})(?![A-Za-z0-9_-])'),
        ('g-', 'gtm-', 'ua-'),
        'A string resembles a Google Analytics or Tag Manager identifier. These identifiers are commonly public; this is not a vulnerability.',
        'Check consent, privacy disclosures and configuration as appropriate for your site.'),
)

MAX_OBSERVATIONS_PER_FILE = 200
_IGNORE = re.compile(r'\brepoguard\s*:\s*ignore\b', re.IGNORECASE)


def scan_information(path: str, text: str, respect_inline_ignores: bool = False,
                     origin: str = 'project') -> list[Finding]:
    """Report at most one observation per rule per line without copying its value."""
    lowered = text.lower()
    candidates = [rule for rule in _INFO_RULES
                  if (any(hint in text for hint in ('G-', 'GTM-', 'UA-'))
                      if rule.rule_id == 'RG-INFO-005'
                      else any(hint in lowered for hint in rule.hints))]
    if not candidates:
        return []
    results: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        if respect_inline_ignores and _IGNORE.search(line):
            continue
        for rule in candidates:
            match = rule.pattern.search(line)
            if not match:
                continue
            results.append(Finding(rule.rule_id, 'information', 'info', rule.title, path, number,
                                   rule.detail, rule.action, column=match.start() + 1, origin=origin))
            if len(results) >= MAX_OBSERVATIONS_PER_FILE:
                return results
    return results
