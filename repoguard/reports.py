"""Text, JSON, SARIF and standalone HTML reports; never include source snippets."""
import html
import json
import re
from urllib.parse import quote

from . import __version__
from .models import Finding, ScanReport


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _osv_label(report: ScanReport) -> str:
    return {
        'not_requested': 'Not checked — use --osv to opt in',
        'complete': f'Queried {report.osv_queries} inventoried exact package version(s)',
        'partial': f'Incomplete ({report.osv_queries} versions queried) — see coverage notes',
        'no_supported_dependencies': 'No supported exact dependency versions found',
        'demo': 'Synthetic example — no OSV request was made',
    }.get(report.osv_status, 'Unknown')


def text_report(report: ScanReport) -> str:
    data = report.to_dict()['summary']
    lines = [
        f"RepoGuard {__version__}  |  {report.project}" + ('  [DEMO — SYNTHETIC]' if report.demo else ''),
        '=' * 60,
        f"Files: {data['files_scanned']} scanned, {data['skipped_items']} skipped items ({data['binary_or_encoding_skipped']} binary/non-UTF-8)",
        f"File scan: {'INCOMPLETE — see coverage notes' if report.scan_incomplete else 'Finished within the documented scope'}",
        f"Dependencies inventoried: {data['dependencies']}" + (' (inventory incomplete)' if report.inventory_incomplete else ''),
        f"Possible secrets: {data['possible_secrets']}  |  Advisory matches: {data['advisories']}",
        f"OSV: {_osv_label(report)}",
        '',
    ]
    if not report.findings:
        lines.append('No findings under the active rules. This is not a security guarantee.')
    for item in report.findings:
        lines.extend([
            f"[{item.severity.upper()}] {item.title} — {item.path}:{item.line}",
            f"  {item.detail}",
            f"  Action: {item.remediation}",
        ])
        if item.reference:
            lines.append(f'  Reference: {item.reference}')
        lines.append('')
    if report.warnings:
        lines.append('Coverage notes:')
        lines.extend(f'  - {message}' for message in report.warnings)
    lines.extend(['', 'Source snippets and matched values are not intentionally copied. Filenames and package metadata may themselves be sensitive.',
                  'Review false positives and coverage limits; an absence of findings is not a security guarantee.'])
    return '\n'.join(lines) + '\n'


def json_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + '\n'


def sarif_report(report: ScanReport) -> str:
    rules = {}
    results = []
    levels = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'unknown': 'warning', 'low': 'note'}
    for finding in report.findings:
        if finding.rule_id not in rules:
            label = 'Known dependency advisory' if finding.category == 'dependency' else finding.title
            rules[finding.rule_id] = {'id': finding.rule_id, 'shortDescription': {'text': label}}
        result = {
            'ruleId': finding.rule_id,
            'level': levels.get(finding.severity, 'warning'),
            'message': {'text': f'{finding.title}. {finding.detail} Action: {finding.remediation}'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(finding.path, safe='/-._~')}, 'region': {'startLine': max(1, finding.line)}}}],
            'properties': {'category': finding.category, 'severity': finding.severity},
        }
        if finding.reference:
            result['properties']['reference'] = finding.reference
        results.append(result)
    document = {
        'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{'tool': {'driver': {'name': 'RepoGuard', 'version': __version__, 'rules': list(rules.values())}},
                  'results': results,
                  'invocations': [{'executionSuccessful': not report.scan_incomplete and report.osv_status != 'partial'}],
                  'properties': {'osv_status': report.osv_status, 'file_scan_incomplete': report.scan_incomplete,
                                 'dependency_inventory_incomplete': report.inventory_incomplete,
                                 'inline_ignores_enabled': report.inline_ignores_enabled,
                                 'coverage_warnings': report.warnings, 'demo': report.demo}}],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + '\n'


def _finding_card(item: Finding) -> str:
    kind = 'DEPENDENCY' if item.category == 'dependency' else 'SECRET'
    severity = item.severity if item.severity in {'high', 'medium', 'low', 'critical', 'unknown'} else 'unknown'
    reference = ''
    if re.fullmatch(r'https://osv\.dev/vulnerability/[A-Za-z0-9._:-]+', item.reference):
        reference = f'<a class="finding-link" href="{_escape(item.reference)}" target="_blank" rel="noopener noreferrer">Read advisory ↗</a>'
    return f'''<article class="finding-card"><div class="finding-main"><div class="finding-head"><span class="severity {severity}">{_escape(severity.upper())}</span><span class="finding-kind">{kind} · {_escape(item.rule_id)}</span></div><h3>{_escape(item.title)}</h3><p>{_escape(item.detail)}</p><div class="location"><span aria-hidden="true">⌁</span> {_escape(item.path)}<span class="line">:{item.line}</span></div></div><div class="finding-action"><span class="action-label">RECOMMENDED NEXT STEP</span><p>{_escape(item.remediation)}</p>{reference}</div></article>'''


def html_report(report: ScanReport) -> str:
    counts = report.to_dict()['summary']
    cards = ''.join(_finding_card(item) for item in report.findings)
    if not cards:
        cards = '<div class="empty-state"><span>✓</span><h3>No findings under the active rules.</h3><p>This is not a guarantee that the project is secure. Review the coverage below.</p></div>'
    warnings = ''.join(f'<li>{_escape(message)}</li>' for message in report.warnings) or '<li>No additional warnings recorded.</li>'
    demo = '<div class="demo-banner">DEMO REPORT <span>— Synthetic data. No real repository was scanned for this example.</span></div>' if report.demo else ''
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark"><title>RepoGuard report — {_escape(report.project)}</title><style>
:root{{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e4ece9;background:#0a1211;font-synthesis:none}}*{{box-sizing:border-box}}body{{margin:0;font-size:14px}}a{{color:#91e4b5}}a:focus-visible{{outline:3px solid #7bdeb0;outline-offset:3px}}.shell{{max-width:1240px;margin:auto;padding:0 32px}}.top{{border-bottom:1px solid #26332f;background:#0d1715}}.top-inner{{height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}}.brand{{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.04em;font-size:18px}}.mark{{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;color:#10201b;background:#9ae1ae;font-size:18px}}.brand small{{color:#719083;font-size:10px;letter-spacing:.12em;font-weight:700;margin-left:6px}}.local{{font-size:10px;letter-spacing:.09em;color:#8fc7a3;border:1px solid #325540;border-radius:20px;padding:6px 10px;white-space:nowrap}}.local:before{{content:'●';font-size:8px;margin-right:6px;color:#78d39a}}.hero{{display:flex;justify-content:space-between;gap:25px;align-items:end;padding:50px 0 30px}}.eyebrow{{color:#83bd99;letter-spacing:.14em;font-size:10px;font-weight:800;margin:0 0 12px}}h1{{font-size:clamp(32px,4vw,45px);letter-spacing:-.055em;line-height:1.08;margin:0 0 12px}}.muted{{color:#849a91;margin:0;line-height:1.6}}.meta{{color:#6f8b7d;font-size:11px;text-align:right;white-space:nowrap}}.demo-banner{{background:#4c3d1b;color:#eed896;border:1px solid #6e5a25;border-radius:10px;padding:11px 14px;margin:0 0 18px;font-weight:800;font-size:11px;letter-spacing:.05em}}.demo-banner span{{font-weight:500;letter-spacing:0}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.stat{{background:#101d19;border:1px solid #263b31;border-radius:13px;padding:19px 20px;min-width:0}}.stat-label{{font-size:10px;color:#819b8e;letter-spacing:.08em;font-weight:750;text-transform:uppercase}}.stat-value{{font-size:29px;font-weight:800;letter-spacing:-.05em;margin:8px 0 2px;color:#e8f2eb}}.stat-value.accent{{color:#9fe5b3}}.stat-help{{color:#6e8879;font-size:11px;line-height:1.4}}.layout{{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:20px;margin-top:34px}}.section-heading{{display:flex;align-items:end;justify-content:space-between;margin-bottom:15px;gap:10px}}.section-heading h2,.coverage h2{{font-size:19px;letter-spacing:-.03em;margin:0}}.section-heading span{{font-size:11px;color:#758b7f}}.findings{{display:grid;gap:10px}}.finding-card{{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(200px,.9fr);background:#101c18;border:1px solid #243a2e;border-radius:12px;overflow:hidden}}.finding-main,.finding-action{{padding:19px 20px}}.finding-action{{border-left:1px solid #273a2f;background:#111f1a}}.finding-head{{display:flex;gap:9px;align-items:center}}.severity{{font-size:9px;letter-spacing:.07em;font-weight:850;border-radius:5px;padding:4px 7px}}.severity.high,.severity.critical{{color:#ffb3a6;background:#59312c}}.severity.medium{{color:#eccc7d;background:#4f4226}}.severity.unknown{{color:#b5c6df;background:#273c52}}.severity.low{{color:#9acead;background:#274632}}.finding-kind{{color:#708c7c;font-size:9px;font-weight:800;letter-spacing:.08em}}.finding-card h3{{font-size:14px;letter-spacing:-.01em;margin:12px 0 6px}}.finding-card p{{color:#8da398;font-size:12px;line-height:1.55;margin:0}}.location{{display:inline-flex;gap:4px;margin-top:12px;background:#1a2b23;color:#bdd1c4;border-radius:6px;padding:5px 8px;font:11px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}.line{{color:#75bf8d}}.action-label{{display:block;color:#6e8d79;font-size:9px;letter-spacing:.09em;font-weight:800;margin-bottom:10px}}.finding-link{{display:inline-block;margin-top:12px;font-size:11px;font-weight:700;text-decoration:none}}.finding-link:hover{{text-decoration:underline}}.coverage{{background:#101c18;border:1px solid #243a2e;border-radius:12px;padding:20px;align-self:start}}.coverage h2{{font-size:15px}}.coverage-row{{padding:15px 0;border-bottom:1px solid #26392e}}.coverage-row strong{{display:block;color:#aac4b1;font-size:11px;margin-bottom:4px}}.coverage-row span{{color:#7b9585;font-size:11px;line-height:1.5}}.coverage ul{{padding-left:17px;color:#8da398;font-size:11px;line-height:1.6}}.privacy{{margin-top:17px;padding:12px;border:1px solid #34543f;border-radius:8px;color:#a6c6ad;background:#17291e;font-size:11px;line-height:1.5}}.empty-state{{background:#101c18;border:1px solid #243a2e;border-radius:12px;padding:35px;text-align:center;color:#8da398}}.empty-state span{{color:#9ce5b0;font-size:24px}}.empty-state h3{{color:#d8e9df}}.empty-state p{{font-size:12px}}footer{{margin-top:55px;padding:25px 0 35px;border-top:1px solid #263a2e;color:#718d7b;font-size:11px;display:flex;justify-content:space-between;gap:20px}}@media(max-width:820px){{.stats{{grid-template-columns:repeat(2,1fr)}}.layout{{grid-template-columns:1fr}}.coverage{{order:-1}}.hero{{align-items:start;flex-direction:column}}.meta{{text-align:left}}}}@media(max-width:520px){{.shell{{padding:0 16px}}.top-inner{{height:62px}}.brand small{{display:none}}.hero{{padding-top:32px}}.stat{{padding:15px}}.stat-value{{font-size:25px}}.finding-card{{grid-template-columns:1fr}}.finding-action{{border-left:0;border-top:1px solid #273a2f}}footer{{flex-direction:column}}}}
</style></head><body><header class="top"><div class="shell top-inner"><div class="brand"><span class="mark" aria-hidden="true">✳</span>repoguard<small>SECURITY REPORT</small></div><span class="local">LOCAL-FIRST</span></div></header><main class="shell"><section class="hero"><div><p class="eyebrow">REPOSITORY SECURITY / REPORT</p><h1>Security, brought<br>into focus<span style="color:#90d8a4">.</span></h1><p class="muted">An explainable snapshot of <strong>{_escape(report.project)}</strong>.<br>Source snippets and matched values are not intentionally copied.</p></div><div class="meta">GENERATED<br>{_escape(report.created_at)}</div></section>{demo}<section class="stats" aria-label="Scan overview"><div class="stat"><div class="stat-label">Possible secrets</div><div class="stat-value">{counts['possible_secrets']:02d}</div><div class="stat-help">Verify every match</div></div><div class="stat"><div class="stat-label">OSV advisories</div><div class="stat-value">{counts['advisories']:02d}</div><div class="stat-help">{_escape(report.osv_status.replace('_',' '))}</div></div><div class="stat"><div class="stat-label">Dependencies</div><div class="stat-value accent">{counts['dependencies']:02d}</div><div class="stat-help">Exact versions inventoried</div></div><div class="stat"><div class="stat-label">Files scanned</div><div class="stat-value">{counts['files_scanned']:02d}</div><div class="stat-help">{counts['skipped_items']} items skipped</div></div></section><div class="layout"><section><div class="section-heading"><h2>Findings</h2><span>{len(report.findings)} total · Review required</span></div><div class="findings">{cards}</div></section><aside class="coverage"><h2>Coverage &amp; context</h2><div class="coverage-row"><strong>Vulnerability lookup</strong><span>{_escape(_osv_label(report))}</span></div><div class="coverage-row"><strong>Scope</strong><span>Working files only. Git history is not scanned. Some files may be excluded or skipped. {'File scan incomplete.' if report.scan_incomplete else ''} {'Dependency inventory incomplete.' if report.inventory_incomplete else ''}</span></div><div class="coverage-row"><strong>Important</strong><span>Heuristics can miss issues or flag false positives. A clean result is not proof of safety.</span></div><ul>{warnings}</ul><div class="privacy">◈ &nbsp;Filenames and package metadata can themselves contain sensitive information. Review reports before sharing.</div></aside></div><footer><span><strong>repoguard.</strong> Built for clarity, not complacency.</span><span>Open source · Local-first · v{_escape(__version__)}</span></footer></main></body></html>'''
