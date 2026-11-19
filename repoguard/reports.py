"""Text, JSON, SARIF and offline HTML reports; never include source snippets."""
import html
import json
import re
from urllib.parse import quote

from . import __version__
from .models import Finding, ScanReport


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


_TEXT = {
    'en': {
        'scope_standard': 'Standard', 'scope_deep': 'Deep', 'origin_project': 'Project',
        'origin_generated': 'Generated', 'origin_third_party': 'Third-party',
        'scanned': 'Text files analyzed', 'entries': 'File entries examined', 'skipped': 'Skipped items or file parts',
        'partial_files': 'partially analyzed text files', 'secrets': 'Possible secrets', 'advisories': 'OSV advisory matches',
        'information': 'Public information & configuration', 'dependencies': 'Dependency entries', 'unique': 'unique coordinates',
        'file_status': 'File scan', 'incomplete': 'INCOMPLETE — see coverage notes',
        'within_scope': 'Finished within the configured scope; see exclusions',
        'inventory_incomplete': 'dependency inventory incomplete', 'scope': 'Scope', 'osv': 'OSV',
        'findings': 'Findings to review', 'vendor_findings': 'Third-party findings', 'action': 'Next step',
        'no_findings': 'No findings under the active rules. This is not a security guarantee.',
        'info_intro': 'Informational indicators are not automatically secrets or vulnerabilities and do not trigger --fail-on.',
        'no_info': 'No matching informational indicators in the analyzed text.',
        'coverage': 'Coverage & context', 'warnings': 'Coverage notes', 'none': 'None recorded.',
        'limits': 'Limits', 'file_limit': 'per file', 'entry_limit': 'file entries', 'total_limit': 'total bytes',
        'skip_by_reason': 'Omissions by reason', 'skipped_list': 'Skipped items and file parts', 'scanned_list': 'Analyzed file inventory',
        'no_details': 'No detailed entries recorded.', 'details_omitted': 'additional entries omitted from the report',
        'details_more_text': 'additional recorded entries; use HTML or JSON to view them',
        'file_part': 'part of file', 'file': 'file', 'directory': 'directory', 'partial': 'partial',
        'binary': 'binary or unsupported encoding', 'size': 'bytes examined', 'unknown': 'unknown',
        'coverage_explain': 'A skipped directory counts as one item: files inside it were not enumerated. Git history, archive contents and binary files are not analyzed.',
        'lock_explain': 'In standard mode node_modules is skipped, except its hidden npm lock when present. Deep mode includes dependency and vendor directories.',
        'privacy': 'Source snippets and matched values are not intentionally copied. Project names, paths and package metadata may themselves be sensitive; review before sharing.',
        'caution': 'Heuristics can miss issues or flag harmless examples, especially in generated or third-party code. At most one result per rule and line is shown, even on minified lines with multiple matches. A clean result is not proof of safety.',
        'demo': 'DEMO — SYNTHETIC', 'demo_note': 'Synthetic data. No real repository was scanned for this example.',
        'view_advisory': 'Read advisory ↗', 'secret_kind': 'POSSIBLE SECRET', 'dependency_kind': 'DEPENDENCY',
        'info_kind': 'INFORMATION', 'review_required': 'Review required', 'local': 'LOCAL-FIRST',
        'hero_eyebrow': 'REPOSITORY SECURITY / REPORT', 'hero_title': 'Security, brought into focus.',
        'hero_subtitle': 'An explainable snapshot of', 'generated_at': 'GENERATED',
        'report_title': 'RepoGuard report', 'osv_help': 'Not all advisories are distinct issues',
        'files_help': 'Some items may be omitted', 'info_help': 'Not vulnerability verdicts',
        'secrets_help': 'Verify every match', 'in_vendor': 'in third-party code', 'osv_partial_short': 'Lookup or inventory incomplete',
        'vendor_note': 'Results in third-party or compiled code often include examples or false positives.',
        'formats': 'Encodings analyzed', 'deps_list': 'Dependency inventory', 'line': 'line', 'column': 'column',
        'no_warnings': 'No additional warnings recorded.', 'read_time': 'Generated locally',
        'ref': 'Reference', 'info_severity': 'INFO', 'bytes': 'bytes', 'files': 'files',
        'dep_help': 'Exact versions inventoried; installed npm metadata can be stale.',
    },
    'fr': {
        'scope_standard': 'Standard', 'scope_deep': 'Approfondi', 'origin_project': 'Projet',
        'origin_generated': 'Fichier généré', 'origin_third_party': 'Dépendance / tiers',
        'scanned': 'Fichiers texte analysés', 'entries': 'Entrées de fichiers examinées', 'skipped': 'Éléments ou portions ignorés',
        'partial_files': 'fichiers texte analysés partiellement', 'secrets': 'Secrets possibles', 'advisories': 'Correspondances avec des avis OSV',
        'information': 'Informations publiques et configurations', 'dependencies': 'Entrées de dépendances', 'unique': 'coordonnées distinctes',
        'file_status': 'Analyse des fichiers', 'incomplete': 'INCOMPLÈTE — voir les notes de couverture',
        'within_scope': 'Terminée dans le périmètre choisi ; voir les exclusions',
        'inventory_incomplete': 'inventaire des dépendances incomplet', 'scope': 'Périmètre', 'osv': 'OSV',
        'findings': 'Alertes à vérifier', 'vendor_findings': 'Alertes dans les fichiers tiers', 'action': 'Prochaine étape',
        'no_findings': 'Aucune alerte selon les règles actives. Cela ne garantit pas la sécurité du projet.',
        'info_intro': 'Ces indices sont informatifs : ils ne sont pas automatiquement des secrets ou des failles et ne déclenchent pas --fail-on.',
        'no_info': 'Aucun indice informatif correspondant dans les textes analysés.',
        'coverage': 'Couverture et contexte', 'warnings': 'Notes de couverture', 'none': 'Aucun élément enregistré.',
        'limits': 'Limites', 'file_limit': 'par fichier', 'entry_limit': 'entrées de fichiers', 'total_limit': 'octets au total',
        'skip_by_reason': 'Omissions par raison', 'skipped_list': 'Éléments et portions ignorés', 'scanned_list': 'Liste des fichiers analysés',
        'no_details': 'Aucun détail enregistré.', 'details_omitted': 'entrées supplémentaires omises du rapport',
        'details_more_text': 'entrées supplémentaires enregistrées ; utilisez HTML ou JSON pour les voir',
        'file_part': 'portion de fichier', 'file': 'fichier', 'directory': 'dossier', 'partial': 'partiel',
        'binary': 'binaires ou encodages non pris en charge', 'size': 'octets examinés', 'unknown': 'inconnue',
        'coverage_explain': 'Un dossier ignoré compte pour un seul élément : ses fichiers internes ne sont pas comptés. L’historique Git, le contenu des archives et les binaires ne sont pas analysés.',
        'lock_explain': 'En mode standard, node_modules est ignoré sauf son fichier de verrouillage npm caché s’il existe. Le mode approfondi inclut les dossiers de dépendances et de code tiers.',
        'privacy': 'Les extraits et valeurs détectées ne sont pas volontairement recopiés. Les noms de projets, chemins et métadonnées des paquets peuvent eux-mêmes être sensibles : vérifiez avant de partager.',
        'caution': 'Les règles peuvent manquer des problèmes ou signaler des exemples inoffensifs, surtout dans le code généré ou tiers. Un résultat au maximum est affiché par règle et par ligne, même si une ligne minifiée contient plusieurs correspondances. Un rapport vide ne prouve pas la sécurité.',
        'demo': 'DÉMONSTRATION — FICTIVE', 'demo_note': 'Données fictives. Aucun dépôt réel n’a été analysé pour cet exemple.',
        'view_advisory': 'Consulter l’avis ↗', 'secret_kind': 'SECRET POSSIBLE', 'dependency_kind': 'DÉPENDANCE',
        'info_kind': 'INFORMATION', 'review_required': 'Vérification nécessaire', 'local': 'LOCAL PAR DÉFAUT',
        'hero_eyebrow': 'SÉCURITÉ DU DÉPÔT / RAPPORT', 'hero_title': 'La sécurité, plus claire.',
        'hero_subtitle': 'Un aperçu explicable de', 'generated_at': 'GÉNÉRÉ',
        'report_title': 'Rapport RepoGuard', 'osv_help': 'Plusieurs avis peuvent décrire le même problème',
        'files_help': 'Certains éléments peuvent être omis', 'info_help': 'Ce ne sont pas des verdicts de faille',
        'secrets_help': 'Vérifiez chaque résultat', 'in_vendor': 'dans du code tiers', 'osv_partial_short': 'Recherche ou inventaire incomplet',
        'vendor_note': 'Les résultats dans le code tiers ou compilé peuvent être des exemples ou des faux positifs.',
        'formats': 'Encodages analysés', 'deps_list': 'Inventaire des dépendances', 'line': 'ligne', 'column': 'colonne',
        'no_warnings': 'Aucune note supplémentaire enregistrée.', 'read_time': 'Généré localement',
        'ref': 'Référence', 'info_severity': 'INFO', 'bytes': 'octets', 'files': 'fichiers',
        'dep_help': 'Versions exactes inventoriées ; les métadonnées npm installées peuvent être périmées.',
    },
}

_REASONS = {
    'vcs_metadata': ('Git/VCS metadata — history not analyzed', 'Métadonnées Git/VCS — historique non analysé'),
    'standard_excluded_directory': ('Directory excluded in standard mode', 'Dossier exclu en mode standard'),
    'user_excluded_directory': ('Directory excluded by the user', 'Dossier exclu par l’utilisateur'),
    'user_excluded_file': ('File excluded by the user', 'Fichier exclu par l’utilisateur'),
    'symlink_directory': ('Symbolic-link directory not followed', 'Lien symbolique vers un dossier non suivi'),
    'symlink_or_non_regular_file': ('Symbolic link or non-regular file', 'Lien symbolique ou fichier non ordinaire'),
    'archive_or_document_not_opened': ('Archive or document not opened', 'Archive ou document non ouvert'),
    'binary_or_non_text': ('Binary or non-text file', 'Fichier binaire ou non textuel'),
    'unsupported_encoding': ('Unsupported text encoding', 'Encodage texte non pris en charge'),
    'unreadable_file': ('File could not be read', 'Fichier illisible'),
    'unreadable_directory': ('Directory could not be read', 'Dossier illisible'),
    'file_size_limit': ('File tail exceeds per-file limit', 'Fin de fichier au-delà de la limite par fichier'),
    'total_byte_limit': ('File tail exceeds total byte limit', 'Fin de fichier au-delà de la limite totale'),
    'report_output': ('Output report excluded', 'Rapport de sortie exclu'),
}

_ROTATE_FR = 'Vérifiez le résultat. Si le secret est réel, révoquez-le ou renouvelez-le d’abord, puis retirez-le du dépôt et de son historique.'
_FR_FINDINGS = {
    'RG-SEC-001': ('Jeton GitHub possible', 'Une chaîne ressemble à un jeton GitHub. Sa valeur n’est pas affichée.', _ROTATE_FR),
    'RG-SEC-002': ('Jeton GitHub à permissions fines possible', 'Une chaîne ressemble à un jeton GitHub à permissions fines.', _ROTATE_FR),
    'RG-SEC-003': ('Bloc de clé privée', 'Un marqueur de clé privée est présent ; le contenu de la clé n’est pas affiché.', 'Vérifiez si la clé est réelle. Si elle est exposée, remplacez-la et retirez-la de l’historique.'),
    'RG-SEC-004': ('Clé Stripe de production possible', 'Une chaîne ressemble à une clé Stripe secrète ou restreinte de production.', _ROTATE_FR),
    'RG-SEC-005': ('Jeton Slack possible', 'Une chaîne ressemble à un jeton Slack.', _ROTATE_FR),
    'RG-SEC-006': ('Identifiant de clé d’accès AWS possible', 'Un identifiant de clé AWS a été repéré. Un identifiant seul n’est pas la clé secrète correspondante.', 'Vérifiez le compte IAM associé et renouvelez les identifiants si leur exposition est confirmée.'),
    'RG-SEC-007': ('Identifiant sensible inscrit en dur : possibilité', 'Une affectation ressemble à un identifiant sensible. Cette règle peut signaler des exemples ou du code compilé et manquer d’autres valeurs.', 'Vérifiez s’il s’agit d’un vrai secret ; si oui, renouvelez-le et utilisez un gestionnaire de secrets.'),
    'RG-SEC-008': ('Identifiants possibles dans une URL de connexion', 'Une URL de connexion semble contenir un utilisateur et un mot de passe.', _ROTATE_FR),
    'RG-SEC-009': ('Jeton GitLab possible', 'Une chaîne ressemble à un jeton personnel GitLab.', _ROTATE_FR),
    'RG-SEC-010': ('Jeton npm possible', 'Une chaîne ressemble à un jeton d’accès npm.', _ROTATE_FR),
    'RG-SEC-011': ('Secret client OAuth Google possible', 'Une chaîne ressemble à un secret client OAuth Google, différent d’une clé API de navigateur.', _ROTATE_FR),
    'RG-SEC-012': ('Jeton d’accès OAuth Google possible', 'Une chaîne ressemble à un jeton d’accès OAuth Google.', _ROTATE_FR),
    'RG-SEC-013': ('Clé API SendGrid possible', 'Une chaîne ressemble à une clé API SendGrid.', _ROTATE_FR),
    'RG-SEC-014': ('Clé API secrète possible', 'Une chaîne ressemble à une clé API secrète. Des exemples ou chaînes sans rapport peuvent aussi correspondre.', _ROTATE_FR),
    'RG-INFO-001': ('Identifiant éditeur Google publicitaire', 'Une chaîne ressemble à un identifiant éditeur Google, souvent destiné à être public dans ads.txt ou le code du site. Sa présence n’est pas une faille.', 'Consultez le fichier d’origine si vous souhaitez voir l’identifiant et comparez la configuration dans votre compte publicitaire.'),
    'RG-INFO-002': ('Indice d’intégration publicitaire Google', 'Le fichier fait référence à une intégration publicitaire Google. Cette référence seule ne prouve pas que les publicités sont actives.', 'Vérifiez le site et la configuration du compte publicitaire si cette intégration est attendue.'),
    'RG-INFO-003': ('Configuration ressemblant à une clé API Google', 'Une chaîne a le format d’une clé API Google. Les clés clientes de navigateur ou Firebase peuvent être volontairement publiques : ce n’est pas une preuve de fuite ou de faille. Les restrictions n’ont pas été vérifiées.', 'Vérifiez dans Google Cloud les restrictions, quotas et API autorisées ; vérifiez aussi les autorisations côté serveur et les règles Firebase si nécessaire.'),
    'RG-INFO-004': ('Adresse de projet Firebase possible', 'Une chaîne ressemble à une adresse de projet Firebase. Sa présence ne prouve pas que le service ou ses données sont accessibles publiquement.', 'Vérifiez les contrôles d’accès et les règles de sécurité du projet Firebase concerné.'),
    'RG-INFO-005': ('Identifiant Google Analytics ou Tag Manager possible', 'Une chaîne ressemble à un identifiant Google Analytics ou Tag Manager. Ces identifiants sont souvent publics ; ce n’est pas une faille.', 'Vérifiez si nécessaire le consentement, la politique de confidentialité et la configuration du site.'),
}


def _tr(language: str, key: str) -> str:
    return _TEXT.get(language, _TEXT['en'])[key]


def _reason(reason: str, language: str) -> str:
    translations = _REASONS.get(reason)
    return translations[1 if language == 'fr' else 0] if translations else reason.replace('_', ' ')


def _origin_label(origin: str, language: str) -> str:
    return _tr(language, 'origin_' + origin) if origin in {'project', 'generated', 'third_party'} else origin


def _finding_text(item: Finding, language: str) -> tuple[str, str, str]:
    if language != 'fr':
        return item.title, item.detail, item.remediation
    if item.rule_id in _FR_FINDINGS:
        return _FR_FINDINGS[item.rule_id]
    if item.rule_id == 'RG-DEP-OSV':
        advisory = item.reference.rsplit('/', 1)[-1] if item.reference else item.title
        match = re.fullmatch(r'(npm|PyPI) package (\S+) (\S+) matched an OSV advisory\. Severity is not assessed by this version\.', item.detail)
        detail = (f'Le paquet {match.group(2)} ({match.group(1)}, version {match.group(3)}) correspond à un avis OSV. Sa gravité n’est pas évaluée.'
                  if match else 'Une dépendance correspond à un avis OSV. Sa gravité n’est pas évaluée.')
        return (f'Avis de sécurité : {advisory}', detail,
                'Consultez l’avis, vérifiez s’il s’applique et mettez à jour ou atténuez le risque selon ses recommandations.')
    return item.title, item.detail, item.remediation


def _warning(message: str, language: str) -> str:
    if language != 'fr':
        return message
    exact = {
        'Inline ignores are enabled: ignored lines are not scanned and may hide real secrets.': 'Les exclusions en ligne sont activées : les lignes ignorées ne sont pas analysées et peuvent cacher de vrais secrets.',
        'The hidden npm lock describes installed packages and may be stale; it is not a complete dependency guarantee.': 'Le fichier npm caché décrit des paquets installés et peut être périmé ; il ne garantit pas un inventaire complet.',
        'The dependency inventory is incomplete; OSV results cannot cover all dependencies.': 'L’inventaire des dépendances est incomplet : les résultats OSV ne peuvent pas couvrir toutes les dépendances.',
        'OSV could not be reached or returned an invalid response; dependency results are incomplete.': 'OSV est inaccessible ou sa réponse est invalide : les résultats sur les dépendances sont incomplets.',
        'Some OSV responses were incomplete or invalid.': 'Certaines réponses OSV étaient incomplètes ou invalides.',
        'Additional warnings omitted.': 'Des notes supplémentaires ont été omises.',
    }
    if message in exact:
        return exact[message]
    suffixes = {
        ': this dependency file format is not inventoried by RepoGuard.': ': ce format de dépendances n’est pas inventorié par RepoGuard.',
        ': dependency file was excluded from the inventory.': ': fichier de dépendances exclu de l’inventaire.',
        ': dependency file is a symlink or is not a regular file and was skipped.': ': fichier de dépendances ignoré car c’est un lien symbolique ou un fichier non ordinaire.',
        ': dependency file is binary or has an unsupported encoding.': ': fichier de dépendances binaire ou d’encodage non pris en charge.',
        ': file could not be read safely.': ': fichier impossible à lire en toute sécurité.',
        ': a directory could not be read; coverage is incomplete.': ': dossier illisible ; la couverture est incomplète.',
        ': a directory entry could not be inspected.': ': entrée de dossier impossible à examiner.',
        ': hidden npm lock could not be inspected.': ': fichier npm caché impossible à examiner.',
        ': installed npm package manifest could not be parsed.': ': fichier de paquet npm installé impossible à lire.',
        ': installed npm package has no supported exact name and version.': ': le paquet npm installé n’a pas de nom et de version exacte reconnus.',
        ': package-lock.json could not be parsed.': ': fichier de verrouillage npm impossible à lire.',
        ': package-lock.json is not an object.': ': le fichier de verrouillage npm n’est pas un objet.',
        ': unsupported or missing npm lockfileVersion.': ': version du fichier de verrouillage npm absente ou non prise en charge.',
        ': package-lock.json is missing its packages inventory.': ': l’inventaire des paquets manque dans le fichier de verrouillage npm.',
        ': npm v1 dependency inventory is not an object.': ': l’inventaire npm v1 n’est pas un objet.',
        ': dependency inventory was truncated.': ': inventaire des dépendances tronqué.',
    }
    for end, translated in suffixes.items():
        if message.endswith(end):
            return message[:-len(end)] + translated
    patterns = (
        (r'^Scan stopped after (\d+) file entries; coverage is incomplete\.$', r'Analyse arrêtée après \1 entrées de fichiers ; la couverture est incomplète.'),
        (r'^Scan stopped at the (\d+) byte total limit; coverage is incomplete\.$', r'Analyse arrêtée à la limite totale de \1 octets ; la couverture est incomplète.'),
        (r'^(.*): only the first (\d+) bytes were examined; the rest exceeded a scan limit\.$', r'\1 : seuls les \2 premiers octets ont été examinés ; le reste dépasse une limite.'),
        (r'^(.*): (\d+) non-exact or unsupported requirement\(s\) were not inventoried\.$', r'\1 : \2 dépendance(s) sans version exacte ou non prises en charge n’ont pas été inventoriées.'),
        (r'^(.*): (\d+) dependency entry/entries had unsupported names or versions\.$', r'\1 : \2 entrée(s) avaient un nom ou une version non pris en charge.'),
        (r'^(.*): secret findings were capped at (\d+)\.$', r'\1 : alertes de secrets limitées à \2.'),
        (r'^(.*): information observations were capped at (\d+)\.$', r'\1 : informations limitées à \2.'),
        (r'^Dependency inventory is limited to (\d+) entries\.$', r'L’inventaire est limité à \1 entrées de dépendances.'),
        (r'^OSV checks are limited to (\d+) unique dependency versions per scan\.$', r'Les recherches OSV sont limitées à \1 versions de dépendances distinctes.'),
        (r'^OSV pagination stopped after (\d+) pages for at least one dependency\.$', r'La pagination OSV s’est arrêtée après \1 pages pour au moins une dépendance.'),
    )
    for pattern, replacement in patterns:
        if re.fullmatch(pattern, message):
            return re.sub(pattern, replacement, message)
    return message  # Unknown future warnings remain visible rather than being silently dropped.


def _osv_label(report: ScanReport, language: str = 'en') -> str:
    if language == 'fr':
        return {
            'not_requested': 'Non consulté — utilisez --osv pour l’activer',
            'complete': f'{report.osv_queries} version(s) exacte(s) inventoriée(s) consultée(s)',
            'partial': f'Incomplet ({report.osv_queries} versions consultées) — voir les notes',
            'no_supported_dependencies': 'Aucune version exacte prise en charge trouvée',
            'demo': 'Exemple fictif — aucune requête OSV effectuée',
        }.get(report.osv_status, 'Inconnu')
    return {
        'not_requested': 'Not checked — use --osv to opt in',
        'complete': f'Queried {report.osv_queries} inventoried exact package version(s)',
        'partial': f'Incomplete ({report.osv_queries} versions queried) — see coverage notes',
        'no_supported_dependencies': 'No supported exact dependency versions found',
        'demo': 'Synthetic example — no OSV request was made',
    }.get(report.osv_status, 'Unknown')


def _severity(item: Finding, language: str) -> str:
    if language == 'fr':
        return {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN', 'low': 'FAIBLE',
                'unknown': 'INCONNU', 'info': 'INFO'}.get(item.severity, 'INCONNU')
    return item.severity.upper()


def text_report(report: ScanReport, language: str = 'en') -> str:
    tr = lambda key: _tr(language, key)
    data = report.to_dict()['summary']
    lines = [
        f"RepoGuard {__version__}  |  {report.project}" + (f"  [{tr('demo')}]" if report.demo else ''),
        '=' * 60,
        f"{tr('scope')}: {tr('scope_deep' if report.scope == 'deep' else 'scope_standard')}",
        f"{tr('scanned')}: {data['files_scanned']} ({data['files_partially_scanned']} {tr('partial_files')})",
        f"{tr('entries')}: {data['file_entries_seen']}  |  {tr('skipped')}: {data['skipped_items']} ({data['binary_or_encoding_skipped']} {tr('binary')})",
        f"{tr('file_status')}: {tr('incomplete') if report.scan_incomplete else tr('within_scope')}",
        f"{tr('dependencies')}: {data['dependencies']} ({data['unique_dependencies']} {tr('unique')})" + (f" — {tr('inventory_incomplete')}" if report.inventory_incomplete else ''),
        f"{tr('secrets')}: {data['possible_secrets']} ({data['third_party_secrets']} {tr('in_vendor')})  |  {tr('advisories')}: {data['advisories']}  |  {tr('information')}: {data['public_information']}",
        f"OSV: {_osv_label(report, language)}", '', tr('findings') + ':',
    ]
    if not report.findings:
        lines.append(tr('no_findings'))
    for item in report.findings:
        title, detail, action = _finding_text(item, language)
        lines.extend([f"[{_severity(item, language)} · {_origin_label(item.origin, language)}] {title} — {item.path}:{item.line}:{item.column}",
                      f'  {detail}', f"  {tr('action')}: {action}"])
        if item.reference:
            lines.append(f"  {tr('ref')}: {item.reference}")
        lines.append('')
    lines.extend([tr('information') + ':', tr('info_intro')])
    if not report.observations:
        lines.append(tr('no_info'))
    for item in report.observations:
        title, detail, action = _finding_text(item, language)
        lines.extend([f"[INFO · {_origin_label(item.origin, language)}] {title} — {item.path}:{item.line}:{item.column}",
                      f'  {detail}', f"  {tr('action')}: {action}", ''])
    lines.extend(['', tr('coverage') + ':', '  ' + tr('coverage_explain'), '  ' + tr('lock_explain')])
    if report.limits:
        lines.append(f"  {tr('limits')}: {report.limits['file_bytes']} {tr('bytes')} {tr('file_limit')}; {report.limits['file_entries']} {tr('entry_limit')}; {report.limits['total_bytes']} {tr('total_limit')}.")
    if report.encoding_counts:
        lines.append(f"  {tr('formats')}: " + ', '.join(f'{k}: {v}' for k, v in report.encoding_counts.items()))
    lines.append(f"  {tr('skip_by_reason')}:")
    lines.extend(f'    - {_reason(reason, language)}: {count}' for reason, count in report.skipped_by_reason.items())
    if not report.skipped_by_reason:
        lines.append('    - ' + tr('none'))
    if report.warnings:
        lines.append(f"  {tr('warnings')}:")
        lines.extend(f'    - {_warning(message, language)}' for message in report.warnings)
    for title, records, omitted, fmt in (
        (tr('skipped_list'), report.skipped_details, report.skipped_details_omitted,
         lambda x: f'{x.path} — {_reason(x.reason, language)}'),
        (tr('scanned_list'), report.scanned_files, report.scanned_file_details_omitted,
         lambda x: f'{x.path} — {x.encoding}, {x.bytes_scanned} {tr("bytes")}' + (f' ({tr("partial")})' if x.partial else '')),
    ):
        lines.append(f'  {title} ({len(records)}):')
        lines.extend('    - ' + fmt(x) for x in records[:100])
        if not records:
            lines.append('    - ' + tr('no_details'))
        if len(records) > 100:
            lines.append(f"    - {len(records) - 100} {tr('details_more_text')}.")
        if omitted:
            lines.append(f"    - {omitted} {tr('details_omitted')}.")
    lines.extend(['', tr('privacy'), tr('caution')])
    return '\n'.join(lines) + '\n'


def json_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + '\n'


def sarif_report(report: ScanReport) -> str:
    rules = {}
    results = []
    levels = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'unknown': 'warning', 'low': 'note', 'info': 'note'}
    for finding in report.findings + report.observations:
        if finding.rule_id not in rules:
            label = 'Known dependency advisory' if finding.category == 'dependency' else finding.title
            rules[finding.rule_id] = {'id': finding.rule_id, 'shortDescription': {'text': label}}
        result = {
            'ruleId': finding.rule_id,
            'level': levels.get(finding.severity, 'warning'),
            'message': {'text': f'{finding.title}. {finding.detail} Action: {finding.remediation}'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(finding.path, safe='/-._~')},
                                               'region': {'startLine': max(1, finding.line), 'startColumn': max(1, finding.column)}}}],
            'properties': {'category': finding.category, 'severity': finding.severity, 'origin': finding.origin},
        }
        if finding.category == 'information':
            result['kind'] = 'informational'
        if finding.reference:
            result['properties']['reference'] = finding.reference
        results.append(result)
    document = {
        'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{'tool': {'driver': {'name': 'RepoGuard', 'version': __version__, 'rules': list(rules.values())}},
                  'columnKind': 'unicodeCodePoints', 'results': results,
                  'invocations': [{'executionSuccessful': not report.scan_incomplete and report.osv_status != 'partial'}],
                  'properties': {'osv_status': report.osv_status, 'file_scan_incomplete': report.scan_incomplete,
                                 'dependency_inventory_incomplete': report.inventory_incomplete,
                                 'inline_ignores_enabled': report.inline_ignores_enabled,
                                 'coverage': report.to_dict()['coverage'], 'coverage_warnings': report.warnings, 'demo': report.demo}}],
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + '\n'


def _finding_card(item: Finding, language: str) -> str:
    tr = lambda key: _tr(language, key)
    kind = tr('dependency_kind') if item.category == 'dependency' else tr('info_kind') if item.category == 'information' else tr('secret_kind')
    severity = item.severity if item.severity in {'high', 'medium', 'low', 'critical', 'unknown', 'info'} else 'unknown'
    title, detail, action = _finding_text(item, language)
    reference = ''
    if re.fullmatch(r'https://osv\.dev/vulnerability/[A-Za-z0-9._:-]+', item.reference):
        reference = f'<a class="finding-link" href="{_escape(item.reference)}" target="_blank" rel="noopener noreferrer">{_escape(tr("view_advisory"))}</a>'
    return (f'<article class="finding-card"><div class="finding-main"><div class="finding-head">'
            f'<span class="severity {severity}">{_escape(_severity(item, language))}</span>'
            f'<span class="finding-kind">{_escape(kind)} · {_escape(item.rule_id)} · {_escape(_origin_label(item.origin, language))}</span></div>'
            f'<h3>{_escape(title)}</h3><p>{_escape(detail)}</p><div class="location">⌁ {_escape(item.path)}'
            f'<span class="line">:{item.line}:{item.column}</span></div></div>'
            f'<div class="finding-action"><span class="action-label">{_escape(tr("action").upper())}</span>'
            f'<p>{_escape(action)}</p>{reference}</div></article>')


def _details(title: str, count: int, body: str) -> str:
    return f'<details class="detail"><summary>{_escape(title)} <span>{count}</span></summary>{body}</details>'


def _inventory_html(report: ScanReport, language: str) -> str:
    tr = lambda key: _tr(language, key)
    skips = ''.join(f'<li><code>{_escape(item.path)}</code><small>{_escape(_reason(item.reason, language))} · {_escape(tr(item.kind))}</small></li>'
                    for item in report.skipped_details)
    files = ''.join(f'<li><code>{_escape(item.path)}</code><small>{_escape(item.encoding)} · {item.bytes_scanned} {_escape(tr("bytes"))} · '
                    f'{_escape(_origin_label(item.origin, language))}{(" · " + _escape(tr("partial"))) if item.partial else ""}</small></li>'
                    for item in report.scanned_files)
    deps = ''.join(f'<li><code>{_escape(dep.name)}@{_escape(dep.version)}</code><small>{_escape(dep.ecosystem)} · {_escape(dep.path)}:{dep.line}</small></li>'
                   for dep in report.dependencies)
    def container(body: str, omitted: int = 0) -> str:
        if not body:
            body = f'<li>{_escape(tr("no_details"))}</li>'
        note = f'<p class="omitted">{omitted} {_escape(tr("details_omitted"))}.</p>' if omitted else ''
        return f'<ul class="path-list">{body}</ul>{note}'
    return (_details(tr('skipped_list'), len(report.skipped_details), container(skips, report.skipped_details_omitted))
            + _details(tr('scanned_list'), len(report.scanned_files), container(files, report.scanned_file_details_omitted))
            + _details(tr('deps_list'), len(report.dependencies), container(deps)))


def html_report(report: ScanReport, language: str = 'en') -> str:
    tr = lambda key: _tr(language, key)
    counts = report.to_dict()['summary']
    primary = [item for item in report.findings if item.origin != 'third_party']
    vendor = [item for item in report.findings if item.origin == 'third_party']
    cards = ''.join(_finding_card(item, language) for item in primary)
    if not cards:
        cards = f'<div class="empty-state"><span>✓</span><h3>{_escape(tr("no_findings"))}</h3></div>' if not vendor else ''
    vendor_cards = ''.join(_finding_card(item, language) for item in vendor)
    if vendor_cards:
        cards += _details(tr('vendor_findings'), len(vendor), f'<p class="detail-intro">{_escape(tr("vendor_note"))}</p><div class="findings">{vendor_cards}</div>')
    info_primary = ''.join(_finding_card(item, language) for item in report.observations if item.origin != 'third_party')
    info_vendor = [item for item in report.observations if item.origin == 'third_party']
    if info_vendor:
        info_primary += _details(tr('origin_third_party'), len(info_vendor), '<div class="findings">' + ''.join(_finding_card(item, language) for item in info_vendor) + '</div>')
    if not info_primary:
        info_primary = f'<div class="empty-state"><p>{_escape(tr("no_info"))}</p></div>'
    warnings = ''.join(f'<li>{_escape(_warning(message, language))}</li>' for message in report.warnings) or f'<li>{_escape(tr("no_warnings"))}</li>'
    reasons = ''.join(f'<li>{_escape(_reason(reason, language))}: <strong>{count}</strong></li>' for reason, count in report.skipped_by_reason.items()) or f'<li>{_escape(tr("none"))}</li>'
    encodings = ', '.join(f'{key}: {value}' for key, value in report.encoding_counts.items()) or tr('none')
    demo = f'<div class="demo-banner">{_escape(tr("demo"))} <span>— {_escape(tr("demo_note"))}</span></div>' if report.demo else ''
    scope = tr('scope_deep' if report.scope == 'deep' else 'scope_standard')
    status = tr('incomplete') if report.scan_incomplete else tr('within_scope')
    limits = (f"{report.limits['file_bytes']} {tr('bytes')} {tr('file_limit')} · {report.limits['file_entries']} {tr('entry_limit')} · {report.limits['total_bytes']} {tr('total_limit')}"
              if report.limits else tr('none'))
    inventory = _inventory_html(report, language)
    return f'''<!doctype html>
<html lang="{_escape(language)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark"><title>{_escape(tr('report_title'))} — {_escape(report.project)}</title><style>
:root{{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e4ece9;background:#0a1211;font-synthesis:none}}*{{box-sizing:border-box}}body{{margin:0;font-size:14px}}a{{color:#91e4b5}}a:focus-visible,summary:focus-visible{{outline:3px solid #7bdeb0;outline-offset:3px}}.shell{{max-width:1280px;margin:auto;padding:0 32px}}.top{{border-bottom:1px solid #26332f;background:#0d1715}}.top-inner{{height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}}.brand{{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.04em;font-size:18px}}.mark{{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;color:#10201b;background:#9ae1ae;font-size:18px}}.brand small{{color:#719083;font-size:10px;letter-spacing:.12em;font-weight:700;margin-left:6px}}.local{{font-size:10px;letter-spacing:.09em;color:#8fc7a3;border:1px solid #325540;border-radius:20px;padding:6px 10px;white-space:nowrap}}.hero{{display:flex;justify-content:space-between;gap:25px;align-items:end;padding:48px 0 30px}}.eyebrow{{color:#83bd99;letter-spacing:.14em;font-size:10px;font-weight:800;margin:0 0 12px}}h1{{font-size:clamp(32px,4vw,45px);letter-spacing:-.055em;line-height:1.08;margin:0 0 12px}}.muted{{color:#9ab1a5;margin:0;line-height:1.6}}.meta{{color:#819c8e;font-size:11px;text-align:right;white-space:nowrap}}.demo-banner{{background:#4c3d1b;color:#eed896;border:1px solid #6e5a25;border-radius:10px;padding:11px 14px;margin:0 0 18px;font-weight:800;font-size:11px;letter-spacing:.05em}}.demo-banner span{{font-weight:500;letter-spacing:0}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.stat{{background:#101d19;border:1px solid #263b31;border-radius:13px;padding:19px 20px;min-width:0}}.stat-label{{font-size:10px;color:#9ab3a5;letter-spacing:.08em;font-weight:750;text-transform:uppercase}}.stat-value{{font-size:29px;font-weight:800;letter-spacing:-.05em;margin:8px 0 2px;color:#e8f2eb}}.stat-value.accent{{color:#9fe5b3}}.stat-help{{color:#8ea99b;font-size:11px;line-height:1.4}}.layout{{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:20px;margin-top:34px}}.section-heading{{display:flex;align-items:end;justify-content:space-between;margin:0 0 15px;gap:10px}}.section-heading h2,.coverage h2{{font-size:19px;letter-spacing:-.03em;margin:0}}.section-heading span{{font-size:11px;color:#91a99b}}.section-intro{{color:#a2b9ab;font-size:12px;line-height:1.6;margin:0 0 15px}}.info-section{{margin-top:38px}}.findings{{display:grid;gap:10px}}.finding-card{{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(190px,.9fr);background:#101c18;border:1px solid #243a2e;border-radius:12px;overflow:hidden}}.finding-main,.finding-action{{padding:19px 20px;min-width:0}}.finding-action{{border-left:1px solid #273a2f;background:#111f1a}}.finding-head{{display:flex;gap:9px;align-items:center;flex-wrap:wrap}}.severity{{font-size:9px;letter-spacing:.07em;font-weight:850;border-radius:5px;padding:4px 7px}}.severity.high,.severity.critical{{color:#ffb3a6;background:#59312c}}.severity.medium{{color:#eccc7d;background:#4f4226}}.severity.unknown{{color:#b5c6df;background:#273c52}}.severity.low,.severity.info{{color:#9acead;background:#274632}}.finding-kind{{color:#91ac9b;font-size:9px;font-weight:800;letter-spacing:.08em}}.finding-card h3{{font-size:14px;letter-spacing:-.01em;margin:12px 0 6px}}.finding-card p{{color:#a1b7aa;font-size:12px;line-height:1.55;margin:0}}.location{{display:flex;gap:4px;margin-top:12px;background:#1a2b23;color:#bdd1c4;border-radius:6px;padding:5px 8px;font:11px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;word-break:break-word}}.line{{color:#75bf8d;white-space:nowrap}}.action-label{{display:block;color:#91aa99;font-size:9px;letter-spacing:.09em;font-weight:800;margin-bottom:10px}}.finding-link{{display:inline-block;margin-top:12px;font-size:11px;font-weight:700;text-decoration:none}}.coverage{{background:#101c18;border:1px solid #243a2e;border-radius:12px;padding:20px;align-self:start;min-width:0}}.coverage h2{{font-size:15px}}.coverage-row{{padding:15px 0;border-bottom:1px solid #26392e}}.coverage-row strong{{display:block;color:#b7d2be;font-size:11px;margin-bottom:4px}}.coverage-row span,.coverage-row p{{color:#9bb2a3;font-size:11px;line-height:1.6;overflow-wrap:anywhere}}.coverage ul{{padding-left:17px;color:#a1b6a8;font-size:11px;line-height:1.6}}.privacy{{margin-top:17px;padding:12px;border:1px solid #34543f;border-radius:8px;color:#b9d4be;background:#17291e;font-size:11px;line-height:1.5}}.detail{{margin-top:10px;border:1px solid #2d4535;border-radius:9px;background:#12211a;min-width:0}}.detail>summary{{cursor:pointer;padding:12px 13px;color:#d1e4d7;font-size:11px;font-weight:750;overflow-wrap:anywhere}}.detail>summary span{{color:#9fceb0;margin-left:5px}}.detail[open]{{padding-bottom:10px}}.detail .findings{{padding:0 10px}}.detail-intro{{color:#a1b7aa;font-size:11px;line-height:1.5;margin:0;padding:0 13px 12px}}.path-list{{max-height:360px;overflow:auto;padding:0 12px 0 28px!important;margin:0;color:#a4baa9!important}}.path-list li{{padding:6px 0;border-top:1px solid #263b2e;overflow-wrap:anywhere}}.path-list code{{font:10px ui-monospace,SFMono-Regular,Consolas,monospace;color:#d0e4d4;overflow-wrap:anywhere;word-break:break-word}}.path-list small{{display:block;color:#8ca897;font-size:10px;margin-top:3px}}.omitted{{padding:0 12px;color:#eccc7d;font-size:11px}}.empty-state{{background:#101c18;border:1px solid #243a2e;border-radius:12px;padding:28px;text-align:center;color:#a1b7aa}}.empty-state span{{color:#9ce5b0;font-size:24px}}.empty-state h3{{color:#d8e9df;font-size:13px}}.empty-state p{{font-size:12px}}footer{{margin-top:55px;padding:25px 0 35px;border-top:1px solid #263a2e;color:#91aa99;font-size:11px;display:flex;justify-content:space-between;gap:20px}}@media(max-width:900px){{.stats{{grid-template-columns:repeat(2,1fr)}}.layout{{grid-template-columns:1fr}}.coverage{{order:-1}}.hero{{align-items:start;flex-direction:column}}.meta{{text-align:left}}}}@media(max-width:520px){{.shell{{padding:0 16px}}.top-inner{{height:62px}}.brand small{{display:none}}.hero{{padding-top:32px}}.stat{{padding:15px}}.stat-value{{font-size:25px}}.finding-card{{grid-template-columns:1fr}}.finding-action{{border-left:0;border-top:1px solid #273a2f}}footer{{flex-direction:column}}}}
</style></head><body><header class="top"><div class="shell top-inner"><div class="brand"><span class="mark" aria-hidden="true">✳</span>repoguard<small>{_escape(tr('report_title').upper())}</small></div><span class="local">{_escape(tr('local'))}</span></div></header><main class="shell"><section class="hero"><div><p class="eyebrow">{_escape(tr('hero_eyebrow'))}</p><h1>{_escape(tr('hero_title'))}</h1><p class="muted">{_escape(tr('hero_subtitle'))} <strong>{_escape(report.project)}</strong>.<br>{_escape(tr('privacy'))}</p></div><div class="meta">{_escape(tr('generated_at'))}<br>{_escape(report.created_at)}</div></section>{demo}<section class="stats" aria-label="{_escape(tr('scope'))}"><div class="stat"><div class="stat-label">{_escape(tr('secrets'))}</div><div class="stat-value">{counts['possible_secrets']:02d}</div><div class="stat-help">{_escape(tr('secrets_help'))} · {counts['third_party_secrets']} {_escape(tr('in_vendor'))}</div></div><div class="stat"><div class="stat-label">{_escape(tr('advisories'))}</div><div class="stat-value">{counts['advisories']:02d}</div><div class="stat-help">{_escape(tr('osv_partial_short') if report.osv_status == 'partial' else tr('osv_help'))}</div></div><div class="stat"><div class="stat-label">{_escape(tr('information'))}</div><div class="stat-value accent">{counts['public_information']:02d}</div><div class="stat-help">{_escape(tr('info_help'))}</div></div><div class="stat"><div class="stat-label">{_escape(tr('scanned'))}</div><div class="stat-value">{counts['files_scanned']:02d}</div><div class="stat-help">{counts['skipped_items']} {_escape(tr('skipped').lower())}</div></div></section><div class="layout"><div><section><div class="section-heading"><h2>{_escape(tr('findings'))}</h2><span>{len(report.findings)} · {_escape(tr('review_required'))}</span></div><div class="findings">{cards}</div></section><section class="info-section"><div class="section-heading"><h2>{_escape(tr('information'))}</h2><span>{len(report.observations)}</span></div><p class="section-intro">{_escape(tr('info_intro'))}</p><div class="findings">{info_primary}</div></section></div><aside class="coverage"><h2>{_escape(tr('coverage'))}</h2><div class="coverage-row"><strong>{_escape(tr('file_status'))}</strong><span>{_escape(status)}<br>{_escape(tr('scope'))} : {_escape(scope)}<br>{counts['files_partially_scanned']} {_escape(tr('partial_files'))}</span></div><div class="coverage-row"><strong>{_escape(tr('osv'))}</strong><span>{_escape(_osv_label(report, language))}</span></div><div class="coverage-row"><strong>{_escape(tr('dependencies'))}</strong><span>{counts['dependencies']} · {counts['unique_dependencies']} {_escape(tr('unique'))}<br>{_escape(tr('inventory_incomplete') if report.inventory_incomplete else tr('dep_help'))}</span></div><div class="coverage-row"><strong>{_escape(tr('limits'))}</strong><span>{_escape(limits)}</span></div><div class="coverage-row"><strong>{_escape(tr('formats'))}</strong><span>{_escape(encodings)}</span></div><div class="coverage-row"><strong>{_escape(tr('skip_by_reason'))}</strong><ul>{reasons}</ul><p>{_escape(tr('coverage_explain'))}</p><p>{_escape(tr('lock_explain'))}</p></div><div class="coverage-row"><strong>{_escape(tr('warnings'))}</strong><ul>{warnings}</ul></div>{inventory}<div class="privacy">◈ &nbsp;{_escape(tr('caution'))}<br><br>{_escape(tr('privacy'))}</div></aside></div><footer><span><strong>repoguard.</strong> {_escape(tr('read_time'))}</span><span>Open source · v{_escape(__version__)}</span></footer></main></body></html>'''
