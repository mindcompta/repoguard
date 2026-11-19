"""Extract exact versions from selected dependency files; no code is executed."""
import json
import re
from pathlib import PurePosixPath

from .models import Dependency

MAX_DEPENDENCIES_PER_FILE = 5000
_NAME_NPM = re.compile(r'^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]{0,212}$')
_NAME_PYPI = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_VERSION = re.compile(r'^[0-9][A-Za-z0-9.!+_-]{0,127}$')
_REQUIREMENT = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([0-9][A-Za-z0-9.!+_-]{0,127})\s*(?:;[^#]*)?(?:\s*#.*)?$')


def is_installed_npm_manifest(path: str) -> bool:
    """Recognize an installed package root, not arbitrary fixture package.json files."""
    parts = PurePosixPath(path).parts
    lower = [part.lower() for part in parts]
    if not parts or lower[-1] != 'package.json' or 'node_modules' not in lower:
        return False
    index = len(lower) - 1 - lower[::-1].index('node_modules')
    name_parts = parts[index + 1:-1]
    return len(name_parts) == 1 or (len(name_parts) == 2 and name_parts[0].startswith('@'))


def is_dependency_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower() if parts else ''
    hidden_lock = name == '.package-lock.json' and len(parts) > 1 and parts[-2].lower() == 'node_modules'
    return (name in {'package-lock.json', 'npm-shrinkwrap.json'} or hidden_lock
            or is_installed_npm_manifest(path)
            or (name.endswith('.txt') and (name.startswith('requirements') or any(part.lower() == 'requirements' for part in parts[:-1]))))


def _dependency(ecosystem: str, name: object, version: object, path: str, line: int) -> Dependency | None:
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if ecosystem == 'PyPI':
        if not _NAME_PYPI.fullmatch(name):
            return None
        # PEP 503 normalization prevents mismatches between equivalent PyPI names.
        name = re.sub(r'[-_.]+', '-', name).lower()
    elif ecosystem == 'npm':
        if not _NAME_NPM.fullmatch(name):
            return None
        name = name.lower()
    else:
        return None
    if not _VERSION.fullmatch(version):
        return None
    return Dependency(ecosystem=ecosystem, name=name, version=version, path=path, line=line)


def _requirements(path: str, text: str) -> tuple[list[Dependency], list[str]]:
    dependencies: list[Dependency] = []
    skipped = 0
    for line_number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        match = _REQUIREMENT.fullmatch(stripped)
        if not match:
            skipped += 1
            continue
        dep = _dependency('PyPI', match.group(1), match.group(2), path, line_number)
        if dep:
            dependencies.append(dep)
        else:
            skipped += 1
        if len(dependencies) >= MAX_DEPENDENCIES_PER_FILE:
            return dependencies, [f'{path}: dependency inventory reached the {MAX_DEPENDENCIES_PER_FILE} item limit.']
    warnings = [f'{path}: {skipped} non-exact or unsupported requirement(s) were not inventoried.'] if skipped else []
    return dependencies, warnings


def _npm_lock(path: str, text: str) -> tuple[list[Dependency], list[str]]:
    try:
        lock = json.loads(text)
    except (ValueError, RecursionError):
        return [], [f'{path}: package-lock.json could not be parsed.']
    if not isinstance(lock, dict):
        return [], [f'{path}: package-lock.json is not an object.']
    version = lock.get('lockfileVersion')
    if version not in (1, 2, 3):
        return [], [f'{path}: unsupported or missing npm lockfileVersion.']
    dependencies: list[Dependency] = []
    omitted = 0
    truncated = False
    packages = lock.get('packages')
    if version in (2, 3) and not isinstance(packages, dict):
        return [], [f'{path}: package-lock.json is missing its packages inventory.']
    if isinstance(packages, dict):
        for location, entry in packages.items():
            if len(dependencies) >= MAX_DEPENDENCIES_PER_FILE:
                truncated = True
                break
            if not isinstance(location, str) or not isinstance(entry, dict):
                omitted += 1
                continue
            if not location:
                continue  # Root project, not a third-party dependency.
            if 'node_modules/' not in location:
                continue
            if entry.get('link'):
                omitted += 1  # Workspace/link versions cannot be inferred safely.
                continue
            derived = location.rsplit('node_modules/', 1)[-1]
            name = entry.get('name') or derived
            dep = _dependency('npm', name, entry.get('version'), path, 1)
            if dep:
                dependencies.append(dep)
            else:
                omitted += 1
    else:
        if not isinstance(lock.get('dependencies', {}), dict):
            return [], [f'{path}: npm v1 dependency inventory is not an object.']
        # npm lockfile v1 nests dependencies. Bound depth and count on untrusted files.
        def visit(tree: object, depth: int) -> None:
            nonlocal omitted, truncated
            if not isinstance(tree, dict):
                return
            if depth > 30:
                truncated = True
                return
            for name, entry in tree.items():
                if len(dependencies) >= MAX_DEPENDENCIES_PER_FILE:
                    truncated = True
                    return
                if not isinstance(entry, dict):
                    omitted += 1
                    continue
                dep = _dependency('npm', name, entry.get('version'), path, 1)
                if dep:
                    dependencies.append(dep)
                else:
                    omitted += 1
                visit(entry.get('dependencies'), depth + 1)
        visit(lock.get('dependencies'), 0)
    warnings = []
    if omitted:
        warnings.append(f'{path}: {omitted} dependency entry/entries had unsupported names or versions.')
    if truncated:
        warnings.append(f'{path}: dependency inventory was truncated.')
    return dependencies, warnings


def _installed_npm_manifest(path: str, text: str) -> tuple[list[Dependency], list[str]]:
    try:
        manifest = json.loads(text)
    except (ValueError, RecursionError):
        return [], [f'{path}: installed npm package manifest could not be parsed.']
    dep = (_dependency('npm', manifest.get('name'), manifest.get('version'), path, 1)
           if isinstance(manifest, dict) else None)
    if dep is None:
        return [], [f'{path}: installed npm package has no supported exact name and version.']
    return [dep], []


def extract_dependencies(path: str, text: str) -> tuple[list[Dependency], list[str]]:
    name = PurePosixPath(path).name.lower()
    if name in {'package-lock.json', 'npm-shrinkwrap.json', '.package-lock.json'} and is_dependency_file(path):
        return _npm_lock(path, text)
    if is_installed_npm_manifest(path):
        return _installed_npm_manifest(path, text)
    if is_dependency_file(path):
        return _requirements(path, text)
    return [], []
