#!/usr/bin/env python3
"""Validate the explicit public file list and local documentation links, offline."""
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def public_files():
    files = json.loads((ROOT / 'scripts/release_files.json').read_text())
    if not isinstance(files, list) or len(set(files)) != len(files):
        raise ValueError('Public file list must contain unique relative paths')
    for name in files:
        path = ROOT / name
        if not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Invalid public file path')
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Missing file, symlink or path outside repository: ' + name)
    return files


def check():
    errors = []
    files = public_files()
    for name in files:
        path = ROOT / name
        if path.suffix == '.png':
            if not path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'):
                errors.append('Invalid PNG: ' + name)
            continue
        text = path.read_text()
        if re.search(r'/Users/[A-Za-z0-9_\-]+/', text):
            errors.append('Personal absolute home path: ' + name)
        if re.search(r'\b(?:sk-|github_pat_|ghp_)[A-Za-z0-9_\-]{20,}', text):
            errors.append('Credential-like string: ' + name)
        if name.endswith('.md'):
            visible = re.sub(r'(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$', '', text)
            for target in re.findall(r'!?\[[^\]]*\]\(([^\s)]+)\)', visible):
                if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                    continue
                target = unquote(target.split('#', 1)[0])
                if target and not (path.parent / target).exists():
                    errors.append('Broken relative link: ' + name + ' -> ' + target)
    forbidden = {'privacy-audit.json', 'egress-history.json', '.DS_Store', '.env'}
    if any(Path(name).name in forbidden or '.learnings' in Path(name).parts for name in files):
        errors.append('Private runtime or local learning data included')
    for script in ['build_app.command', '启动工具.command']:
        if not (ROOT / script).stat().st_mode & 0o111:
            errors.append('Missing executable permission: ' + script)
    if errors:
        raise ValueError('\n'.join(errors))
    print('PASS: {} public files, documentation links, image headers, private-path and credential-pattern checks'.format(len(files)))
    return files


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError, TypeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
