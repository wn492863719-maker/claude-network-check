#!/usr/bin/env python3
"""Export the allowlisted public text files as complete replaceable code blocks."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def export_sources():
    files = json.loads((ROOT / 'scripts/release_files.json').read_text())
    parts = ['# 完整文件内容\n\nClaude Network Check 2.2.1 的全部公开文本文件。按文件标题复制完整代码块；图像文件随源码包提供。\n']
    languages = {'.py': 'python', '.swift': 'swift', '.html': 'html', '.md': 'markdown',
                 '.command': 'zsh', '.json': 'json', '.yml': 'yaml'}
    for name in files:
        if name.endswith('.png') or name == 'docs/完整文件内容.md':
            continue
        path = ROOT / name
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Source path outside public repository')
        parts.append('\n## ' + name + '\n\n````' + languages.get(path.suffix, 'text') + '\n' + path.read_text().rstrip('\n') + '\n````\n')
    destination = ROOT / 'docs/完整文件内容.md'
    destination.write_text(''.join(parts))
    return destination


if __name__ == '__main__':
    print(export_sources().relative_to(ROOT))
