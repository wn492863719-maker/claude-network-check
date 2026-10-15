#!/usr/bin/env python3
"""Package allowlisted public source and a verified macOS app; never include state."""
import argparse
import hashlib
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import zipfile
from check_release import ROOT, check
from export_sources import export_sources

VERSION = '2.2.1'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'release')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('Application packaging requires macOS')
    export_sources()
    files = check()
    app = ROOT / 'dist/Claude Network Check.app'
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    machine = platform.machine()
    subprocess.run(['lipo', str(app / 'Contents/MacOS/NetworkEnvironmentCheck'), '-verify_arch', machine], check=True)
    out = args.output.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    source_zip = out / ('claude-network-check-v' + VERSION + '-source.zip')
    with zipfile.ZipFile(source_zip, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(ROOT / name, 'claude-network-check/' + name)
    source_name = 'Claude-Network-Check-v' + VERSION + '-macos-' + machine
    app_zip = out / (source_name + '.zip')
    with tempfile.TemporaryDirectory(prefix='claude-network-release-') as temporary:
        stage = Path(temporary) / source_name
        stage.mkdir()
        shutil.copytree(app, stage / app.name, symlinks=True)
        shutil.copy2(ROOT / 'LICENSE', stage / 'LICENSE')
        shutil.copy2(ROOT / 'docs/APP_INSTALL.md', stage / '安装说明.md')
        subprocess.run(['/usr/bin/ditto', '-c', '-k', '--keepParent', '--norsrc', str(stage), str(app_zip)], check=True)
    checksum = out / 'SHA256SUMS.txt'
    checksum.write_text(''.join(hashlib.sha256(file.read_bytes()).hexdigest() + '  ' + file.name + '\n' for file in [source_zip, app_zip]))
    shutil.copy2(ROOT / 'docs/RELEASE_NOTES.md', out / 'RELEASE_NOTES.md')
    shutil.copy2(ROOT / 'docs/GITHUB_PUBLISH.md', out / 'GITHUB_PUBLISH.md')
    print('Release output: ' + str(out))
    for file in [source_zip, app_zip, checksum]:
        print('{}: {} bytes'.format(file.name, file.stat().st_size))


if __name__ == '__main__':
    main()
