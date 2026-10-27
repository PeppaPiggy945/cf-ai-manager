"""Build an explicit-whitelist portable release. Never packages user profiles or results."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'dist',
                        help='Separate release directory; preserves a running portable build')
    args = parser.parse_args()
    destination = args.output_dir.resolve()
    work = ROOT/'build' if destination == (ROOT/'dist').resolve() else destination/'_build'
    sys.path.insert(0,str(ROOT))
    from cfai.scanner import core_path
    from cfai import __version__
    from cfai.routing import china_snapshot
    core_path()
    china_snapshot()
    resources=ROOT/'resources'
    required=['MIHOMO-LICENSE.txt','fonts/OFL.txt','licenses/ClashCloudflareDynamic.txt','mihomo-v1.19.32-source.tar.gz']
    for name in required:
        if not (resources/name).is_file():
            raise RuntimeError('Missing distribution notice/source: '+name)
    subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--windowed','--onedir',
        '--name','CFAIManager','--icon',str(resources/'icon.ico'),'--distpath',str(destination),'--workpath',str(work),
        '--specpath',str(work),'--add-data',f'{resources};resources',
        '--exclude-module','PySide6.QtWebEngineCore','--exclude-module','PySide6.QtWebEngineWidgets',
        '--exclude-module','PySide6.QtQml','--exclude-module','PySide6.QtQuick',
        '--exclude-module','numpy','--exclude-module','pandas',str(ROOT/'app.py')],cwd=ROOT,check=True)
    package=destination/'CFAIManager'
    for name in ['README.md','THIRD_PARTY_NOTICES.md','LICENSE.txt']:
        shutil.copy2(ROOT/name,package/name)
    third=package/'third_party'
    third.mkdir(exist_ok=True)
    shutil.copy2(resources/'mihomo-v1.19.32-source.tar.gz',third/'mihomo-v1.19.32-source.tar.gz')
    (package/'_internal'/'resources'/'mihomo-v1.19.32-source.tar.gz').unlink(missing_ok=True)
    license_root=third/'licenses'
    license_root.mkdir(exist_ok=True)
    for name in ['PySide6','PySide6_Essentials','PySide6_Addons','shiboken6','PyYAML','PyInstaller','pyinstaller-hooks-contrib','altgraph','packaging','pefile','pywin32-ctypes','setuptools']:
        dist=importlib.metadata.distribution(name)
        for file in dist.files or []:
            if any(part.lower().startswith(('license','copying','notice')) for part in file.parts):
                source=Path(dist.locate_file(file))
                if source.is_file():
                    target=license_root/name/Path(*file.parts[-3:])
                    target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copy2(source,target)
    python_license=Path(sys.base_prefix)/'LICENSE.txt'
    if python_license.exists():shutil.copy2(python_license,license_root/'PYTHON-LICENSE.txt')
    manifest={}
    for path in sorted(package.rglob('*')):
        if path.is_file():
            relative=path.relative_to(package).as_posix()
            if path.name in ('profiles.json','results.json','observations.json','settings.json'):
                raise RuntimeError('Runtime user data entered release')
            manifest[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
    (package/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    archive=destination/f'CFAIManager-{__version__}-windows-x64.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for path in sorted(package.rglob('*')):
            if path.is_file():z.write(path,Path('CFAIManager')/path.relative_to(package))
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(digest+'  '+archive.name+'\n',encoding='ascii')
    print('Release:',archive,'SHA256:',digest)


if __name__=='__main__':main()
