"""Fetch pinned official Mihomo build resources without installing or touching Clash."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
from urllib.request import Request, urlopen
import zipfile


ROOT = Path(__file__).resolve().parent
MAXIMUM_DOWNLOAD = 100_000_000


def fetch(url):
    request = Request(url, headers={'User-Agent': 'CFAIManager-resource-preparation/0.1.0'})
    with urlopen(request, timeout=90) as response:
        data = response.read(MAXIMUM_DOWNLOAD + 1)
    if len(data) > MAXIMUM_DOWNLOAD:
        raise ValueError('Resource exceeds download limit')
    return data


def save_atomic(path, data):
    import os
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    resources = ROOT / 'resources'
    manifest = json.loads((resources / 'core.json').read_text(encoding='utf-8-sig'))
    version, asset = manifest['version'], manifest['asset']
    binary = resources / 'mihomo.exe'
    if binary.exists() and hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['sha256']:
        print('Pinned Mihomo executable already verified.')
    else:
        archive = fetch(f'https://github.com/MetaCubeX/mihomo/releases/download/{version}/{asset}')
        if hashlib.sha256(archive).hexdigest() != manifest['archive_sha256']:
            raise ValueError('Official release archive checksum mismatch; existing resources preserved')
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            names = [n for n in package.namelist() if Path(n).name == 'mihomo-windows-amd64-v1.exe']
            if len(names) != 1:
                raise ValueError('Unexpected release archive contents')
            data = package.read(names[0])
        if hashlib.sha256(data).hexdigest() != manifest['sha256']:
            raise ValueError('Mihomo executable checksum mismatch')
        save_atomic(binary, data)
        print('Pinned Mihomo executable downloaded and verified.')
    source = resources / f'mihomo-{version}-source.tar.gz'
    expected_source = manifest['source_archive_sha256']
    if not source.exists() or hashlib.sha256(source.read_bytes()).hexdigest() != expected_source:
        data = fetch(f'https://codeload.github.com/MetaCubeX/mihomo/tar.gz/refs/tags/{version}')
        if hashlib.sha256(data).hexdigest() != expected_source:
            raise ValueError('Corresponding source checksum mismatch')
        save_atomic(source, data)
    print('Corresponding source archive verified. Resources ready; nothing installed.')


if __name__ == '__main__':
    main()
