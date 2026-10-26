# Third-party notices

## Application

CF AI Manager source files in this directory: MIT License; see LICENSE.txt. The existing local Nova/Angeles manager supplied the physical-interface binding approach. No live node credentials or original deployment paths are included in the release.

The independent project ClashCloudflareDynamic v1.5.2 was studied for multi-round interleaving, request-wall-clock throughput, historical candidate allocation and download reporting. Its implementation is MIT licensed, copyright 2026 ClashCloudflareDynamic contributors: https://github.com/YanYunCY/ClashCloudflareDynamic . This application implements its own UI and independent-core pipeline. Its license is preserved under resources/licenses/ClashCloudflareDynamic.txt.

## Mihomo

MetaCubeX/mihomo v1.19.32, GPL-3.0. Runs as a separate executable communicating over local REST/HTTP, not as a linked library. Upstream release and exact asset are recorded in resources/core.json.

- Source: https://github.com/MetaCubeX/mihomo/tree/v1.19.32
- Corresponding source archive included in the portable release: third_party/mihomo-v1.19.32-source.tar.gz
- License: resources/MIHOMO-LICENSE.txt
- Build instructions and Go module dependencies are in that source archive. Users may replace the executable and update core.json's checksum when testing modified builds.

## Qt / PySide6 / Shiboken6

Qt for Python 6.8.3 uses dynamically loaded Qt libraries, available under LGPL-3.0 and the component licenses distributed by The Qt Company. Users may replace compatible Qt/PySide6 libraries in _internal. License texts from installed distribution metadata are included in third_party/licenses. Matching source: https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.8.3-src/ and https://download.qt.io/archive/qt/6.8/6.8.3/single/ . No Qt WebEngine is used.

## Python / PyYAML / PyInstaller

Python: PSF license, https://www.python.org/ . PyYAML 6.0.3: MIT, https://github.com/yaml/pyyaml . PyInstaller 6.16.0 bootloader: GPL with its distribution exception, https://pyinstaller.org/ . Distribution license texts accompany the portable release.

## Noto Sans CJK

Noto Sans CJK SC Regular, SIL Open Font License 1.1; copyright and full terms in resources/fonts/OFL.txt. Source: https://github.com/notofonts/noto-cjk . Font hash is in resources/fonts/font.json. No proprietary Windows fonts are redistributed.
