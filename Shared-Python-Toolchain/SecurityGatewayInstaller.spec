# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

project_root = Path.cwd()
payload_env = os.environ.get("SECURITY_GATEWAY_PAYLOAD_PATH")
if not payload_env:
    raise SystemExit("SECURITY_GATEWAY_PAYLOAD_PATH is required. Use scripts/build-security-gateway.ps1.")
payload_path = Path(payload_env)
if not payload_path.exists():
    raise SystemExit(f"Security Gateway payload missing: {payload_path}")
uninstaller_env = os.environ.get("SECURITY_GATEWAY_UNINSTALLER_PATH")
if not uninstaller_env:
    raise SystemExit("SECURITY_GATEWAY_UNINSTALLER_PATH is required. Use scripts/build-security-gateway.ps1.")
uninstaller_path = Path(uninstaller_env)
if not uninstaller_path.exists():
    raise SystemExit(f"Security Gateway uninstaller missing: {uninstaller_path}")

a = Analysis(
    ['installer\\installer.py'],
    pathex=[],
    binaries=[],
    datas=[
        (str(payload_path), 'payload'),
        (str(uninstaller_path), 'payload'),
        ('docs/INSTALL_GUIDE.pdf', 'docs'),
        ('installer/dependencies.json', 'installer'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SecurityGatewayInstaller',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='spec\\SecurityGatewayInstaller.version.txt',
)
