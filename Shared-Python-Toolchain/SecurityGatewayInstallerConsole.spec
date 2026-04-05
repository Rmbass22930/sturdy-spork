# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path


def resolve_bundle_root(env_name: str, exe_name: str) -> Path:
    value = os.environ.get(env_name)
    if not value:
        raise SystemExit(f"{env_name} is required. Use scripts/build-security-gateway.ps1.")
    candidate = Path(value)
    if candidate.is_dir():
        bundle_root = candidate
    else:
        bundle_root = candidate.parent
    exe_path = bundle_root / exe_name
    if not exe_path.exists():
        raise SystemExit(f"{exe_name} missing from bundle root: {bundle_root}")
    return bundle_root


payload_root = resolve_bundle_root("SECURITY_GATEWAY_PAYLOAD_PATH", "SecurityGateway.exe")
uninstaller_root = resolve_bundle_root("SECURITY_GATEWAY_UNINSTALLER_PATH", "SecurityGateway-Uninstall.exe")

a = Analysis(
    ['installer\\installer.py'],
    pathex=[],
    binaries=[],
    datas=[
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
    [],
    [],
    [],
    name='SecurityGatewayInstallerConsole',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    exclude_binaries=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    uac_admin=False,
    runtime_tmpdir=os.environ.get("SECURITY_GATEWAY_RUNTIME_TMPDIR"),
    codesign_identity=None,
    entitlements_file=None,
    version='spec\\SecurityGatewayInstaller.version.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    Tree(str(payload_root), prefix='payload/SecurityGateway'),
    Tree(str(uninstaller_root), prefix='payload/SecurityGateway-Uninstall'),
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SecurityGatewayInstallerConsole',
)
