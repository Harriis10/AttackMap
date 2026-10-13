# PyInstaller spec for the AttackMap Windows GUI + CLI (onedir, fast build).
from pathlib import Path

ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "installer" / "entry.py")],
    pathex=[str(ROOT / "src")],
    optimize=0,
    module_collection_mode=None,
    binaries=[],
    datas=[
        (str(ROOT / "src" / "attackmap" / "ui" / "web"), "attackmap/ui/web"),
        (str(ROOT / "src" / "attackmap" / "ui" / "fixtures"), "attackmap/ui/fixtures"),
        (str(ROOT / "src" / "attackmap" / "taint_sinks.yaml"), "attackmap"),
        (str(ROOT / "src" / "attackmap" / "taint_sinks.yaml"), "."),
    ],
    hiddenimports=[
        "attackmap.cli",
        "attackmap.analyzers",
        "attackmap.ui",
        "attackmap.ui.launch",
        "attackmap.ui.server",
        "attackmap.ui.runner",
        "attackmap.ui.config",
        "attackmap.ui.report",
        "attackmap.ui.output",
        "attackmap.ui.secrets",
        "attackmap.ui.watch",
        "attackmap.ui.suppress_write",
        "typer",
        "pydantic",
        "networkx",
        "yaml",
        "webview",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "pytest",
        "IPython",
        "notebook",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="attackmap",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="attackmap",
)
