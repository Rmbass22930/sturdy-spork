import re
from pathlib import Path
from datetime import datetime

SRC_DIR = Path(r"G:\BallisticTarget\src")

MAIN = SRC_DIR / "BallisticTargetGUI.py"
GEO  = SRC_DIR / "EnvironmentalsGeoGUI.py"

def backup(p: Path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    b = p.with_suffix(p.suffix + f".bak_{ts}")
    b.write_text(p.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    return b

def ensure_imports(code: str, imports: list[str]) -> str:
    # Insert missing imports after last import/from line (best effort)
    lines = code.splitlines(True)
    existing = set()
    for ln in lines:
        m = re.match(r"^\s*(import|from)\s+([A-Za-z0-9_\.]+)", ln)
        if m:
            existing.add(ln.strip())

    missing = [imp for imp in imports if not re.search(rf"(?m)^\s*{re.escape(imp)}\s*$", code)]
    if not missing:
        return code

    # find insertion point after last import/from
    last_idx = -1
    for i, ln in enumerate(lines):
        if re.match(r"^\s*(import|from)\s+.+", ln):
            last_idx = i
    if last_idx >= 0:
        insert_at = last_idx + 1
        lines.insert(insert_at, "".join([m + "\n" for m in missing]) + "\n")
        return "".join(lines)
    else:
        return "".join([m + "\n" for m in missing]) + "\n\n" + code

def patch_geo_portable():
    code = GEO.read_text(encoding="utf-8", errors="replace")
    code = ensure_imports(code, ["import sys"])

    # Replace get_config_path() with a portable version
    pattern = r"(?ms)^def\s+get_config_path\(\)\s*->\s*Path:\s*.*?^\s*return\s+.*?config\.json\s*$"
    repl = (
        'def get_config_path() -> Path:\n'
        '    """\n'
        '    PORTABLE mode:\n'
        '    - If frozen (PyInstaller): store config.json beside the EXE (USB-friendly)\n'
        '    - Else: store beside this .py when running from source\n'
        '    """\n'
        '    if getattr(sys, "frozen", False):\n'
        '        base = Path(sys.executable).resolve().parent\n'
        '    else:\n'
        '        base = Path(__file__).resolve().parent\n'
        '    return base / "config.json"\n'
    )

    if re.search(pattern, code):
        code = re.sub(pattern, repl, code, count=1)
    else:
        # If function not matched, do a simpler targeted replace on known old LOCALAPPDATA block
        code = re.sub(
            r'(?ms)^def\s+get_config_path\(\)\s*->\s*Path:\s*.*?^\s*return\s+base\s*/\s*"BallisticTarget"\s*/\s*"config\.json"\s*$',
            repl,
            code,
            count=1
        )

    GEO.write_text(code, encoding="utf-8")
    return True

def patch_main_portable():
    code = MAIN.read_text(encoding="utf-8", errors="replace")

    # Remove hardcoded PROJECT_ROOT = Path(r"G:\BallisticTarget") if present
    code = re.sub(r'(?m)^\s*PROJECT_ROOT\s*=\s*Path\(r".*?BallisticTarget"\)\s*\r?\n', "", code, count=1)

    # Remove any remaining hardcoded G:\BallisticTarget strings
    code = code.replace(r"G:\BallisticTarget", r"")  # keeps it from ever showing up as a literal
    code = code.replace("G:\\BallisticTarget", "")

    # Ensure core imports needed by the portable root
    code = ensure_imports(code, ["import sys", "from pathlib import Path"])

    # Portable root block
    portable_block = (
        "\n"
        "def get_app_root() -> Path:\n"
        "    \"\"\"Portable root:\n"
        "    - If frozen (PyInstaller): folder containing the EXE\n"
        "    - Else: folder containing this .py\n"
        "    \"\"\"\n"
        "    if getattr(sys, \"frozen\", False):\n"
        "        return Path(sys.executable).resolve().parent\n"
        "    return Path(__file__).resolve().parent\n"
        "\n"
        "APP_ROOT = get_app_root()\n"
        "CONFIG_PATH = APP_ROOT / \"config.json\"\n"
        "OUTPUT_DIR = APP_ROOT / \"output\" / \"targets\"\n"
        "LOG_DIR = APP_ROOT / \"logs\"\n"
        "\n"
    )

    # Remove older APP_ROOT/CONFIG_PATH/OUTPUT_DIR/LOG_DIR definitions (best effort)
    code = re.sub(r"(?ms)^\s*APP_ROOT\s*=.*?^\s*LOG_DIR\s*=.*?\r?\n", "", code, count=1)

    # Insert portable block after last import/from line
    lines = code.splitlines(True)
    last_imp = -1
    for i, ln in enumerate(lines):
        if re.match(r"^\s*(import|from)\s+.+", ln):
            last_imp = i
    if last_imp >= 0:
        lines.insert(last_imp + 1, portable_block)
        code = "".join(lines)
    else:
        code = portable_block + code

    # Replace load_env_from_geo_config with a correct try/except (fixes your “expected except/finally” issue)
    good_loader = (
        "def load_env_from_geo_config():\n"
        "    \"\"\"Load environmentals from config.json (portable: beside EXE/script).\"\"\"\n"
        "    try:\n"
        "        cfg_path = CONFIG_PATH\n"
        "        if cfg_path.exists():\n"
        "            import json\n"
        "            return json.loads(cfg_path.read_text(encoding=\"utf-8\"))\n"
        "    except Exception:\n"
        "        pass\n"
        "    return {}\n"
        "\n"
    )

    if re.search(r"(?ms)^\s*def\s+load_env_from_geo_config\(\)\s*:\s*.*?(?=^\s*def\s+|^\s*class\s+|\Z)", code):
        code = re.sub(
            r"(?ms)^\s*def\s+load_env_from_geo_config\(\)\s*:\s*.*?(?=^\s*def\s+|^\s*class\s+|\Z)",
            good_loader,
            code,
            count=1
        )
    else:
        # If missing, add near top after portable block
        code = good_loader + code

    MAIN.write_text(code, encoding="utf-8")
    return True

def main():
    b1 = backup(MAIN)
    b2 = backup(GEO)

    patch_geo_portable()
    patch_main_portable()

    print("OK: patched for portability (no hardcoded G:\\ paths).")
    print(f"Backup main: {b1}")
    print(f"Backup geo : {b2}")

if __name__ == "__main__":
    main()
