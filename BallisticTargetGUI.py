import math
import sys
import re
from pathlib import Path
import os
import json
import shutil
import subprocess
import urllib.parse
import urllib.request
import webbrowser
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from fpdf import FPDF

HTTP_USER_AGENT = "BallisticTarget/2026.02 (support@ballistictarget.app)"
DEFAULT_HTTP_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}
METNO_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}


def _fetch_json(url: str, extra_headers: dict | None = None, timeout: int = 10) -> dict | None:
    headers = DEFAULT_HTTP_HEADERS.copy()
    if extra_headers:
        headers.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _ms_to_mph(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value) * 2.236936
    except Exception:
        return None

def get_app_root() -> Path:
    """
    Portable root:
    - If frozen (PyInstaller), use folder beside the EXE (USB-friendly).
    - If running from source, use this .py folder.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

APP_ROOT = get_app_root()
CONFIG_PATH = APP_ROOT / "config.json"
OUTPUT_DIR = APP_ROOT / "output"
LOG_DIR = APP_ROOT / "logs"


def _normalize_path_for_compare(path: Path) -> str:
    """
    Normalize a path for safe string comparisons across drives / casings.
    """
    try:
        return os.path.normcase(os.path.abspath(str(path)))
    except Exception:
        return str(path)


def _list_user_desktop_dirs() -> list[Path]:
    """
    Return Desktop directories for the current user, including OneDrive variants.
    """
    candidates: list[Path] = []
    seen: set[str] = set()

    def _add_candidate(base: Path | str | None):
        if not base:
            return
        try:
            path = Path(base).expanduser()
        except Exception:
            return
        key = _normalize_path_for_compare(path)
        if key in seen:
            return
        seen.add(key)
        if path.exists():
            candidates.append(path)

    home = Path.home()
    _add_candidate(home / "Desktop")

    userprofile = os.environ.get("USERPROFILE")
    userprofile_path = None
    if userprofile:
        userprofile_path = Path(userprofile)
        _add_candidate(userprofile_path / "Desktop")

    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        val = os.environ.get(var)
        if val:
            _add_candidate(Path(val) / "Desktop")

    if userprofile_path and userprofile_path.exists():
        try:
            for child in userprofile_path.iterdir():
                if child.is_dir() and child.name.lower().startswith("onedrive"):
                    _add_candidate(child / "Desktop")
        except Exception:
            pass

    return candidates


def find_peer_desktop_output_dirs() -> list[Path]:
    """
    If the app is running from a Desktop install, locate matching installations on
    other Desktop roots (e.g., OneDrive) so generated targets can be mirrored there.
    """
    desktops = _list_user_desktop_dirs()
    if not desktops:
        return []

    app_name = APP_ROOT.name.strip()
    if not app_name:
        return []

    app_norm = _normalize_path_for_compare(APP_ROOT)
    installed_on_desktop = any(
        _normalize_path_for_compare(desktop / app_name) == app_norm for desktop in desktops
    )
    if not installed_on_desktop:
        return []

    peers: list[Path] = []
    seen: set[str] = set()
    for desktop in desktops:
        candidate_root = desktop / app_name
        if _normalize_path_for_compare(candidate_root) == app_norm:
            continue
        peer_output = candidate_root / "output"
        key = _normalize_path_for_compare(peer_output)
        if key in seen:
            continue
        seen.add(key)
        peers.append(peer_output)

    return peers


def mirror_pdf_to_peer_desktops(pdf_path: Path) -> tuple[list[Path], list[tuple[Path, str]]]:
    """
    Copy a generated PDF into output folders on additional Desktop installs.
    Returns (success_paths, [(failed_path, error_message), ...]).
    """
    mirrored: list[Path] = []
    errors: list[tuple[Path, str]] = []
    original_norm = _normalize_path_for_compare(pdf_path)

    for peer_output in find_peer_desktop_output_dirs():
        target = peer_output / pdf_path.name
        if _normalize_path_for_compare(target) == original_norm:
            continue
        try:
            peer_output.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pdf_path, target)
            mirrored.append(target)
        except Exception as exc:
            errors.append((target, str(exc)))

    return mirrored, errors

MOA_AT_100Y_IN = 1.047
INCH_TO_MM = 25.4

def moa_diameter_inches(distance_yd: float, moa_value: float = 1.0) -> float:
    if distance_yd <= 0:
        return 0.0
    return MOA_AT_100Y_IN * (distance_yd / 100.0) * moa_value

def moa_diameter_mm(distance_yd: float, moa_value: float = 1.0) -> float:
    return moa_diameter_inches(distance_yd, moa_value) * INCH_TO_MM

def drop_to_moa(drop_in: float, distance_yd: float) -> float:
    denom = moa_diameter_inches(distance_yd, 1.0)
    if denom <= 0:
        return 0.0
    return drop_in / denom

def build_ballistic_rows(distances: list[int], velocity: float, bc: float, sight_height: float,
                         zero_range: float, temp: float, altitude: float) -> dict[int, dict[str, float]]:
    rows: dict[int, dict[str, float]] = {}
    for d in distances:
        drop, vel_r, tof, ang = calculate_ballistics(d, velocity, bc, sight_height, zero_range, temp, altitude)
        rows[d] = {
            "drop": drop,
            "velocity": vel_r,
            "tof": tof,
            "angle": ang,
            "drop_moa": drop_to_moa(drop, d),
        }
    return rows

def load_env_from_geo_config() -> dict:
    """
    Load environmentals from portable config.json (USB-safe).
    Never raises, always returns dict.
    """
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def fetch_weather(lat: float, lon: float) -> dict:
    base = "https://api.open-meteo.com/v1/forecast"
    params = urllib.parse.urlencode(
        {
            "latitude": lat,
            "longitude": lon,
            "current": "temperature_2m,wind_speed_10m,wind_direction_10m,wind_gusts_10m",
            "wind_speed_unit": "mph",
            "temperature_unit": "fahrenheit",
            "timezone": "auto",
        }
    )
    url = f"{base}?{params}"
    data = _fetch_json(url)
    if data:
        cur = data.get("current") or {}
        return {
            "temp_F": float(cur.get("temperature_2m")) if cur.get("temperature_2m") is not None else None,
            "wind_speed_mph": float(cur.get("wind_speed_10m")) if cur.get("wind_speed_10m") is not None else None,
            "wind_dir_deg": float(cur.get("wind_direction_10m")) if cur.get("wind_direction_10m") is not None else None,
            "wind_gust_mph": float(cur.get("wind_gusts_10m")) if cur.get("wind_gusts_10m") is not None else None,
        }

    fallback_url = f"https://api.met.no/weatherapi/locationforecast/2.0/compact?lat={lat:.4f}&lon={lon:.4f}"
    fallback = _fetch_json(fallback_url, extra_headers=METNO_HEADERS, timeout=12)
    if fallback:
        try:
            times = fallback.get("properties", {}).get("timeseries") or []
            latest = times[0]
            details = latest.get("data", {}).get("instant", {}).get("details", {})
            temp = details.get("air_temperature")
            speed = _ms_to_mph(details.get("wind_speed"))
            gust = _ms_to_mph(details.get("wind_speed_of_gust"))
            direction = details.get("wind_from_direction")
            return {
                "temp_F": float(temp) if temp is not None else None,
                "wind_speed_mph": speed,
                "wind_dir_deg": float(direction) if direction is not None else None,
                "wind_gust_mph": gust,
            }
        except Exception:
            pass

    return {"temp_F": None, "wind_speed_mph": None, "wind_dir_deg": None, "wind_gust_mph": None}


def fetch_elevation(lat: float, lon: float) -> float | None:
    base = "https://api.open-meteo.com/v1/elevation"
    params = urllib.parse.urlencode({"latitude": lat, "longitude": lon})
    url = f"{base}?{params}"
    data = _fetch_json(url)
    if data:
        elevations = data.get("elevation")
        if isinstance(elevations, list) and elevations:
            meters = elevations[0]
            try:
                return float(meters) * 3.28084
            except Exception:
                return None

    fallback_url = f"https://api.opentopodata.org/v1/aster30m?locations={lat:.6f},{lon:.6f}"
    fallback = _fetch_json(fallback_url, timeout=12)
    if fallback:
        results = fallback.get("results")
        if isinstance(results, list) and results:
            meters = results[0].get("elevation")
            if meters is not None:
                try:
                    return float(meters) * 3.28084
                except Exception:
                    return None
    return None

# --- G1 DRAG MODEL (STANDARD) ----------------------------
# Mach-based drag coefficient table (G1)
# Columns: Mach, Cd
G1_DRAG_TABLE = [
    (0.0, 0.262),
    (0.5, 0.255),
    (0.7, 0.248),
    (0.9, 0.242),
    (1.0, 0.295),
    (1.2, 0.365),
    (1.5, 0.380),
    (2.0, 0.360),
    (2.5, 0.330),
    (3.0, 0.300),
]

SPEED_OF_SOUND_FPS = 1116.0  # ~59F

def g1_cd_for_velocity(v_fps: float) -> float:
    mach = max(v_fps / SPEED_OF_SOUND_FPS, 0.01)
    for i in range(len(G1_DRAG_TABLE) - 1):
        m1, cd1 = G1_DRAG_TABLE[i]
        m2, cd2 = G1_DRAG_TABLE[i + 1]
        if m1 <= mach <= m2:
            t = (mach - m1) / (m2 - m1)
            return cd1 + t * (cd2 - cd1)
    return G1_DRAG_TABLE[-1][1]
# ---------------------------------------------------------

G_FTPS2 = 32.174
RHO_STANDARD = 1.225  # kg/m^3 at sea level

def calculate_air_density_ratio(altitude_ft: float, temp_F: float) -> float:
    temp_C = (temp_F - 32) * 5.0 / 9.0
    altitude_m = altitude_ft * 0.3048
    pressure = 101325 * (1 - 2.25577e-5 * altitude_m) ** 5.25588
    density = pressure / (287.05 * (temp_C + 273.15))
    return density / RHO_STANDARD

def calculate_ballistics(range_yd, velocity_fps, bc, sight_height_in, zero_range_yd, temp_F, altitude_ft):
    '''
    Ballistics using G1 drag (TableG1) via py-ballisticcalc (point-mass).
    Returns: (drop_in, vel_fps, tof_s, bore_angle_deg)

    If anything fails, falls back to the simple approximation so builds never break.
    '''
    def _fallback():
        G_FTPS2 = 32.174
        range_ft = float(range_yd) * 3.0

        rho_ratio = calculate_air_density_ratio(altitude_ft, temp_F)

        bc2 = float(bc) if float(bc) > 0 else 0.05
        v0 = float(velocity_fps) if float(velocity_fps) > 0 else 1.0

        k = 0.00035 * rho_ratio / bc2
        vel_r = max(v0 * math.exp(-k * float(range_yd)), 1.0)
        v_avg = (v0 + vel_r) / 2.0
        tof = range_ft / v_avg
        drop_in = 0.5 * G_FTPS2 * (tof ** 2) * 12.0

        zero_ft = float(zero_range_yd) * 3.0
        zero_ft = zero_ft if zero_ft > 0 else 1.0
        sight_height_ft = float(sight_height_in) / 12.0

        vel_zero = max(v0 * math.exp(-k * float(zero_range_yd)), 1.0)
        vavg_zero = (v0 + vel_zero) / 2.0
        tof_zero = zero_ft / vavg_zero
        drop_zero_ft = 0.5 * G_FTPS2 * (tof_zero ** 2)

        tan_theta = (sight_height_ft + drop_zero_ft) / zero_ft
        sight_angle_deg = math.degrees(math.atan(tan_theta))
        return drop_in, vel_r, tof, sight_angle_deg

    try:
        from py_ballisticcalc import Calculator, Shot, Weapon, Ammo, DragModel
        from py_ballisticcalc.drag_tables import TableG1
        from py_ballisticcalc.unit import Distance, Velocity, Temperature

        calc = Calculator()

        shot = Shot(
            weapon=Weapon(sight_height=float(sight_height_in)),
            ammo=Ammo(
                DragModel(float(bc), TableG1),
                mv=Velocity.FPS(float(velocity_fps))
            )
        )

        # atmosphere (best effort)
        try:
            shot.atmo.altitude = Distance.Foot(float(altitude_ft))
            shot.atmo.temperature = Temperature.Fahrenheit(float(temp_F))
        except Exception:
            pass

        # zero
        try:
            calc.set_weapon_zero(shot, Distance.Yard(float(zero_range_yd)))
        except Exception:
            pass

        res = calc.fire(shot, trajectory_range=float(range_yd), extra_data=True)

        pts = None
        for attr in ("trajectory", "_trajectory", "data", "_data"):
            if hasattr(res, attr):
                pts = getattr(res, attr)
                break
        if pts is None:
            try:
                pts = list(res)
            except Exception:
                pts = None

        if not pts:
            return _fallback()

        def _yd(u):
            try:
                return float(u) / 36.0
            except Exception:
                return None

        best = None
        best_err = 1e9
        for pt in pts:
            d = getattr(pt, "distance", None)
            yd = _yd(d) if d is not None else None
            if yd is None:
                continue
            err = abs(yd - float(range_yd))
            if err < best_err:
                best = pt
                best_err = err

        if best is None:
            return _fallback()

        vel = getattr(best, "velocity", None)
        t = getattr(best, "time", None)
        drop = getattr(best, "target_drop", None)

        vel_fps = float(vel) if vel is not None else None
        tof_s = float(t) if t is not None else None
        drop_in = float(drop) if drop is not None else None

        bore_deg = 0.0  # optional; keep simple

        if vel_fps is None or tof_s is None or drop_in is None:
            return _fallback()

        return drop_in, vel_fps, tof_s, bore_deg

    except Exception:
        return _fallback()

def _safe_filename(text: str) -> str:
    text = text.strip()
    text = re.sub(r'[\\/:*?"<>|]+', "_", text)
    text = re.sub(r"\s+", "_", text)
    return text[:120] if text else "BallisticTarget"

def generate_one_page_target_pdf(pdf_path: Path, rifle: str, ammo: str, velocity: float, bc: float,
                                 sight_height: float, zero_range: float, temp: float, altitude: float,
                                 wind_speed: float = 0.0, wind_dir: float = 0.0, wind_gust: float = 0.0):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.set_title("Ballistic Sight-In Target")
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Ballistic Sight-In Target - {rifle}", ln=True, align="C")
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 6, f"Ammo: {ammo}", ln=True)
    pdf.cell(0, 6, f"MV: {velocity} fps | BC(G1): {bc} | Sight Height: {sight_height} in | Zero: {zero_range} yd", ln=True)
    pdf.cell(0, 6, f"Temp: {temp} F | Altitude: {altitude} ft | Wind: {wind_speed:.1f} mph @ {wind_dir:.0f}\u00B0 (FROM) | Gust: {wind_gust:.1f} mph", ln=True)
    pdf.ln(3)

    distances = [50, 100, 200, 300, 400]
    colors = {
        50:  (255, 0, 0),
        100: (0, 0, 255),
        200: (0, 150, 0),
        300: (255, 165, 0),
        400: (160, 0, 160),
    }

    dot_x_positions_mm = {
        50: 35.0,
        100: 150.0,
        200: 35.0,
        300: 170.0,
        400: 105.0,
    }

    target_top_mm = 55.0
    target_bottom_mm = pdf.h - 45.0
    margin_mm = 12.0
    page_bottom_limit = pdf.h - margin_mm

    ballistic_rows = build_ballistic_rows(distances, velocity, bc, sight_height, zero_range, temp, altitude)
    drop_values = [row["drop_moa"] for row in ballistic_rows.values()]
    min_drop_moa = min(drop_values)
    max_drop_moa = max(drop_values)

    def _map_drop_to_mm(drop_value: float) -> float:
        if math.isclose(max_drop_moa, min_drop_moa):
            return (target_top_mm + target_bottom_mm) / 2.0
        norm = (drop_value - min_drop_moa) / (max_drop_moa - min_drop_moa)
        span = max(target_bottom_mm - target_top_mm, 1.0)
        return target_top_mm + norm * span

    pdf.set_font("Arial", "B", 12)
    dot_bottoms: list[float] = []
    for d in distances:
        cx = dot_x_positions_mm[d]
        cy = _map_drop_to_mm(ballistic_rows[d]["drop_moa"])
        diameter_mm = max(moa_diameter_mm(d, 1.0), 6.0)
        radius_mm = diameter_mm / 2.0
        cx = min(max(cx, margin_mm + radius_mm), pdf.w - margin_mm - radius_mm)
        cy = min(max(cy, target_top_mm + radius_mm), page_bottom_limit - radius_mm)
        r, g, b = colors[d]
        pdf.set_fill_color(r, g, b)
        pdf.ellipse(cx - radius_mm, cy - radius_mm, diameter_mm, diameter_mm, style="F")
        pdf.set_draw_color(255, 255, 255)
        pdf.set_line_width(0.4)
        pdf.line(cx - radius_mm, cy, cx + radius_mm, cy)
        pdf.line(cx, cy - radius_mm, cx, cy + radius_mm)
        pdf.set_fill_color(0, 0, 0)
        pdf.ellipse(cx - 1.5, cy - 1.5, 3.0, 3.0, style="F")
        label = f"{d} yd | Hold {ballistic_rows[d]['drop_moa']:.2f} MOA"
        pdf.set_xy(cx - radius_mm, cy + radius_mm + 2)
        pdf.set_font("Arial", "", 9)
        pdf.multi_cell(diameter_mm, 4.2, label, align="C")
        pdf.set_font("Arial", "B", 12)
        dot_bottoms.append(cy + radius_mm)

    pdf.set_font("Arial", "", 10)
    legend_y = max(target_top_mm + 10, min(pdf.h - 35, max(dot_bottoms, default=target_top_mm) + 6))
    pdf.set_xy(10, legend_y)
    pdf.multi_cell(
        0,
        5,
        "Each dot is drawn to 1.00 MOA at its labeled distance when printed at 100%. "
        "Dots are vertically spaced according to the MOA hold they represent, so greater drop places the dot lower on the page. "
        "Aim at the colored dot for the stated range; the computed hold/dial value is shown under each dot "
        "and summarized on the next page.",
    )

    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 9, "Ballistic Table & Usage Notes", ln=True, align="C")
    pdf.ln(2)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(
        0,
        5.5,
        "Drops are referenced to the zero range you entered. Positive MOA values indicate how much you must dial "
        "or hold over to stay on target at that distance.",
    )
    pdf.ln(2)

    headers = ["Yds", "Drop (in)", "Drop (MOA)", "Vel @ range (fps)", "TOF (sec)", "Angle (deg)"]
    widths = [18, 30, 30, 42, 30, 30]
    row_h = 6

    pdf.set_font("Arial", "B", 10)
    pdf.set_x(10)
    for header, w in zip(headers, widths):
        pdf.cell(w, row_h, header, border=1, align="C")
    pdf.ln(row_h)

    pdf.set_font("Arial", "", 10)
    for d in distances:
        row = ballistic_rows[d]
        pdf.set_x(10)
        pdf.cell(widths[0], row_h, f"{d}", border=1, align="C")
        pdf.cell(widths[1], row_h, f"{row['drop']:.2f}", border=1, align="R")
        pdf.cell(widths[2], row_h, f"{row['drop_moa']:.2f}", border=1, align="R")
        pdf.cell(widths[3], row_h, f"{row['velocity']:.0f}", border=1, align="R")
        pdf.cell(widths[4], row_h, f"{row['tof']:.3f}", border=1, align="R")
        pdf.cell(widths[5], row_h, f"{row['angle']:.3f}", border=1, align="R")
        pdf.ln(row_h)

    pdf.ln(5)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "How to use the MOA dots", ln=True)
    pdf.set_font("Arial", "", 10)
    steps = [
        "Confirm your rifle is zeroed at the distance shown in the header (50 yd by default).",
        "Keep that zero in place when you move to the other dots—do not re-zero at each distance; instead, dial/hold the value shown.",
        "Do not adjust horizontal windage when moving to a farther dot. Simply dial/hold the elevation value so the crosshair stays centered on the colored dot.",
        "Print this target at 100% scale on US Letter / A4 paper so the MOA subtensions remain accurate.",
        "When shooting at a farther distance, dial or hold the MOA shown for that dot, then aim at the colored dot.",
        "Your impacts should land in the center crosshair; if they do not, adjust zero or ballistic inputs and reprint.",
    ]
    for step in steps:
        pdf.multi_cell(0, 5, f"• {step}")

    pdf.ln(3)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Per-distance quick reference", ln=True)
    pdf.set_font("Arial", "", 10)
    for d in distances:
        row = ballistic_rows[d]
        pdf.multi_cell(
            0,
            5,
            f"{d} yd dot: hold/dial {row['drop_moa']:.2f} MOA up "
            f"({row['drop']:.2f} in of drop, MV {row['velocity']:.0f} fps).",
        )

    pdf.output(str(pdf_path))

def _to_float(s: str, field_name: str) -> float:
    try:
        return float(s.strip())
    except Exception:
        raise ValueError(f"{field_name} must be a number.")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BallisticTarget - One Page PDF Target")
        self.resizable(False, False)

        # Menu
        menubar = tk.Menu(self)
        tools = tk.Menu(menubar, tearoff=0)
        tools.add_command(label='Environmentals + Geo', command=self.on_open_env_geo)
        menubar.add_cascade(label='Tools', menu=tools)
        self.config(menu=menubar)
        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self)
        frm.grid(row=0, column=0, sticky="nsew")

        self.vars = {
            "rifle": tk.StringVar(value="PSA PA-10 18in"),
            "ammo": tk.StringVar(value="Hornady Superformance .308 165gr SST"),
            "velocity": tk.StringVar(value="2840"),
            "bc": tk.StringVar(value="0.447"),
            "sight_height": tk.StringVar(value="2.60"),
            "zero_range": tk.StringVar(value="50"),
            "temp": tk.StringVar(value="59"),
            "altitude": tk.StringVar(value="0"),
            "wind_speed": tk.StringVar(value="0"),
            "wind_dir": tk.StringVar(value="0"),
            "wind_gust": tk.StringVar(value="0"),
            "use_env": tk.StringVar(value="1"),
        }
        self.target_choice = tk.StringVar(value="")
        self.target_lookup = {}
        row = 0
        ttk.Label(frm, text="Rifle Model:").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["rifle"], width=45).grid(row=row, column=1, **pad); row += 1

        ttk.Label(frm, text="Ammunition:").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["ammo"], width=45).grid(row=row, column=1, **pad); row += 1

        ttk.Label(frm, text="Muzzle Velocity (fps):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["velocity"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Ballistic Coefficient (G1):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["bc"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Sight Height (in):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["sight_height"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Zero Range (yd):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["zero_range"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Temperature (F):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["temp"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Altitude (ft):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["altitude"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        # Environmentals + Geo import
        ttk.Checkbutton(frm, text="Use Environmentals (Temp/Altitude)", variable=self.vars["use_env"],
                        onvalue="1", offvalue="0").grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Button(frm, text="Load Temp/Alt from Geo tool", command=self.load_env_from_config).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Button(frm, text="Fetch Weather (Open-Meteo)", command=self.fetch_weather_from_api).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Tip: Turn OFF VPN for accurate Geo location before sharing a Maps link.", foreground="#444")\
            .grid(row=row, column=1, sticky="w", **pad); row += 1

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        ttk.Button(btns, text="Generate PDF Target", command=self.on_generate).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Environmentals + Geo", command=self.on_open_env_geo).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Quit", command=self.destroy).grid(row=0, column=2, padx=6)
        row += 1

        print_controls = ttk.Frame(frm)
        print_controls.grid(row=row, column=0, columnspan=2, pady=(0, 8))
        ttk.Button(print_controls, text="Print Newest Target", command=self.on_print_newest).grid(row=0, column=0, padx=6)
        ttk.Button(print_controls, text="Print Selected Target", command=self.on_print_selected).grid(row=0, column=1, padx=6)
        ttk.Button(print_controls, text="Open Targets Folder", command=self.on_open_targets_folder).grid(row=0, column=2, padx=6)
        self.print_copies = tk.IntVar(value=1)
        self.copy_status = tk.StringVar(value="")
        copies_box = ttk.Labelframe(print_controls, text="Print Copies")
        copies_box.grid(row=0, column=3, padx=(12, 0), pady=(0, 6), sticky="nsew", rowspan=2)
        ttk.Label(copies_box, textvariable=self.copy_status).grid(row=0, column=0, padx=8, pady=(6, 2))
        ttk.Button(copies_box, text="Choose...", command=self.prompt_print_copies).grid(row=1, column=0, padx=8, pady=(0, 8))
        self.target_combo = ttk.Combobox(
            print_controls,
            textvariable=self.target_choice,
            width=56,
            state="readonly",
            postcommand=lambda: self.refresh_target_dropdown(select_newest=False),
        )
        self.target_combo.grid(row=1, column=0, columnspan=3, padx=6, pady=(6, 0), sticky="ew")
        self.target_combo.bind("<<ComboboxSelected>>", self.on_target_selected)
        row += 1
        self._update_copy_display()

        self.status = tk.StringVar(value=f"Output: {OUTPUT_DIR}")
        ttk.Label(frm, textvariable=self.status).grid(row=row, column=0, columnspan=2, pady=(0,10))
        self.refresh_target_dropdown(select_newest=True)

    def _list_saved_targets(self):
        try:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        targets = [p for p in OUTPUT_DIR.glob("*.pdf") if p.is_file()]

        def _mtime(path: Path) -> float:
            try:
                return path.stat().st_mtime
            except OSError:
                return 0.0

        targets.sort(key=_mtime, reverse=True)
        return targets

    def refresh_target_dropdown(self, select_newest=False):
        targets = self._list_saved_targets()
        names = [p.name for p in targets]
        self.target_lookup = {p.name: p for p in targets}
        self.target_combo["values"] = names

        if names:
            current = self.target_choice.get().strip()
            if select_newest or current not in self.target_lookup:
                self.target_choice.set(names[0])
        else:
            self.target_choice.set("")

    def _update_copy_display(self) -> None:
        try:
            value = int(self.print_copies.get())
        except (ValueError, tk.TclError):
            value = 1
        value = max(1, min(20, value))
        self.print_copies.set(value)
        label = "1 copy" if value == 1 else f"{value} copies"
        self.copy_status.set(label)

    def _get_requested_copies(self) -> int | None:
        try:
            copies = int(self.print_copies.get())
        except (ValueError, tk.TclError):
            messagebox.showwarning("Copies", "Enter a whole number of copies (1-20).")
            self.print_copies.set(1)
            self._update_copy_display()
            return None
        copies = max(1, min(20, copies))
        self.print_copies.set(copies)
        self._update_copy_display()
        return copies

    def prompt_print_copies(self):
        value = simpledialog.askinteger(
            "Print Copies",
            "How many copies do you want to print?",
            parent=self,
            initialvalue=self.print_copies.get(),
            minvalue=1,
            maxvalue=20,
        )
        if value:
            self.print_copies.set(value)
            self._update_copy_display()

    def _print_target_file(self, target_path: Path, copies: int = 1):
        if not target_path.exists():
            raise FileNotFoundError(f"Target file not found:\n{target_path}")

        if sys.platform.startswith("win"):
            for _ in range(copies):
                os.startfile(str(target_path), "print")
            return

        print_cmd = shutil.which("lp")
        args = []
        if print_cmd:
            if copies > 1:
                args.extend(["-n", str(copies)])
        else:
            print_cmd = shutil.which("lpr")
            if not print_cmd:
                raise RuntimeError("No print command found (lp/lpr).")
            if copies > 1:
                args.extend(["-#", str(copies)])
        subprocess.run([print_cmd, *args, str(target_path)], check=True)

    def on_print_newest(self):
        targets = self._list_saved_targets()
        if not targets:
            messagebox.showwarning("No targets", f"No saved targets found in:\n{OUTPUT_DIR}")
            return

        newest = targets[0]
        copies = self._get_requested_copies()
        if copies is None:
            return

        try:
            self._print_target_file(newest, copies=copies)
            self.target_choice.set(newest.name)
            suffix = f" (x{copies})" if copies > 1 else ""
            self.status.set(f"Sent to printer: {newest.name}{suffix}")
            self.refresh_target_dropdown(select_newest=False)
        except Exception as e:
            self.status.set("Print failed.")
            messagebox.showerror("Print Error", f"Failed to print:\n{newest}\n\n{e}")

    def on_target_selected(self, _event=None):
        selected_name = self.target_choice.get().strip()
        if selected_name:
            self.status.set(f"Selected target: {selected_name}")

    def on_print_selected(self, _event=None):
        self.refresh_target_dropdown(select_newest=False)
        selected_name = self.target_choice.get().strip()
        if not selected_name:
            messagebox.showwarning("No target selected", "Select a saved target first.")
            return

        target = self.target_lookup.get(selected_name)
        if target is None:
            self.refresh_target_dropdown(select_newest=False)
            messagebox.showwarning("Not found", f"Selected target not found:\n{selected_name}")
            return

        copies = self._get_requested_copies()
        if copies is None:
            return

        try:
            self._print_target_file(target, copies=copies)
            suffix = f" (x{copies})" if copies > 1 else ""
            self.status.set(f"Sent to printer: {target.name}{suffix}")
        except Exception as e:
            self.status.set("Print failed.")
            messagebox.showerror("Print Error", f"Failed to print:\n{target}\n\n{e}")

    def on_open_targets_folder(self):
        try:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(str(OUTPUT_DIR))
                self.status.set(f"Opened folder: {OUTPUT_DIR}")
                return

            opener = shutil.which("xdg-open") or shutil.which("open")
            if not opener:
                raise RuntimeError("No folder opener found (xdg-open/open).")

            subprocess.Popen([opener, str(OUTPUT_DIR)])
            self.status.set(f"Opened folder: {OUTPUT_DIR}")
        except Exception as e:
            messagebox.showerror("Open Folder Error", f"Failed to open folder:\n{OUTPUT_DIR}\n\n{e}")


    def load_env_from_config(self):
        """Load temp/alt from %LOCALAPPDATA%\\\\BallisticTarget\\\\config.json (written by Geo tool). Shows VPN reminder once."""
        try:
            cfg_path = CONFIG_PATH

            if not cfg_path.exists():
                messagebox.showwarning(
                    "Not found",
                    f"Config not found:\n{cfg_path}\n\nRun the Geo tool once and click Save."
                )
                return

            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

            # One-time VPN reminder (stored in config so it only shows once)
            try:
                if not cfg.get("vpn_tip_shown", False):
                    messagebox.showinfo(
                        "VPN Reminder",
                        "For accurate Geo location, turn OFF VPN on your phone and PC before sharing a Maps link.\n\n"
                        "VPNs can change the apparent location used by map links / lookups."
                    )
                    cfg["vpn_tip_shown"] = True
                    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            except Exception:
                pass

            if "temp_F" in cfg:
                self.vars["temp"].set(str(cfg["temp_F"]))
            if "altitude_ft" in cfg:
                self.vars["altitude"].set(str(cfg["altitude_ft"]))

            # Ensure environmentals enabled
            if "use_env" in self.vars:
                self.vars["use_env"].set("1")

            messagebox.showinfo("Loaded", f"Loaded Temp/Alt from:\n{cfg_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config:\n{e}")

    def fetch_weather_from_api(self):
        cfg = load_env_from_geo_config()
        lat = cfg.get("lat")
        lon = cfg.get("lon")
        if lat is None or lon is None:
            messagebox.showwarning(
                "Missing location",
                "Save a latitude/longitude in the Environmentals + Geo tool first.",
            )
            return
        try:
            lat_val = float(lat)
            lon_val = float(lon)
        except (TypeError, ValueError):
            messagebox.showerror("Invalid location", "Latitude/longitude in config are invalid. Re-save them in the Geo tool.")
            return

        weather = fetch_weather(lat_val, lon_val)
        elevation = fetch_elevation(lat_val, lon_val)
        updated = []
        if weather["temp_F"] is not None:
            self.vars["temp"].set(f"{weather['temp_F']:.1f}")
            cfg["temp_F"] = weather["temp_F"]
            updated.append("temperature")
        if weather["wind_speed_mph"] is not None and "wind_speed" in self.vars:
            self.vars["wind_speed"].set(f"{weather['wind_speed_mph']:.1f}")
            cfg["wind_speed_mph"] = weather["wind_speed_mph"]
            updated.append("wind speed")
        if weather["wind_dir_deg"] is not None and "wind_dir" in self.vars:
            self.vars["wind_dir"].set(f"{weather['wind_dir_deg']:.0f}")
            cfg["wind_dir_deg"] = weather["wind_dir_deg"]
            updated.append("wind direction")
        if weather["wind_gust_mph"] is not None and "wind_gust" in self.vars:
            self.vars["wind_gust"].set(f"{weather['wind_gust_mph']:.1f}")
            cfg["wind_gust_mph"] = weather["wind_gust_mph"]
            updated.append("wind gust")
        if elevation is not None:
            self.vars["altitude"].set(f"{elevation:.0f}")
            cfg["altitude_ft"] = elevation
            updated.append("altitude")
        if "use_env" in self.vars:
            self.vars["use_env"].set("1")

        try:
            CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except Exception:
            pass

        if updated:
            messagebox.showinfo("Weather Updated", f"Updated via Open-Meteo: {', '.join(updated)}")
        else:
            messagebox.showwarning("No data", "Open-Meteo did not return usable weather data.")


    def on_open_env_geo(self):
        try:
            EnvGeoDialog(self)
        except Exception as e:
            messagebox.showerror("Env+Geo Error", str(e))

    def on_generate(self):
        try:
            rifle = self.vars["rifle"].get().strip()
            ammo = self.vars["ammo"].get().strip()
            if not rifle:
                raise ValueError("Rifle Model is required.")
            if not ammo:
                raise ValueError("Ammunition is required.")

            velocity = _to_float(self.vars["velocity"].get(), "Muzzle Velocity (fps)")
            bc = _to_float(self.vars["bc"].get(), "Ballistic Coefficient (G1)")
            sight_height = _to_float(self.vars["sight_height"].get(), "Sight Height (in)")
            zero_range = _to_float(self.vars["zero_range"].get(), "Zero Range (yd)")
            temp = _to_float(self.vars["temp"].get(), "Temperature (F)")
            altitude = _to_float(self.vars["altitude"].get(), "Altitude (ft)")
            wind_speed = _to_float(self.vars["wind_speed"].get(), "Wind Speed (mph)")
            wind_dir   = _to_float(self.vars["wind_dir"].get(), "Wind Direction (deg)")
            wind_gust  = _to_float(self.vars["wind_gust"].get(), "Wind Gust (mph)")
            try:
                if "use_env" in self.vars and self.vars["use_env"].get().strip() == "1":
                    cfg = load_env_from_geo_config()
                    # override only if present
                    temp = float(cfg.get("temp_F", temp))
                    altitude = float(cfg.get("altitude_ft", altitude))
                    wind_speed = float(cfg.get("wind_speed_mph", wind_speed))
                    wind_dir   = float(cfg.get("wind_dir_deg", wind_dir))
                    wind_gust  = float(cfg.get("wind_gust_mph", wind_gust))
            except Exception:
                pass
            wind_speed = _to_float(self.vars["wind_speed"].get(), "Wind Speed (mph)")
            wind_dir   = _to_float(self.vars["wind_dir"].get(), "Wind Direction (deg)")
            wind_gust  = _to_float(self.vars["wind_gust"].get(), "Wind Gust (mph)")
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            filename = f"BallisticTarget_{_safe_filename(rifle)}_{_safe_filename(ammo)}.pdf"
            pdf_path = OUTPUT_DIR / filename

            self.status.set("Generating PDF...")
            self.update_idletasks()

            generate_one_page_target_pdf(pdf_path, rifle, ammo, velocity, bc, sight_height, zero_range, temp, altitude, wind_speed, wind_dir, wind_gust)

            mirrored_paths, mirror_errors = mirror_pdf_to_peer_desktops(pdf_path)
            if mirrored_paths:
                count = len(mirrored_paths)
                plural = "s" if count != 1 else ""
                self.status.set(f"Saved: {pdf_path} (mirrored to {count} desktop{plural})")
            else:
                self.status.set(f"Saved: {pdf_path}")

            self.refresh_target_dropdown(select_newest=True)
            detail = f"PDF saved here:\n{pdf_path}"
            if mirrored_paths:
                other = "\n".join(str(p) for p in mirrored_paths)
                detail += f"\n\nAlso copied to:\n{other}"
            messagebox.showinfo("Done", detail)
            if mirror_errors:
                error_lines = "\n".join(f"{dest}: {err}" for dest, err in mirror_errors)
                messagebox.showwarning("Copy Warning", f"Some desktop copies failed:\n{error_lines}")

        except Exception as e:
            self.status.set("Error.")
            messagebox.showerror("Error", str(e))

class EnvGeoDialog(tk.Toplevel):
    """
    Embedded Environmentals + Geo (portable).
    Writes CONFIG_PATH beside the EXE (USB-friendly).
    """
    def __init__(self, master):
        super().__init__(master)
        self.title("Environmentals + Geo (Portable)")
        self.resizable(False, False)

        self.provider = tk.StringVar(value="Google Maps")
        self.location_name = tk.StringVar(value="")
        self.lat = tk.StringVar(value="")
        self.lon = tk.StringVar(value="")
        self.temp = tk.StringVar(value="59")
        self.alt = tk.StringVar(value="0")
        self.wind_speed = tk.StringVar(value="0")
        self.wind_dir = tk.StringVar(value="0")
        self.wind_gust = tk.StringVar(value="0")

        self.maps_link = tk.StringVar(value="")

        pad = {"padx": 10, "pady": 5}
        frm = ttk.Frame(self)
        frm.grid(row=0, column=0, sticky="nsew")

        r = 0
        ttk.Label(frm, text="Map Provider:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Combobox(frm, textvariable=self.provider, values=["Google Maps","Apple Maps"], width=25, state="readonly").grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Location Name (optional):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.location_name, width=35).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Paste Maps link OR 'lat, lon':").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.maps_link, width=35).grid(row=r, column=1, sticky="w", **pad); r += 1

        btns = ttk.Frame(frm); btns.grid(row=r, column=1, sticky="w", **pad)
        ttk.Button(btns, text="Extract Lat/Lon", command=self.on_extract).grid(row=0, column=0, padx=0, pady=0)
        ttk.Button(btns, text="Open Provider", command=self.on_open_provider).grid(row=0, column=1, padx=8, pady=0)
        r += 1

        ttk.Label(frm, text="Latitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lat, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Longitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lon, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Separator(frm, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", padx=10, pady=8); r += 1

        ttk.Label(frm, text="Temp (F):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.temp, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Altitude (ft):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.alt, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Wind Speed (mph):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_speed, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Wind Dir (deg FROM):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_dir, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Wind Gust (mph):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_gust, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Separator(frm, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", padx=10, pady=8); r += 1

        ttk.Label(frm, text="VPN NOTE: Turn OFF VPN for accurate Geo location.").grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=2); r += 1

        ttk.Button(frm, text="Save to USB config.json", command=self.on_save).grid(row=r, column=0, columnspan=2, pady=10)

        self.load_existing()

    def load_existing(self):
        try:
            if CONFIG_PATH.exists():
                import json
                cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                self.provider.set(cfg.get("map_provider","Google Maps"))
                self.location_name.set(cfg.get("location_name",""))
                self.lat.set("" if cfg.get("lat") is None else str(cfg.get("lat")))
                self.lon.set("" if cfg.get("lon") is None else str(cfg.get("lon")))
                self.temp.set(str(cfg.get("temp_F", "59")))
                self.alt.set(str(cfg.get("altitude_ft", "0")))
                self.wind_speed.set(str(cfg.get("wind_speed_mph", "0")))
                self.wind_dir.set(str(cfg.get("wind_dir_deg", "0")))
                self.wind_gust.set(str(cfg.get("wind_gust_mph", "0")))
        except Exception:
            pass

    def try_extract_latlon(self, text: str):
        text = (text or "").strip()
        # direct "lat, lon"
        m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$", text)
        if m:
            return float(m.group(1)), float(m.group(2))
        # google "@lat,lon"
        m = re.search(r"/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", text)
        if m:
            return float(m.group(1)), float(m.group(2))
        # q=lat,lon or ll=lat,lon
        m = re.search(r"[?&](?:q|ll)=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", text)
        if m:
            return float(m.group(1)), float(m.group(2))
        return None, None

    def on_open_provider(self):
        prov = (self.provider.get() or "Google Maps").lower()
        if "apple" in prov:
            webbrowser.open("https://maps.apple.com/")
        else:
            webbrowser.open("https://maps.google.com/")

    def on_extract(self):
        lat, lon = self.try_extract_latlon(self.maps_link.get())
        if lat is None or lon is None:
            messagebox.showerror(
                "Could not extract",
                "Could not extract lat/lon.\n\nPaste:\n- a Google/Apple Maps share link, OR\n- '32.214666, -95.455974'"
            )
            return
        self.lat.set(str(lat)); self.lon.set(str(lon))
        messagebox.showinfo("Extracted", f"Latitude: {lat}\nLongitude: {lon}")

    def on_save(self):
        try:
            def f(x, name):
                x = (x or "").strip()
                return float(x) if x != "" else 0.0

            t = f(self.temp.get(), "Temp")
            a = f(self.alt.get(), "Altitude")
            ws = f(self.wind_speed.get(), "Wind speed")
            wd = f(self.wind_dir.get(), "Wind dir")
            wg = f(self.wind_gust.get(), "Wind gust")

            lat_s = (self.lat.get() or "").strip()
            lon_s = (self.lon.get() or "").strip()
            lat = float(lat_s) if lat_s else None
            lon = float(lon_s) if lon_s else None

            if lat is not None and not (-90 <= lat <= 90): raise ValueError("Latitude must be between -90 and 90.")
            if lon is not None and not (-180 <= lon <= 180): raise ValueError("Longitude must be between -180 and 180.")

            cfg = {
                "map_provider": self.provider.get().strip() or "Google Maps",
                "location_name": self.location_name.get().strip(),
                "lat": lat,
                "lon": lon,
                "temp_F": float(t),
                "altitude_ft": float(a),
                "wind_speed_mph": float(ws),
                "wind_dir_deg": float(wd),
                "wind_gust_mph": float(wg),
            }

            import json

            CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"Saved:\n{CONFIG_PATH}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    App().mainloop()

if __name__ == "__main__":
    main()
























