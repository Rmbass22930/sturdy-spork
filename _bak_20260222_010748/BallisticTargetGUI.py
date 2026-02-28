def load_env_from_geo_config():
    """Load environmentals from config.json (portable: beside EXE/script)."""
    try:
        cfg_path = CONFIG_PATH
        if cfg_path.exists():
            import json
            return json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

ï»¿
# -------------------- PORTABLE PATHS --------------------
from pathlib import Path

def app_base_dir() -> Path:
    """
    Returns folder where the app should store output/logs/config.
    - PyInstaller EXE: folder containing the EXE (portable/USB friendly)
    - Source run: folder containing this .py
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

BASE_DIR   = app_base_dir()
OUTPUT_DIR = BASE_DIR / "output" / "targets"
LOG_DIR    = BASE_DIR / "logs"
CONFIG_PATH = BASE_DIR / "config.json"
# --------------------------------------------------------
import math

import sys
import re
from pathlib import Path

import os
import json
def load_env_from_geo_config() -> dict:
    """
    Load environmentals from portable config.json (USB-safe).
    Never raises, always returns dict.
    """
    try:
        if CONFIG_PATH.exists():
            import json
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _app_base_dir() -> Path:
    """
    PORTABLE (USB) mode:
    - When frozen: store data beside the EXE (sys.executable folder)
    - When running from source: store data beside this .py file
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent



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

# BallisticTarget (GUI) - everything stored on G:
BASE_DIR = _app_base_dir()




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
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Ballistic Sight-In Target (One Page) - {rifle}", ln=True, align="C")
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 6, f"Ammo: {ammo}", ln=True)
    pdf.cell(0, 6, f"MV: {velocity} fps | BC(G1): {bc} | Sight Height: {sight_height} in | Zero: {zero_range} yd", ln=True)
    pdf.cell(0, 6, f"Temp: {temp} F | Altitude: {altitude} ft | Wind: {wind_speed:.1f} mph @ {wind_dir:.0f}Â° (FROM) | Gust: {wind_gust:.1f} mph", ln=True)
    pdf.cell(0, 6, f"Wind: {wind_speed:.1f} mph @ {wind_dir:.0f}Â° (FROM) | Gust: {wind_gust:.1f} mph", ln=True)
    pdf.ln(4)

    distances = [50, 100, 200, 300, 400]
    colors = {
        50:  (255, 0, 0),
        100: (0, 0, 255),
        200: (0, 150, 0),
        300: (255, 165, 0),
        400: (160, 0, 160),
    }

    positions = {
        50:  (25, 55),
        100: (105, 55),
        200: (25, 115),
        300: (105, 115),
        400: (65, 170),
    }
    circle_d = 50

    pdf.set_font("Arial", "B", 12)
    for d in distances:
        x, y = positions[d]
        r, g, b = colors[d]
        pdf.set_fill_color(r, g, b)
        pdf.ellipse(x, y, circle_d, circle_d, style="F")

        pdf.set_fill_color(0, 0, 0)
        pdf.ellipse(x + circle_d/2 - 1.5, y + circle_d/2 - 1.5, 3, 3, style="F")

        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(x, y + circle_d + 2)
        pdf.cell(circle_d, 6, f"{d} yd", align="C")

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 12)
    pdf.set_xy(10, 235)
    pdf.cell(0, 7, "Ballistic Data (computed for each distance)", ln=True)

    pdf.set_font("Arial", "B", 10)
    pdf.set_x(10)
    pdf.cell(20, 7, "Yds", border=1)
    pdf.cell(35, 7, "Drop (in)", border=1)
    pdf.cell(45, 7, "Vel @ range (fps)", border=1)
    pdf.cell(35, 7, "TOF (sec)", border=1)
    pdf.cell(30, 7, "Angle (deg)", border=1, ln=True)

    pdf.set_font("Arial", "", 10)
    for d in distances:
        drop, vel_r, tof, ang = calculate_ballistics(d, velocity, bc, sight_height, zero_range, temp, altitude)
        pdf.set_x(10)
        pdf.cell(20, 7, f"{d}", border=1)
        pdf.cell(35, 7, f"{drop:.2f}", border=1)
        pdf.cell(45, 7, f"{vel_r:.0f}", border=1)
        pdf.cell(35, 7, f"{tof:.3f}", border=1)
        pdf.cell(30, 7, f"{ang:.3f}", border=1, ln=True)

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

        ttk.Label(frm, text="Tip: Turn OFF VPN for accurate Geo location before sharing a Maps link.", foreground="#444")\
            .grid(row=row, column=1, sticky="w", **pad); row += 1

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        ttk.Button(btns, text="Generate PDF Target", command=self.on_generate).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Quit", command=self.destroy).grid(row=0, column=1, padx=6)

        self.status = tk.StringVar(value=f"Output: {OUTPUT_DIR}")
        ttk.Label(frm, textvariable=self.status).grid(row=row+1, column=0, columnspan=2, pady=(0,10))


    def load_env_from_config(self):
        """Load temp/alt from %LOCALAPPDATA%\\\\BallisticTarget\\\\config.json (written by Geo tool). Shows VPN reminder once."""
        try:
            from pathlib import Path
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

            self.status.set(f"Saved: {pdf_path}")
            messagebox.showinfo("Done", f"PDF saved here:\n{pdf_path}")

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

def get_app_root() -> Path:
    """Portable root:
    - If frozen (PyInstaller): folder containing the EXE
    - Else: folder containing this .py
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

APP_ROOT = get_app_root()
CONFIG_PATH = APP_ROOT / "config.json"
OUTPUT_DIR = APP_ROOT / "output" / "targets"
LOG_DIR = APP_ROOT / "logs"

            CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"Saved:\n{CONFIG_PATH}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    App().mainloop()

if __name__ == "__main__":
    main()






















