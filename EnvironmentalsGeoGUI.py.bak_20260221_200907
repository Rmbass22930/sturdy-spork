def _extract_lat_lon_from_link(url: str):
    """
    Best-effort extraction of lat/lon from common Google/Apple maps share links.
    Returns (lat, lon) or (None, None).
    """
    if not url:
        return (None, None)

    u = url.strip()

    # Google Maps often contains: @lat,lon,zoom
    m = re.search(r'@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)', u)
    if m:
        return (float(m.group(1)), float(m.group(2)))

    # Sometimes query has "q=lat,lon" or "query=lat,lon"
    try:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query)
        for key in ("q", "query", "ll"):
            if key in qs and qs[key]:
                cand = qs[key][0]
                m2 = re.search(r'(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)', cand)
                if m2:
                    return (float(m2.group(1)), float(m2.group(2)))
    except Exception:
        pass

    # Apple Maps can include "ll=lat,lon"
    m3 = re.search(r'[\?&]ll=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)', u)
    if m3:
        return (float(m3.group(1)), float(m3.group(2)))

    return (None, None)


def _open_meteo_wind(lat: float, lon: float):
    """
    Fetch current wind from Open-Meteo (no key).
    Returns dict with wind_speed_mph, wind_dir_deg, wind_gust_mph (floats).
    """
    # Request current weather + gust + direction (best effort)
    # Open-Meteo supports: current=wind_speed_10m,wind_direction_10m,wind_gusts_10m (names may vary by API version)
    base = "https://api.open-meteo.com/v1/forecast"
    params = urllib.parse.urlencode({
        "latitude": lat,
        "longitude": lon,
        "current": "wind_speed_10m,wind_direction_10m,wind_gusts_10m",
        "wind_speed_unit": "mph",
        "temperature_unit": "fahrenheit",
        "timezone": "auto"
    })
    url = f"{base}?{params}"

    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))

    cur = data.get("current") or {}
    # field names per Open-Meteo docs:
    ws = cur.get("wind_speed_10m")
    wd = cur.get("wind_direction_10m")
    wg = cur.get("wind_gusts_10m")

    # if any missing, default to 0.0
    return {
        "wind_speed_mph": float(ws) if ws is not None else 0.0,
        "wind_dir_deg": float(wd) if wd is not None else 0.0,
        "wind_gust_mph": float(wg) if wg is not None else 0.0,
    }

import json

import sys
import urllib.request
import urllib.parse
import os
import re
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

def get_config_path() -> Path:
    """
    PORTABLE mode:
    Store config.json beside the executable (USB-friendly).
    Fallback to script folder when running from source.
    """
    # When frozen by PyInstaller
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent
    return base / "config.json"
def load_config() -> dict:
    p = get_config_path()
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def save_config(cfg: dict):
    p = get_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def fetch_wind_open_meteo(lat: float, lon: float) -> dict:
    """
    Fetch current wind from Open-Meteo (no API key).
    Returns mph + degrees (FROM) + gust mph.
    """
    base = "https://api.open-meteo.com/v1/forecast"
    params = urllib.parse.urlencode({
        "latitude": lat,
        "longitude": lon,
        "current": "wind_speed_10m,wind_direction_10m,wind_gusts_10m",
        "wind_speed_unit": "mph",
        "timezone": "auto"
    })
    url = f"{base}?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        cur = data.get("current") or {}
        ws = cur.get("wind_speed_10m")
        wd = cur.get("wind_direction_10m")
        wg = cur.get("wind_gusts_10m")
        return {
            "wind_speed_mph": float(ws) if ws is not None else 0.0,
            "wind_dir_deg": float(wd) if wd is not None else 0.0,
            "wind_gust_mph": float(wg) if wg is not None else 0.0,
        }
    except Exception:
        return {"wind_speed_mph": 0.0, "wind_dir_deg": 0.0, "wind_gust_mph": 0.0}
def try_extract_latlon(text: str):
    """
    Extract lat/lon from common Google Maps / Apple Maps share links.
    Supports:
      - .../@lat,lon,17z   (Google)
      - ...?q=lat,lon      (Google)
      - ...ll=lat,lon      (Apple/Google)
      - plain "lat, lon"
    """
    s = (text or "").strip()

    m = re.search(r"/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", s)
    if m:
        return float(m.group(1)), float(m.group(2))

    m = re.search(r"(?:\bq=|\bll=|\bdaddr=)\s*(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", s)
    if m:
        return float(m.group(1)), float(m.group(2))

    m = re.search(r"\b(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\b", s)
    if m:
        lat = float(m.group(1)); lon = float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon

    return None, None

class EnvGeoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BallisticTarget Environmentals + Geo Location")
        self.resizable(False, False)

        cfg = load_config()

        self.provider = tk.StringVar(value=str(cfg.get("map_provider", "Google Maps")))
        self.location_name = tk.StringVar(value=str(cfg.get("location_name", "")))
        self.lat = tk.StringVar(value="" if cfg.get("lat") is None else str(cfg.get("lat")))
        self.lon = tk.StringVar(value="" if cfg.get("lon") is None else str(cfg.get("lon")))
        self.temp = tk.StringVar(value=str(cfg.get("temp_F", 59)))
        self.alt  = tk.StringVar(value=str(cfg.get("altitude_ft", 0)))
        self.maps_link = tk.StringVar(value="")

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0)

        r = 0
        ttk.Label(frm, text="Maps Provider:").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Combobox(frm, textvariable=self.provider, values=["Google Maps", "Apple Maps"], state="readonly", width=20)\
            .grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Label(frm, text="Location Name (optional):").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.location_name, width=38).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Label(frm, text="Latitude:").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.lat, width=20).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Label(frm, text="Longitude:").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.lon, width=20).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r += 1

        ttk.Label(frm, text="Paste Maps share link:").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.maps_link, width=38).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Button(frm, text="Extract Lat/Lon from Link", command=self.on_extract)\
            .grid(row=r, column=0, columnspan=2, pady=(0,8)); r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r += 1

        ttk.Label(frm, text="Temperature (°F):").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.temp, width=20).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        ttk.Label(frm, text="Altitude (ft):").grid(row=r, column=0, sticky="e", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.alt, width=20).grid(row=r, column=1, sticky="w", padx=8, pady=6); r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(btns, text="Save", command=self.on_save).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Open Config Folder", command=self.open_folder).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Quit", command=self.destroy).grid(row=0, column=2, padx=6)

        self.status = tk.StringVar(value=f"Config: {get_config_path()}")
        ttk.Label(frm, textvariable=self.status).grid(row=r+1, column=0, columnspan=2, pady=(10,0))

    def open_folder(self):
        import subprocess
        p = get_config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["explorer", str(p.parent)])

    def on_extract(self):
        lat, lon = try_extract_latlon(self.maps_link.get())
        if lat is None or lon is None:
            messagebox.showerror(
                "Not found",
                "Could not extract lat/lon.\n\nOn your phone:\n"
                "- Google Maps: Share → Copy link\n"
                "- Apple Maps: Share → Copy link\n\nPaste the full link and try again."
            )
            return
        self.lat.set(str(lat)); self.lon.set(str(lon))
        messagebox.showinfo("Extracted", f"Latitude: {lat}\nLongitude: {lon}")

    def on_save(self):
        try:
            t = float(self.temp.get().strip())
            a = float(self.alt.get().strip())

            lat_s = self.lat.get().strip()
            lon_s = self.lon.get().strip()
            lat = float(lat_s) if lat_s else None
            lon = float(lon_s) if lon_s else None
            if lat is not None and not (-90 <= lat <= 90):
                raise ValueError("Latitude must be between -90 and 90.")
            if lon is not None and not (-180 <= lon <= 180):
                raise ValueError("Longitude must be between -180 and 180.")

            cfg = {
                "map_provider": self.provider.get().strip() or "Google Maps",
                "location_name": self.location_name.get().strip(),
                "lat": lat,
                "lon": lon,
                "temp_F": t,
                "altitude_ft": a,
            }
            save_config(cfg)
            messagebox.showinfo("Saved", f"Saved:\n{get_config_path()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    EnvGeoApp().mainloop()

if __name__ == "__main__":
    main()





