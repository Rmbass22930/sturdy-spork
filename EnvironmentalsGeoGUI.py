import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import messagebox, ttk

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
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_ROOT = get_app_root()
CONFIG_PATH = APP_ROOT / "config.json"


def load_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def try_extract_latlon(text: str):
    """
    Extract lat/lon from common Google/Apple link formats or plain "lat, lon".
    Returns (lat, lon) or (None, None).
    """
    s = (text or "").strip()
    if not s:
        return (None, None)

    # direct "lat, lon"
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$", s)
    if m:
        lat = float(m.group(1))
        lon = float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon

    # Google .../@lat,lon,zoom
    m = re.search(r"/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", s)
    if m:
        return float(m.group(1)), float(m.group(2))

    # query params ?q=lat,lon or ll=lat,lon
    try:
        parsed = urllib.parse.urlparse(s)
        qs = urllib.parse.parse_qs(parsed.query)
        for key in ("q", "ll", "query", "daddr"):
            if key in qs and qs[key]:
                cand = qs[key][0]
                m = re.search(r"(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", cand)
                if m:
                    return float(m.group(1)), float(m.group(2))
    except Exception:
        pass

    return (None, None)


def fetch_weather(lat: float, lon: float) -> dict:
    """
    Fetch temperature + wind from Open-Meteo with a MET Norway fallback.
    """
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
    """
    Fetch elevation (ft) from Open-Meteo with an OpenTopo fallback.
    """
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


class EnvGeoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BallisticTarget Environmentals + Geo")
        self.resizable(False, False)

        cfg = load_config()

        self.provider = tk.StringVar(value=str(cfg.get("map_provider", "Google Maps")))
        self.location_name = tk.StringVar(value=str(cfg.get("location_name", "")))
        self.lat = tk.StringVar(value="" if cfg.get("lat") is None else str(cfg.get("lat")))
        self.lon = tk.StringVar(value="" if cfg.get("lon") is None else str(cfg.get("lon")))
        self.temp = tk.StringVar(value=str(cfg.get("temp_F", 59)))
        self.alt = tk.StringVar(value=str(cfg.get("altitude_ft", 0)))
        self.wind_speed = tk.StringVar(value=str(cfg.get("wind_speed_mph", 0)))
        self.wind_dir = tk.StringVar(value=str(cfg.get("wind_dir_deg", 0)))
        self.wind_gust = tk.StringVar(value=str(cfg.get("wind_gust_mph", 0)))
        self.maps_link = tk.StringVar(value="")

        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0)

        r = 0
        ttk.Label(frm, text="Maps Provider:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Combobox(
            frm,
            textvariable=self.provider,
            values=["Google Maps", "Apple Maps"],
            state="readonly",
            width=22,
        ).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Location Name (optional):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.location_name, width=36).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Latitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lat, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Longitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lon, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        r += 1

        ttk.Label(frm, text="Paste Maps link (or lat, lon):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.maps_link, width=36).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        link_btns = ttk.Frame(frm)
        link_btns.grid(row=r, column=1, sticky="w", **pad)
        ttk.Button(link_btns, text="Extract Lat/Lon", command=self.on_extract).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(link_btns, text="Open Provider", command=self.open_provider).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(link_btns, text="Fetch Weather", command=self.on_fetch_weather).grid(row=0, column=2)
        r += 1

        ttk.Separator(frm).grid(row=r, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        r += 1

        ttk.Label(frm, text="Temperature (F):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.temp, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Altitude (ft):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.alt, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Wind Speed (mph):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_speed, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Wind Direction (deg FROM):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_dir, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Wind Gust (mph):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.wind_gust, width=20).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Tip: turn off VPN before sharing links for best accuracy.", foreground="#444")\
            .grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(2, 8))
        r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=2, pady=(6, 0))
        ttk.Button(btns, text="Save", command=self.on_save).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Open Config Folder", command=self.open_folder).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Quit", command=self.destroy).grid(row=0, column=2, padx=6)

        self.status = tk.StringVar(value=f"Config path: {CONFIG_PATH}")
        ttk.Label(frm, textvariable=self.status).grid(row=r + 1, column=0, columnspan=2, pady=(8, 0))

    def open_provider(self):
        prov = (self.provider.get() or "Google Maps").lower()
        url = "https://maps.google.com/" if "apple" not in prov else "https://maps.apple.com/"
        webbrowser.open(url)

    def open_folder(self):
        path = CONFIG_PATH.parent
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(str(path))
        else:
            opener = shutil.which("xdg-open") or shutil.which("open")
            if opener:
                subprocess.Popen([opener, str(path)])
        self.status.set(f"Opened folder: {path}")

    def on_extract(self):
        lat, lon = try_extract_latlon(self.maps_link.get())
        if lat is None or lon is None:
            messagebox.showerror(
                "Could not extract",
                "Paste a Google/Apple Maps share link or plain 'lat, lon' pair.",
            )
            return
        self.lat.set(str(lat))
        self.lon.set(str(lon))
        messagebox.showinfo("Extracted", f"Latitude: {lat}\nLongitude: {lon}")

    def on_fetch_weather(self):
        try:
            lat = float(self.lat.get())
            lon = float(self.lon.get())
        except ValueError:
            messagebox.showerror("Missing lat/lon", "Enter latitude and longitude before fetching weather.")
            return
        weather = fetch_weather(lat, lon)
        elevation = fetch_elevation(lat, lon)
        if weather["temp_F"] is not None:
            self.temp.set(f"{weather['temp_F']:.1f}")
        if weather["wind_speed_mph"] is not None:
            self.wind_speed.set(f"{weather['wind_speed_mph']:.1f}")
        if weather["wind_dir_deg"] is not None:
            self.wind_dir.set(f"{weather['wind_dir_deg']:.0f}")
        if weather["wind_gust_mph"] is not None:
            self.wind_gust.set(f"{weather['wind_gust_mph']:.1f}")
        if elevation is not None:
            self.alt.set(f"{elevation:.0f}")
        messagebox.showinfo("Weather Updated", "Environmental values refreshed from Open-Meteo.")

    def on_save(self):
        try:
            def to_float(value: str, default: float = 0.0) -> float:
                text = (value or "").strip()
                return float(text) if text else float(default)

            lat = (self.lat.get() or "").strip()
            lon = (self.lon.get() or "").strip()
            lat_val = float(lat) if lat else None
            lon_val = float(lon) if lon else None
            if lat_val is not None and not (-90 <= lat_val <= 90):
                raise ValueError("Latitude must be between -90 and 90.")
            if lon_val is not None and not (-180 <= lon_val <= 180):
                raise ValueError("Longitude must be between -180 and 180.")

            cfg = {
                "map_provider": self.provider.get().strip() or "Google Maps",
                "location_name": self.location_name.get().strip(),
                "lat": lat_val,
                "lon": lon_val,
                "temp_F": to_float(self.temp.get(), 59),
                "altitude_ft": to_float(self.alt.get(), 0),
                "wind_speed_mph": to_float(self.wind_speed.get(), 0),
                "wind_dir_deg": to_float(self.wind_dir.get(), 0),
                "wind_gust_mph": to_float(self.wind_gust.get(), 0),
            }
            save_config(cfg)
            self.status.set(f"Saved: {CONFIG_PATH}")
            messagebox.showinfo("Saved", f"Saved:\n{CONFIG_PATH}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))


def main():
    EnvGeoApp().mainloop()


if __name__ == "__main__":
    main()
