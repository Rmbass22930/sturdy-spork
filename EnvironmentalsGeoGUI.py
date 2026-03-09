import json
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import messagebox, ttk

from geo_weather import extract_lat_lon_from_text, fetch_elevation_feet, fetch_weather_from_services


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
        self.status = tk.StringVar(value=f"Config path: {CONFIG_PATH}")
        self._weather_thread: threading.Thread | None = None

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
        self.fetch_weather_btn = ttk.Button(link_btns, text="Fetch Weather", command=self.on_fetch_weather)
        self.fetch_weather_btn.grid(row=0, column=2)
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

        ttk.Label(frm, text="Tip: turn off VPN before sharing links for best accuracy.", foreground="#444").grid(
            row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(2, 8)
        )
        r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=2, pady=(6, 0))
        ttk.Button(btns, text="Save", command=self.on_save).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Open Config Folder", command=self.open_folder).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Quit", command=self.destroy).grid(row=0, column=2, padx=6)

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
        lat, lon = extract_lat_lon_from_text(self.maps_link.get())
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
        if self._weather_thread and self._weather_thread.is_alive():
            messagebox.showinfo("Weather", "Weather fetch already running.")
            return
        try:
            lat = float(self.lat.get())
            lon = float(self.lon.get())
        except ValueError:
            messagebox.showerror("Missing lat/lon", "Enter latitude and longitude before fetching weather.")
            return

        self.fetch_weather_btn.configure(state="disabled")
        self.status.set("Fetching weather and elevation...")

        def worker() -> None:
            weather = fetch_weather_from_services(lat, lon)
            elevation = fetch_elevation_feet(lat, lon)
            self.after(0, lambda: self._on_weather_fetch_complete(weather, elevation))

        self._weather_thread = threading.Thread(target=worker, daemon=True)
        self._weather_thread.start()

    def _on_weather_fetch_complete(self, weather: dict, elevation: float | None) -> None:
        self.fetch_weather_btn.configure(state="normal")
        updated: list[str] = []
        if weather.get("temp_F") is not None:
            self.temp.set(f"{weather['temp_F']:.1f}")
            updated.append("temperature")
        if weather.get("wind_speed_mph") is not None:
            self.wind_speed.set(f"{weather['wind_speed_mph']:.1f}")
            updated.append("wind speed")
        if weather.get("wind_dir_deg") is not None:
            self.wind_dir.set(f"{weather['wind_dir_deg']:.0f}")
            updated.append("wind direction")
        if weather.get("wind_gust_mph") is not None:
            self.wind_gust.set(f"{weather['wind_gust_mph']:.1f}")
            updated.append("wind gust")
        if elevation is not None:
            self.alt.set(f"{elevation:.0f}")
            updated.append("altitude")

        if updated:
            source = weather.get("source") or "weather provider"
            freshness = "cached" if weather.get("stale") else "live"
            if weather.get("stale_minutes") is not None:
                freshness += f" (~{weather['stale_minutes']:.1f} min old)"
            self.status.set(f"Updated via {source} ({freshness}).")
            messagebox.showinfo("Weather Updated", f"Updated via {source} ({freshness}): {', '.join(updated)}")
            return

        self.status.set("Weather fetch returned no usable data.")
        if weather.get("stale"):
            messagebox.showwarning("Cached Weather", "Live weather failed and no new values were applied.")
        else:
            messagebox.showwarning("No data", "Weather providers did not return usable data.")

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
