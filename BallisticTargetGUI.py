import atexit
import copy
import difflib
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Optional, Callable
from fpdf import FPDF
from bs4 import BeautifulSoup, FeatureNotFound
try:
    from pypdf import PdfReader, PdfWriter
except ImportError:  # PyInstaller fallback guarded at runtime
    PdfReader = None
    PdfWriter = None

from geo_projection import (
    CARDINAL_BEARINGS,
    ProjectionError,
    format_elevation,
    project_path,
    project_path_between_points,
)

from web_ballistics import (
    MANUAL_AMMO_CATALOG,
    AmmoWebData,
    RifleWebData,
    TwistReport,
    build_twist_report,
    fetch_ammo_data,
    fetch_rifle_data,
)

HTTP_USER_AGENT = "BallisticTarget/2026.02 (support@ballistictarget.app)"
DEFAULT_HTTP_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}
METNO_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}

_MEI_STALE_SECONDS = 6 * 60 * 60

AMMO_MANUFACTURER_PLACEHOLDER = "Select manufacturer"
AMMO_LOAD_PLACEHOLDER = "Select load"


def _cleanup_stale_mei_dirs() -> None:
    """Remove leftover PyInstaller temp dirs from prior runs."""
    try:
        temp_root = Path(tempfile.gettempdir())
    except (OSError, RuntimeError):
        return
    current = Path(getattr(sys, "_MEIPASS", ""))
    for candidate in temp_root.glob("_MEI*"):
        try:
            if current and candidate == current:
                continue
            age = time.time() - candidate.stat().st_mtime
            if age < _MEI_STALE_SECONDS:
                continue
            shutil.rmtree(candidate, ignore_errors=True)
        except Exception:
            continue


def _remove_current_mei_dir() -> None:
    """Best-effort removal of the active PyInstaller temp dir before bootloader cleanup."""
    mei_root = getattr(sys, "_MEIPASS", None)
    if not mei_root:
        return
    mei_path = Path(mei_root)
    for _ in range(10):
        try:
            shutil.rmtree(mei_path, ignore_errors=False)
            return
        except OSError:
            time.sleep(0.25)
    # Final fallback: dispatch a background thread to retry without blocking exit.
    try:
        timer = threading.Timer(1.0, shutil.rmtree, args=(mei_path,), kwargs={"ignore_errors": True})
        timer.daemon = True
        timer.start()
    except Exception:
        pass


_cleanup_stale_mei_dirs()
atexit.register(_remove_current_mei_dir)


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


def extract_lat_lon_from_text(text: str) -> tuple[float | None, float | None]:
    """
    Parse either a raw "lat, lon" pair or a Google/Apple Maps style share URL.
    Returns (lat, lon) or (None, None) if parsing fails.
    """
    raw = (text or "").strip()
    if not raw:
        return None, None
    manual = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$", raw)
    if manual:
        return float(manual.group(1)), float(manual.group(2))
    at_pattern = re.search(r"/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if at_pattern:
        return float(at_pattern.group(1)), float(at_pattern.group(2))
    q_pattern = re.search(r"[?&](?:q|ll)=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if q_pattern:
        return float(q_pattern.group(1)), float(q_pattern.group(2))
    apple_pattern = re.search(r"loc=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if apple_pattern:
        return float(apple_pattern.group(1)), float(apple_pattern.group(2))
    return None, None

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
PREFERENCES_PATH = APP_ROOT / "preferences.json"
MISSION_STORE_PATH = APP_ROOT / "missions.json"
TELEMETRY_LOG_PATH = LOG_DIR / "telemetry.jsonl"
WEATHER_CACHE_PATH = LOG_DIR / "weather_cache.json"
ELEVATION_CACHE_PATH = LOG_DIR / "elevation_cache.json"

MAX_MISSION_HISTORY = 50
WEATHER_CACHE_MAX_ENTRIES = 320
ELEVATION_CACHE_MAX_ENTRIES = 320
WEATHER_CACHE_MAX_STALE_SECONDS = 6 * 60 * 60  # 6 hours
API_HEALTH_INTERVAL_SECONDS = 5 * 60  # 5 minutes

_PREFS_LOCK = threading.Lock()
_MISSION_LOCK = threading.Lock()


def _migrate_legacy_targets_dir() -> None:
    """Bring older installs that used output/targets up to the new layout."""
    legacy_dir = OUTPUT_DIR / "targets"
    try:
        legacy_exists = legacy_dir.exists() and legacy_dir.is_dir()
    except Exception:
        legacy_exists = False
    if not legacy_exists:
        return

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    for item in list(legacy_dir.iterdir()):
        dest = OUTPUT_DIR / item.name
        if dest.exists():
            continue
        try:
            item.rename(dest)
            continue
        except Exception:
            pass
        try:
            shutil.move(str(item), str(dest))
        except Exception:
            continue

    try:
        legacy_empty = not any(legacy_dir.iterdir())
    except Exception:
        legacy_empty = False
    if legacy_empty:
        try:
            legacy_dir.rmdir()
        except Exception:
            pass


_migrate_legacy_targets_dir()


def _ensure_parent(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


class SimpleJsonCache:
    def __init__(self, path: Path, max_entries: int = 200):
        self.path = path
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
        except FileNotFoundError:
            return {}
        except Exception:
            return {}
        return {}

    def _flush(self) -> None:
        _ensure_parent(self.path)
        try:
            with self.path.open("w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
        except Exception:
            pass

    def _key(self, lat: float, lon: float) -> str:
        return f"{round(float(lat), 3):.3f},{round(float(lon), 3):.3f}"

    def remember(self, lat: float, lon: float, payload: dict[str, Any]) -> None:
        key = self._key(lat, lon)
        entry = {
            "ts": time.time(),
            "data": payload,
        }
        with self._lock:
            self._data[key] = entry
            if len(self._data) > self.max_entries:
                items = sorted(self._data.items(), key=lambda kv: kv[1].get("ts", 0.0), reverse=True)
                trimmed = dict(items[: self.max_entries])
                self._data = trimmed
            self._flush()

    def fetch(self, lat: float, lon: float) -> tuple[dict[str, Any], float] | tuple[None, None]:
        key = self._key(lat, lon)
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None, None
            age = time.time() - float(entry.get("ts", 0.0))
            data = copy.deepcopy(entry.get("data") or {})
            return data, age


WEATHER_CACHE = SimpleJsonCache(WEATHER_CACHE_PATH, WEATHER_CACHE_MAX_ENTRIES)
ELEVATION_CACHE = SimpleJsonCache(ELEVATION_CACHE_PATH, ELEVATION_CACHE_MAX_ENTRIES)


def _maybe_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def load_preferences() -> dict[str, Any]:
    try:
        return json.loads(PREFERENCES_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_preferences(prefs: dict[str, Any]) -> None:
    _ensure_parent(PREFERENCES_PATH)
    with _PREFS_LOCK:
        try:
            PREFERENCES_PATH.write_text(json.dumps(prefs, indent=2), encoding="utf-8")
        except Exception:
            pass


def update_preferences(updates: dict[str, Any]) -> dict[str, Any]:
    with _PREFS_LOCK:
        prefs = load_preferences()
        prefs.update(updates)
        save_preferences(prefs)
        return prefs


class TelemetryLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._lock = threading.Lock()
        self.enabled = bool(load_preferences().get("telemetry_opt_in", False))

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)
        update_preferences({"telemetry_opt_in": self.enabled})

    def log(self, event: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        entry = {
            "event": event,
            "payload": payload,
            "ts": datetime.now(timezone.utc).isoformat(),
            "version": "2026.03",
        }
        try:
            _ensure_parent(self.log_path)
            with self._lock, self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass


def anonymize_location(lat: float | None, lon: float | None) -> dict[str, str | None]:
    if lat is None or lon is None:
        return {"loc_hash": None}
    seed = f"{round(float(lat), 3):.3f}|{round(float(lon), 3):.3f}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return {"loc_hash": digest}


def load_missions() -> list[dict[str, Any]]:
    try:
        data = json.loads(MISSION_STORE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except FileNotFoundError:
        return []
    except Exception:
        return []
    return []


def _write_missions(missions: list[dict[str, Any]]) -> None:
    with _MISSION_LOCK:
        _ensure_parent(MISSION_STORE_PATH)
        try:
            MISSION_STORE_PATH.write_text(json.dumps(missions, indent=2), encoding="utf-8")
        except Exception:
            pass


def store_mission_entry(entry: dict[str, Any]) -> None:
    missions = load_missions()
    missions.append(entry)
    missions.sort(key=lambda item: item.get("created_ts") or "", reverse=True)
    if len(missions) > MAX_MISSION_HISTORY:
        missions = missions[:MAX_MISSION_HISTORY]
    _write_missions(missions)


def replace_all_missions(missions: list[dict[str, Any]]) -> None:
    missions.sort(key=lambda item: item.get("created_ts") or "", reverse=True)
    if len(missions) > MAX_MISSION_HISTORY:
        missions = missions[:MAX_MISSION_HISTORY]
    _write_missions(missions)


def finalize_mission_entry(payload: dict[str, Any], name: str) -> dict[str, Any]:
    entry = copy.deepcopy(payload)
    entry["id"] = entry.get("id") or str(uuid.uuid4())
    entry["name"] = name.strip()
    entry["created_ts"] = datetime.now(timezone.utc).isoformat()
    return entry


def build_mission_payload_from_config(cfg: dict[str, Any]) -> dict[str, Any]:
    lat = _maybe_float(cfg.get("lat"))
    lon = _maybe_float(cfg.get("lon"))
    if lat is None or lon is None:
        raise ValueError("Config is missing Point A latitude/longitude.")
    target_lat = _maybe_float(cfg.get("target_lat"))
    target_lon = _maybe_float(cfg.get("target_lon"))
    range_yd = _maybe_float(cfg.get("range_to_target_yd")) or _maybe_float(cfg.get("range_to_target")) or 0.0
    bearing_deg = _maybe_float(cfg.get("bearing_to_target_deg"))
    env = {
        "temp_F": _maybe_float(cfg.get("temp_F")),
        "altitude_ft": _maybe_float(cfg.get("altitude_ft")),
        "wind_speed_mph": _maybe_float(cfg.get("wind_speed_mph")),
        "wind_dir_deg": _maybe_float(cfg.get("wind_dir_deg")),
        "wind_gust_mph": _maybe_float(cfg.get("wind_gust_mph")),
    }
    payload = {
        "point_a": {
            "lat": lat,
            "lon": lon,
            "location_name": cfg.get("location_name"),
            "provider": cfg.get("map_provider"),
        },
        "point_b": {"lat": target_lat, "lon": target_lon},
        "range_yd": range_yd or 0.0,
        "bearing_deg": bearing_deg,
        "path_points": int(cfg.get("path_points", 5) or 5),
        "use_pins_only": bool(cfg.get("use_pins_only", False)),
        "target_elev_ft": _maybe_float(cfg.get("target_elev_ft")),
        "environment": env,
    }
    return payload


TELEMETRY_LOGGER = TelemetryLogger(TELEMETRY_LOG_PATH)

API_HEALTH_TARGETS = [
    {
        "id": "weather_open_meteo",
        "label": "Weather (Open-Meteo)",
        "type": "json",
        "url": "https://api.open-meteo.com/v1/forecast?latitude=0&longitude=0&current=temperature_2m",
    },
    {
        "id": "weather_metno",
        "label": "Weather (MET Norway)",
        "type": "json",
        "url": "https://api.met.no/weatherapi/locationforecast/2.0/compact?lat=0&lon=0",
        "headers": METNO_HEADERS,
    },
    {
        "id": "elevation_open_meteo",
        "label": "Elevation (Open-Meteo)",
        "type": "json",
        "url": "https://api.open-meteo.com/v1/elevation?latitude=0&longitude=0",
    },
    {
        "id": "maps_connectivity",
        "label": "Mapping (Pins)",
        "type": "head",
        "url": "https://maps.apple.com/?ll=0,0",
    },
]


def _probe_json_endpoint(url: str, headers: dict | None = None, timeout: int = 5) -> bool:
    data = _fetch_json(url, extra_headers=headers, timeout=timeout)
    return bool(data)


def _probe_url(url: str, timeout: int = 5) -> bool:
    req = urllib.request.Request(url, headers=DEFAULT_HTTP_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(64)
            status = getattr(resp, "status", 200)
            return 200 <= status < 500
    except Exception:
        return False


def run_api_health_checks() -> list[dict[str, Any]]:
    now = time.time()
    results: list[dict[str, Any]] = []
    for target in API_HEALTH_TARGETS:
        start = time.time()
        ok = False
        message = ""
        try:
            if target.get("type") == "json":
                ok = _probe_json_endpoint(target["url"], headers=target.get("headers"))
            else:
                ok = _probe_url(target["url"])
            message = "OK" if ok else "No response"
        except Exception as exc:
            ok = False
            message = str(exc)
        latency_ms = int(max((time.time() - start) * 1000.0, 0))
        results.append(
            {
                "id": target["id"],
                "label": target["label"],
                "ok": ok,
                "message": message,
                "latency_ms": latency_ms,
                "timestamp": now,
            }
        )
    return results
TARGETS_ONLY_SUFFIX = ".targets.pdf"
EXTENSION_SUFFIX = ".extension.pdf"
SIGHT_PRESETS_PATH = APP_ROOT / "sight_height_presets.json"
SIGHT_PLATFORM_OPTIONS = [
    ("AR-15 / AR-10 flat-top rail", 1.10),
    ("AR platform w/ tall gas block", 1.20),
    ("Bolt gun w/ 0 MOA rail", 0.90),
    ("Bolt gun w/ 20 MOA rail", 0.95),
    ("AK / side-rail mount", 1.00),
    ("Lever-action w/ barrel-mounted rear sight", 0.82),
    ("Custom measured base offset", None),
]
MOUNT_CENTER_OPTIONS = [
    ("Low rings (1.30\" center)", 1.30),
    ("Absolute co-witness (1.50\" center)", 1.50),
    ("Lower 1/3 height (1.70\" center)", 1.70),
    ("LPVO mid-height (1.93\" center)", 1.93),
    ("Tall / FAST (2.26\" center)", 2.26),
    ("Custom mount center height", None),
]

MOUNT_SPEC_PRESETS = [
    {
        "label": "Vortex Precision QR Extended Cantilever 30mm (1.45\" center)",
        "height": 1.45,
        "keywords": {"vortex", "precision", "qr", "extended", "cantilever", "30", "30mm"},
        "source": "Vortex manufacturer spec",
    },
    {
        "label": "Vortex Precision QR Extended Cantilever 30mm High (1.58\" center)",
        "height": 1.58,
        "keywords": {"vortex", "precision", "qr", "extended", "cantilever", "high", "1.58", "30mm"},
        "source": "Vortex manufacturer spec",
    },
    {
        "label": "Vortex Precision Extended Cantilever 34mm (1.574\" center)",
        "height": 1.574,
        "keywords": {"vortex", "precision", "extended", "cantilever", "34", "34mm"},
        "source": "Vortex manufacturer spec",
    },
    {
        "label": "Burris AR-P.E.P.R. QD 30mm (1.50\" center)",
        "height": 1.50,
        "keywords": {"burris", "ar", "pepr", "qd", "30", "30mm"},
        "source": "Burris AR-P.E.P.R. quick detach spec",
    },
    {
        "label": "Burris AR-P.E.P.R. QD 34mm (1.50\" center)",
        "height": 1.50,
        "keywords": {"burris", "ar", "pepr", "qd", "34", "34mm"},
        "source": "Burris AR-P.E.P.R. quick detach spec",
    },
    {
        "label": "American Defense AD-RECON 30mm (1.47\" center)",
        "height": 1.47,
        "keywords": {"american", "defense", "ad", "recon", "30", "30mm"},
        "source": "American Defense AD-RECON spec",
    },
    {
        "label": "American Defense AD-RECON-M 30mm (1.63\" center)",
        "height": 1.63,
        "keywords": {"american", "defense", "ad", "recon", "m", "30", "30mm"},
        "source": "American Defense AD-RECON-M spec",
    },
    {
        "label": "Contessa Picatinny QD 34mm Medium (1.14\" center)",
        "height": 1.14,
        "keywords": {"contessa", "qd", "picatinny", "34", "34mm"},
        "source": "Contessa Picatinny QD spec",
    },
    {
        "label": "Warne QD X-SKEL 30mm (1.43\" center)",
        "height": 1.43,
        "keywords": {"warne", "xskel", "qd", "30", "30mm"},
        "source": "Warne X-SKEL QD spec",
    },
    {
        "label": "Alaska Arms CZ-550 QD rings (0.40\" saddle)",
        "height": 0.40,
        "keywords": {"alaska", "arms", "cz", "550", "qd", "rings"},
        "source": "Alaska Arms CZ550 QD ring spec",
    },
    {
        "label": "ATN / Bobro Dual Lever 30mm (1.50\" center)",
        "height": 1.50,
        "keywords": {"atn", "bobro", "dual", "lever", "30", "30mm"},
        "source": "ATN/Bobro dual lever mount spec",
    },
    {
        "label": "Leupold Mark IMS 30mm (1.50\" center)",
        "height": 1.50,
        "keywords": {"leupold", "mark", "ims", "30", "30mm"},
        "source": "Leupold Mark IMS spec",
    },
    {
        "label": "Bobro Dual Lever Precision Mount 30mm (1.50\" center)",
        "height": 1.50,
        "keywords": {"bobro", "dual", "lever", "precision", "30", "30mm"},
        "source": "Bobro dual lever mount spec",
    },
    {
        "label": "Midwest Industries QD 30mm (1.55\" center)",
        "height": 1.55,
        "keywords": {"midwest", "industries", "qd", "30", "30mm"},
        "source": "Midwest Industries QD 30mm spec",
    },
    {
        "label": "Midwest Industries QD 34mm High (1.93\" center)",
        "height": 1.93,
        "keywords": {"midwest", "industries", "qd", "34", "34mm", "high"},
        "source": "Midwest Industries QD 34mm spec",
    },
    {
        "label": "EGW HD 30mm rings (1.275\" center)",
        "height": 1.275,
        "keywords": {"egw", "hd", "rings", "30", "30mm"},
        "source": "EGW HD 30mm rings spec",
    },
    {
        "label": "Weaver Tactical 6-Hole XX-High 1\" (1.14\" center)",
        "height": 1.14,
        "keywords": {"weaver", "tactical", "xx", "high", "1", "one", "inch"},
        "source": "Weaver 6-hole tactical ring spec",
    },
]

CUSTOM_SCOPE_BRAND = "Custom / Other"

SCOPE_SPEC_PRESETS = [
    {
        "brand": "Vortex Optics",
        "label": "Vortex Razor HD LHT 4.5-22x50 FFP",
        "recommended_height": 1.70,
        "keywords": {"vortex", "razor", "lht", "4.5", "22", "50", "hd", "ffp"},
        "source": "Vortex Razor HD LHT manual",
    },
    {
        "brand": "Vortex Optics",
        "label": "Vortex Viper PST Gen II 5-25x50",
        "recommended_height": 1.50,
        "keywords": {"vortex", "viper", "pst", "gen", "ii", "5", "25", "50"},
        "source": "Vortex PST Gen II spec sheet",
    },
    {
        "brand": "Vortex Optics",
        "label": "Vortex Crossfire II 4-12x50 AO",
        "recommended_height": 1.45,
        "keywords": {"vortex", "crossfire", "ii", "4", "12", "50", "ao"},
        "source": "Vortex Crossfire II manual",
    },
    {
        "brand": "Vortex Optics",
        "label": "Vortex Strike Eagle 1-6x24",
        "recommended_height": 1.50,
        "keywords": {"vortex", "strike", "eagle", "1", "6", "24"},
        "source": "Vortex Strike Eagle quick reference",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Tactical 3-12x40AO IR Riflescope",
        "recommended_height": 1.55,
        "keywords": {"firefield", "tactical", "3", "12", "40", "ao", "ir"},
        "source": "Firefield Tactical series catalog (objective estimate)",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Tactical 4-16x42AO IR Riflescope",
        "recommended_height": 1.55,
        "keywords": {"firefield", "tactical", "4", "16", "42", "ao", "ir"},
        "source": "Firefield Tactical series catalog (objective estimate)",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Tactical 8-32x50 AO Riflescope",
        "recommended_height": 1.70,
        "keywords": {"firefield", "tactical", "8", "32", "50"},
        "source": "Firefield Tactical series catalog (objective estimate)",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Barrage 2.5-10x40 Riflescope",
        "recommended_height": 1.55,
        "keywords": {"firefield", "barrage", "2.5", "10", "40"},
        "source": "Firefield Barrage spec estimate",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Rapidstrike 1-6x24 Riflescope",
        "recommended_height": 1.50,
        "keywords": {"firefield", "rapidstrike", "1", "6", "24"},
        "source": "Firefield Rapidstrike spec estimate",
    },
    {
        "brand": "Firefield",
        "label": "Firefield Rapidstrike 1-10x24 Riflescope",
        "recommended_height": 1.50,
        "keywords": {"firefield", "rapidstrike", "1", "10", "24"},
        "source": "Firefield Rapidstrike spec estimate",
    },
    {
        "brand": "Firefield",
        "label": "Firefield RapidStrike 3-12x40 (FF13072)",
        "recommended_height": 1.55,
        "keywords": {"firefield", "rapidstrike", "3", "12", "40", "ff13072"},
        "source": "Firefield RapidStrike 3-12x40 catalog (objective 40 mm, 30 mm tube)",
    },
    {
        "brand": "Pulsar",
        "label": "Pulsar Thermion 2 XP50 PRO Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"pulsar", "thermion", "2", "xp50", "pro", "thermal"},
        "source": "Pulsar Thermion 2 XP50 PRO spec (50 mm objective lens)",
    },
    {
        "brand": "Pulsar",
        "label": "Pulsar Thermion 2 XQ35 PRO Thermal Riflescope",
        "recommended_height": 1.55,
        "keywords": {"pulsar", "thermion", "2", "xq35", "pro", "thermal"},
        "source": "Pulsar Thermion 2 XQ35 PRO spec (35 mm objective lens)",
    },
    {
        "brand": "Pulsar",
        "label": "Pulsar Talion XQ38 Pro Thermal Riflescope",
        "recommended_height": 1.55,
        "keywords": {"pulsar", "talion", "xq38", "pro", "thermal"},
        "source": "Pulsar Talion XQ38 Pro spec (38 mm objective lens)",
    },
    {
        "brand": "ATN Corp",
        "label": "ATN ThOR 5 XD 3-15x50 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"atn", "thor", "5", "xd", "3", "15", "50", "thermal"},
        "source": "ATN ThOR 5 XD datasheet (50 mm objective lens)",
    },
    {
        "brand": "ATN Corp",
        "label": "ATN ThOR 4 384 1.25-5x19 Thermal Riflescope",
        "recommended_height": 1.50,
        "keywords": {"atn", "thor", "4", "384", "1.25", "5", "19", "thermal"},
        "source": "ATN ThOR 4 spec (19 mm objective lens)",
    },
    {
        "brand": "ATN Corp",
        "label": "ATN ThOR LT 320 3-6x25 Thermal Riflescope",
        "recommended_height": 1.50,
        "keywords": {"atn", "thor", "lt", "320", "3", "6", "25", "thermal"},
        "source": "ATN ThOR LT manual (25 mm objective lens)",
    },
    {
        "brand": "AGM Global Vision",
        "label": "AGM Rattler TS35-640 Thermal Riflescope",
        "recommended_height": 1.55,
        "keywords": {"agm", "rattler", "ts35", "640", "thermal"},
        "source": "AGM Rattler TS35-640 spec (35 mm objective lens)",
    },
    {
        "brand": "AGM Global Vision",
        "label": "AGM Adder TS50-640 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"agm", "adder", "ts50", "640", "thermal"},
        "source": "AGM Adder TS50-640 spec (50 mm objective lens)",
    },
    {
        "brand": "Sightmark",
        "label": "Sightmark Wraith Mini 2-16x35 Thermal Riflescope",
        "recommended_height": 1.55,
        "keywords": {"sightmark", "wraith", "mini", "2", "16", "35", "thermal"},
        "source": "Sightmark Wraith Mini thermal spec (35 mm objective lens)",
    },
    {
        "brand": "iRay USA",
        "label": "iRay BOLT TH50C 3.5-14x50 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"iray", "bolt", "th50c", "3.5", "14", "50", "thermal"},
        "source": "iRay BOLT TH50C spec (50 mm objective lens)",
    },
    {
        "brand": "FLIR Systems",
        "label": "FLIR ThermoSight Pro PTS536 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"flir", "thermosight", "pro", "pts536", "thermal"},
        "source": "FLIR ThermoSight Pro PTS536 spec (50 mm objective lens)",
    },
    {
        "brand": "FLIR Systems",
        "label": "FLIR ThermoSight Pro PTS233 Thermal Riflescope",
        "recommended_height": 1.50,
        "keywords": {"flir", "thermosight", "pro", "pts233", "thermal"},
        "source": "FLIR ThermoSight Pro PTS233 spec (25 mm objective lens)",
    },
    {
        "brand": "Armasight",
        "label": "Armasight Contractor 640 3-12x50 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"armasight", "contractor", "640", "3", "12", "50", "thermal"},
        "source": "Armasight Contractor 640 spec (50 mm objective lens)",
    },
    {
        "brand": "Armasight",
        "label": "Armasight Contractor 320 3-12x25 Thermal Riflescope",
        "recommended_height": 1.50,
        "keywords": {"armasight", "contractor", "320", "3", "12", "25", "thermal"},
        "source": "Armasight Contractor 320 spec (25 mm objective lens)",
    },
    {
        "brand": "Hawke Optics",
        "label": "Hawke Frontier 30 SF 5-30x56 Riflescope",
        "recommended_height": 1.80,
        "keywords": {"hawke", "frontier", "30", "sf", "5", "30", "56"},
        "source": "Hawke Frontier 30 SF manual (56 mm objective lens)",
    },
    {
        "brand": "Hawke Optics",
        "label": "Hawke Sidewinder 30 4-16x50 Riflescope",
        "recommended_height": 1.70,
        "keywords": {"hawke", "sidewinder", "30", "4", "16", "50"},
        "source": "Hawke Sidewinder 30 spec (50 mm objective lens)",
    },
    {
        "brand": "Holosun",
        "label": "Holosun DRS-TH PRO Thermal Reflex Sight",
        "recommended_height": 1.54,
        "keywords": {"holosun", "drs", "th", "pro", "thermal"},
        "source": "Holosun DRS-TH PRO spec (1.54\" mount center)",
    },
    {
        "brand": "Holosun",
        "label": "Holosun DRS-TH Standard Thermal Reflex Sight",
        "recommended_height": 1.54,
        "keywords": {"holosun", "drs", "th", "thermal"},
        "source": "Holosun DRS-TH spec (1.54\" mount center)",
    },
    {
        "brand": "SIG Sauer",
        "label": "SIG Sauer ECHO3 2-12x Thermal Reflex Sight",
        "recommended_height": 1.54,
        "keywords": {"sig", "sauer", "echo3", "2", "12", "thermal"},
        "source": "SIG Sauer ECHO3 spec (integrated 1.54\" mount height)",
    },
    {
        "brand": "Burris Optics",
        "label": "Burris BTS 50 Thermal Riflescope",
        "recommended_height": 1.70,
        "keywords": {"burris", "bts", "50", "thermal"},
        "source": "Burris BTS 50 spec (50 mm objective lens)",
    },
]

_SCOPE_BRAND_CATALOG: dict[str, list[dict[str, Any]]] = {}
_SCOPE_BRAND_ERRORS: dict[str, str] = {}


def _make_soup(html: str) -> BeautifulSoup:
    for parser in ("lxml", "html.parser"):
        try:
            return BeautifulSoup(html, parser)
        except FeatureNotFound:
            continue
    return BeautifulSoup(html, "html.parser")


def _normalize_scope_label(text: str) -> str:
    if not text:
        return ""
    normalized = (
        text.replace("\u00ae", "")
        .replace("\u2122", "")
        .replace("\u2120", "")
        .replace("\xa0", " ")
    )
    return " ".join(normalized.split())


def _fetch_text(url: str, accept: str = "text/html") -> str:
    headers = DEFAULT_HTTP_HEADERS.copy()
    headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=12) as resp:
        data = resp.read()
        content_encoding = resp.headers.get("Content-Encoding", "")
        if "gzip" in content_encoding.lower():
            data = gzip.decompress(data)
        elif url.lower().endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except OSError:
                pass
    return data.decode("utf-8", errors="replace")


def _parse_mm_value(text: str | None) -> Optional[float]:
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)\s*mm", text.lower())
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _parse_inch_value(text: str | None) -> Optional[float]:
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None

def _value_to_mm(text: str | None) -> Optional[float]:
    mm_value = _parse_mm_value(text)
    if mm_value is not None:
        return mm_value
    inches = _parse_inch_value(text)
    if inches is not None:
        return round(inches * 25.4, 2)
    return None


def _estimate_height_from_objective(objective_mm: Optional[float], tube_mm: Optional[float]) -> Optional[float]:
    if not objective_mm:
        return None
    if objective_mm >= 56:
        height = 1.82
    elif objective_mm >= 52:
        height = 1.72
    elif objective_mm >= 48:
        height = 1.62
    elif objective_mm >= 40:
        height = 1.55
    else:
        height = 1.50
    if tube_mm and tube_mm >= 34:
        height += 0.03
    return round(height, 2)


def _fetch_vortex_catalog() -> list[dict[str, Any]]:
    html = _fetch_text("https://vortexoptics.com/optics/riflescopes.html")
    soup = _make_soup(html)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for card in soup.select("ol.products.list.items.product-items li.product-item"):
        link = card.select_one("a.product-item-link")
        if not link:
            continue
        label = _normalize_scope_label(link.get_text(" ", strip=True))
        href = link.get("href")
        if not label or not href or label in seen:
            continue
        seen.add(label)
        entries.append(
            {
                "label": label,
                "brand": "Vortex",
                "url": href,
                "source": href,
                "objective_mm": None,
                "tube_mm": None,
                "recommended_height": None,
                "error": None,
            }
        )
    return entries


def _extract_vortex_product_specs(html: str) -> dict[str, Any]:
    soup = _make_soup(html)
    for script in soup.find_all("script", {"type": "text/x-magento-init"}):
        text = script.string or script.get_text() or ""
        text = text.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        for value in payload.values():
            renderer = value.get("Magento_Swatches/js/swatch-renderer")
            if not renderer:
                continue
            cfg = renderer.get("jsonConfig") or {}
            details = cfg.get("productdetails") or {}
            for variant in details.values():
                specs = variant.get("specsFeatures", {}).get("specs", {})
                if not specs:
                    continue
                objective = specs.get("vx_objective_lens_diam", {}).get("value")
                tube = specs.get("vx_tube_size", {}).get("value")
                length = specs.get("vx_length", {}).get("value")
                return {
                    "objective_mm": _parse_mm_value(objective),
                    "tube_mm": _parse_mm_value(tube),
                    "length_in": _parse_inch_value(length),
                    "source": "Vortex manufacturer spec",
                }
    return {}


def _extract_leupold_product_specs(html: str) -> dict[str, Any]:
    soup = _make_soup(html)
    specs: dict[str, Any] = {"source": "Leupold manufacturer spec"}
    for row in soup.select("table tr"):
        header = row.find("th")
        value_cell = row.find("td")
        if not header or not value_cell:
            continue
        label = header.get_text(" ", strip=True).lower()
        value = value_cell.get_text(" ", strip=True)
        if not label or not value:
            continue
        if "objective" in label and "lens" in label:
            mm_value = _value_to_mm(value)
            if mm_value:
                specs["objective_mm"] = mm_value
        elif "maintube" in label or "main tube" in label or "tube diameter" in label:
            mm_value = _value_to_mm(value)
            if mm_value:
                specs["tube_mm"] = mm_value
        elif "overall length" in label:
            length_val = _parse_inch_value(value)
            if length_val:
                specs["length_in"] = length_val
    return specs


def _ensure_scope_model_detail(entry: dict[str, Any]) -> None:
    if entry.get("_detail_checked"):
        return
    entry["_detail_checked"] = True

    brand_key = _canonical_scope_brand_key(entry.get("brand"))
    parser = SCOPE_BRAND_DETAIL_LOADERS.get(brand_key)
    if not parser:
        return
    url = entry.get("url")
    if not url:
        entry["error"] = "Missing manufacturer URL."
        return
    try:
        html = _fetch_text(url)
        specs = parser(html)
        if not isinstance(specs, dict):
            specs = {}
        objective_mm = specs.get("objective_mm")
        tube_mm = specs.get("tube_mm")
        if objective_mm:
            entry["objective_mm"] = objective_mm
        if tube_mm:
            entry["tube_mm"] = tube_mm
        if specs.get("length_in"):
            entry["length_in"] = specs.get("length_in")
        existing_height = entry.get("recommended_height")
        recommended = _estimate_height_from_objective(entry.get("objective_mm"), entry.get("tube_mm"))
        if recommended is not None:
            entry["recommended_height"] = recommended
            if specs.get("source"):
                entry["source"] = specs["source"]
            entry.pop("error", None)
        elif existing_height is None:
            entry["error"] = specs.get("error") or "Manufacturer specs did not list an objective diameter."
    except Exception as exc:
        if not entry.get("recommended_height"):
            entry["error"] = str(exc)


def _ensure_scope_brand_catalog(brand: str) -> None:
    key = _canonical_scope_brand_key(brand)
    if not key or key == CUSTOM_SCOPE_BRAND.lower():
        return
    if key in _SCOPE_BRAND_CATALOG:
        return
    loader = SCOPE_BRAND_SOURCES.get(key, {}).get("loader")
    if not loader:
        _SCOPE_BRAND_CATALOG[key] = []
        return
    try:
        entries = loader()
        display = _brand_display_name_for_key(key, brand)
        for entry in entries:
            entry.setdefault("brand", display)
            entry.setdefault("source", entry.get("url"))
        _SCOPE_BRAND_CATALOG[key] = entries
        _SCOPE_BRAND_ERRORS.pop(key, None)
    except Exception as exc:
        _SCOPE_BRAND_CATALOG[key] = []
        _SCOPE_BRAND_ERRORS[key] = str(exc)


def _scope_brand_error(brand: str) -> Optional[str]:
    key = _canonical_scope_brand_key(brand)
    if not key:
        return None
    return _SCOPE_BRAND_ERRORS.get(key)


def _scope_catalog_entries(brand: str) -> list[dict[str, Any]]:
    key = _canonical_scope_brand_key(brand)
    if not key:
        return []
    return _SCOPE_BRAND_CATALOG.get(key, [])


def _find_scope_spec(brand: str, label: str, ensure_detail: bool = True) -> Optional[dict[str, Any]]:
    key = _canonical_scope_brand_key(brand)
    if key:
        _ensure_scope_brand_catalog(brand)
        for entry in _scope_catalog_entries(brand):
            if entry.get("label") == label:
                if ensure_detail:
                    _ensure_scope_model_detail(entry)
                if entry.get("recommended_height") or entry.get("error"):
                    return entry
                break
    brand_lower = (brand or "").lower()
    for spec in SCOPE_SPEC_PRESETS:
        if spec["label"] == label and spec.get("brand", "").lower() == brand_lower:
            return spec
    return None


def _extract_xml_locs(xml_text: str) -> list[str]:
    locs: list[str] = []
    try:
        root = ET.fromstring(xml_text)
        for elem in root.findall(".//{*}loc"):
            text = (elem.text or "").strip()
            if text:
                locs.append(text)
        return locs
    except Exception:
        pass
    return [match.strip() for match in re.findall(r"<loc>(.*?)</loc>", xml_text, flags=re.IGNORECASE | re.DOTALL)]


def _collect_sitemap_scope_urls(sitemap_url: str, include_keywords: list[str], max_urls: int = 40) -> list[str]:
    normalized_keywords = [kw.lower() for kw in include_keywords if kw]
    gathered: list[str] = []
    visited: set[str] = set()

    def _walk(url: str, depth: int) -> None:
        if depth > 3 or len(gathered) >= max_urls or not url or url in visited:
            return
        visited.add(url)
        try:
            xml_text = _fetch_text(url, accept="application/xml")
        except Exception:
            return
        locs = _extract_xml_locs(xml_text)
        is_index = bool(re.search(r"<\s*sitemapindex", xml_text, flags=re.IGNORECASE))
        if is_index:
            for child in locs:
                _walk(child, depth + 1)
                if len(gathered) >= max_urls:
                    break
            return
        for loc in locs:
            low = loc.lower()
            if normalized_keywords and not any(keyword in low for keyword in normalized_keywords):
                continue
            if loc not in gathered:
                gathered.append(loc)
                if len(gathered) >= max_urls:
                    break

    _walk(sitemap_url, 0)
    return gathered


def _slug_to_title(text: str) -> str:
    slug = (text or "").strip().strip("/").split("/")[-1]
    slug = slug.replace("-", " ")
    return _normalize_scope_label(slug)


def _scrape_scope_label_from_page(url: str) -> tuple[str | None, str | None]:
    try:
        html = _fetch_text(url)
    except Exception as exc:
        return None, str(exc)
    soup = _make_soup(html)
    title = soup.find("meta", attrs={"property": "og:title"})
    label = title["content"].strip() if title and title.get("content") else ""
    if not label and soup.title and soup.title.string:
        label = soup.title.string.strip()
    if not label:
        return None, "No title found"
    return _normalize_scope_label(label), None


def _build_scope_entry_from_page(brand_display: str, url: str) -> dict[str, Any]:
    label, error = _scrape_scope_label_from_page(url)
    if not label:
        label = _slug_to_title(url) or url
    entry = {
        "label": label,
        "brand": brand_display,
        "url": url,
        "source": url,
        "objective_mm": None,
        "tube_mm": None,
        "recommended_height": None,
        "error": error,
    }
    try:
        match = _infer_scope_height(label)
        if match:
            entry["label"] = match[0]
            entry["recommended_height"] = match[1]
            entry["source"] = match[2] or url
    except Exception:
        pass
    return entry


def _build_scope_entry_fallback(brand_display: str, url: str, error: Exception | str) -> dict[str, Any]:
    return {
        "label": _normalize_scope_label(_slug_to_title(url) or url),
        "brand": brand_display,
        "url": url,
        "source": url,
        "objective_mm": None,
        "tube_mm": None,
        "recommended_height": None,
        "error": str(error),
    }


def _make_sitemap_loader(
    brand_display: str,
    sitemap_url: str,
    include_keywords: list[str],
    max_urls: int = 40,
    filter_func: Optional[Callable[[dict[str, Any]], bool]] = None,
):
    def _loader() -> list[dict[str, Any]]:
        urls = _collect_sitemap_scope_urls(sitemap_url, include_keywords, max_urls=max_urls)
        entries: list[dict[str, Any]] = []
        seen_labels: set[str] = set()
        for url in urls:
            entry = _build_scope_entry_from_page(brand_display, url)
            label_norm = entry["label"].lower()
            if label_norm in seen_labels:
                continue
            seen_labels.add(label_norm)
            entries.append(entry)
        if filter_func:
            entries = [entry for entry in entries if filter_func(entry)]
        return entries

    return _loader


def _load_aimpoint_red_dot_catalog() -> list[dict[str, Any]]:
    base_url = "https://aimpoint.us/shop-products/red-dot-sights/"
    product_urls: set[str] = set()
    max_pages = 5
    for page in range(1, max_pages + 1):
        page_url = base_url if page == 1 else f"{base_url}?page={page}"
        try:
            html = _fetch_text(page_url)
        except Exception:
            if page == 1:
                raise
            break
        soup = _make_soup(html)
        cards = soup.select("article.card")
        if not cards:
            break
        added = 0
        for card in cards:
            link = card.select_one("h4.card-title a, h3.card-title a, h2.card-title a, a.card-title, a.card-title-link")
            if not link:
                link = card.select_one("a[href]")
            if not link:
                continue
            href = (link.get("href") or "").strip()
            if not href:
                continue
            absolute = urllib.parse.urljoin(base_url, href).split("?")[0].rstrip("/")
            if not absolute or absolute in product_urls:
                continue
            product_urls.add(absolute)
            added += 1
        if added == 0:
            break
    entries: list[dict[str, Any]] = []
    for url in sorted(product_urls):
        try:
            entry = _build_scope_entry_from_page("Aimpoint", url)
        except Exception as exc:
            entry = _build_scope_entry_fallback("Aimpoint", url, exc)
        entries.append(entry)
    return entries


def _load_primary_arms_red_dot_catalog() -> list[dict[str, Any]]:
    base_api = "https://www.primaryarms.com/api/items"
    limit = 24
    params = {
        "c": "3901023",
        "commercecategoryurl": "/red-dot-sights",
        "country": "US",
        "currency": "USD",
        "fieldset": "search",
        "include": "facets",
        "language": "en",
        "limit": str(limit),
        "matrixchilditems_fieldset": "matrixchilditems_mini",
        "n": "2",
        "pricelevel": "5",
        "sort": "custitem_ns_sc_ext_ts_365_amount:desc",
        "use_pcv": "F",
    }
    offset = 0
    total = None
    product_urls: set[str] = set()
    safety_max = 40
    while True:
        params["offset"] = str(offset)
        query = urllib.parse.urlencode(params)
        url = f"{base_api}?{query}"
        text = _fetch_text(url, accept="application/json")
        payload = json.loads(text)
        items = payload.get("items") or []
        if not items:
            break
        total = payload.get("total", total)
        for item in items:
            manufacturer = (item.get("manufacturer") or "").strip().lower()
            if manufacturer != "primary arms":
                continue
            slug = (item.get("urlcomponent") or "").strip().lstrip("/")
            if not slug:
                continue
            product_url = urllib.parse.urljoin("https://www.primaryarms.com/", slug)
            product_urls.add(product_url)
        offset += limit
        if (total is not None and offset >= total) or offset // limit >= safety_max:
            break
    entries: list[dict[str, Any]] = []
    for url in sorted(product_urls):
        try:
            entry = _build_scope_entry_from_page("Primary Arms", url)
        except Exception as exc:
            entry = _build_scope_entry_fallback("Primary Arms", url, exc)
        entries.append(entry)
    return entries


def _load_eotech_holographic_catalog() -> list[dict[str, Any]]:
    api_url = "https://www.eotechinc.com/products.json?limit=250"
    text = _fetch_text(api_url, accept="application/json")
    payload = json.loads(text)
    allowed_types = {"EXPS", "XPS", "HHS", "5x Series", "Pistol Optics"}
    handles: set[str] = set()
    for product in payload.get("products", []):
        product_type = (product.get("product_type") or "").strip()
        if product_type not in allowed_types:
            continue
        handle = (product.get("handle") or "").strip()
        if not handle:
            continue
        handles.add(handle)
    entries: list[dict[str, Any]] = []
    for handle in sorted(handles):
        url = urllib.parse.urljoin("https://www.eotechinc.com/", f"products/{handle}")
        try:
            entry = _build_scope_entry_from_page("EOTech", url)
        except Exception as exc:
            entry = _build_scope_entry_fallback("EOTech", url, exc)
        entries.append(entry)
    return entries


def _load_meprolight_optic_catalog() -> list[dict[str, Any]]:
    category_urls = [
        "https://www.meprolight.com/product_cat/optics/",
        "https://www.meprolight.com/product_cat/pistol-optics/",
    ]
    product_urls: set[str] = set()
    for category in category_urls:
        try:
            html = _fetch_text(category)
        except Exception:
            continue
        soup = _make_soup(html)
        for link in soup.select("ul.products li.product a.woocommerce-LoopProduct-link"):
            href = (link.get("href") or "").strip()
            if not href:
                continue
            absolute = urllib.parse.urljoin(category, href.split("#", 1)[0])
            if "/product/" not in absolute:
                continue
            label_text = _normalize_scope_label(link.get_text(" ", strip=True))
            label_lower = label_text.lower()
            if "magnifier" in label_lower or "display stand" in label_lower:
                continue
            product_urls.add(absolute)
    entries: list[dict[str, Any]] = []
    for url in sorted(product_urls):
        try:
            entry = _build_scope_entry_from_page("Meprolight", url)
        except Exception as exc:
            entry = _build_scope_entry_fallback("Meprolight", url, exc)
        entries.append(entry)
    return entries


def _load_cmore_red_dot_catalog() -> list[dict[str, Any]]:
    category_urls = [
        "https://cmore.com/Category/RTS3-Series",
        "https://cmore.com/Category/CRC",
        "https://cmore.com/Category/rts2",
        "https://cmore.com/Category/STS2",
        "https://cmore.com/Category/railway",
        "https://cmore.com/Category/slideride",
        "https://cmore.com/Category/serendipity",
        "https://cmore.com/Category/C3series",
    ]
    product_urls: set[str] = set()
    for category in category_urls:
        try:
            html = _fetch_text(category)
        except Exception:
            continue
        soup = _make_soup(html)
        for link in soup.select("a[href*='/Item/']"):
            href = (link.get("href") or "").strip()
            if not href:
                continue
            absolute = urllib.parse.urljoin(category, href.split("#", 1)[0])
            if "/Item/" not in absolute:
                continue
            label_text = _normalize_scope_label(link.get_text(" ", strip=True))
            label_lower = label_text.lower()
            if not label_lower or not any(keyword in label_lower for keyword in ("sight", "optic", "series")):
                continue
            product_urls.add(absolute)
    entries: list[dict[str, Any]] = []
    for url in sorted(product_urls):
        try:
            entry = _build_scope_entry_from_page("C-More Systems", url)
        except Exception as exc:
            entry = _build_scope_entry_fallback("C-More Systems", url, exc)
        entries.append(entry)
    return entries


def _make_unavailable_loader(message: str):
    def _loader() -> list[dict[str, Any]]:
        raise RuntimeError(message)

    return _loader


SCOPE_BRAND_SOURCES: dict[str, dict[str, Any]] = {
    "aimpoint": {
        "display": "Aimpoint",
        "aliases": ["aimpoint us", "aimpoint usa"],
        "loader": _load_aimpoint_red_dot_catalog,
    },
    "c-more systems": {
        "display": "C-More Systems",
        "aliases": ["c-more", "cmore", "c more"],
        "loader": _load_cmore_red_dot_catalog,
    },
    "eotech": {
        "display": "EOTech",
        "aliases": ["eotech holographic", "electro-optic technologies"],
        "loader": _load_eotech_holographic_catalog,
    },
    "meprolight": {
        "display": "Meprolight",
        "aliases": ["mepro light"],
        "loader": _load_meprolight_optic_catalog,
    },
    "primary arms": {
        "display": "Primary Arms",
        "aliases": ["primary arms optics"],
        "loader": _load_primary_arms_red_dot_catalog,
    },
    "vortex optics": {
        "display": "Vortex Optics",
        "aliases": ["vortex"],
        "loader": _fetch_vortex_catalog,
    },
    "leupold": {
        "display": "Leupold",
        "aliases": [],
        "loader": _make_sitemap_loader(
            "Leupold",
            "https://www.leupold.com/sitemap.xml",
            ["/riflescopes/", "-riflescope"],
            max_urls=80,
        ),
    },
    "nikon": {
        "display": "Nikon",
        "aliases": ["nikon sport optics", "nikon optics"],
        "loader": _make_unavailable_loader("Nikon discontinued factory riflescopes; catalog unavailable."),
    },
    "burris optics": {
        "display": "Burris Optics",
        "aliases": ["burris"],
        "loader": _make_sitemap_loader(
            "Burris Optics",
            "https://www.burrisoptics.com/sitemap.xml",
            ["/riflescope", "/riflescopes/"],
            max_urls=60,
        ),
    },
    "trijicon": {
        "display": "Trijicon",
        "aliases": [],
        "loader": _make_sitemap_loader(
            "Trijicon",
            "https://www.trijicon.com/sitemap.xml",
            ["/riflescope", "/riflescopes", "/products/product-categories/riflescopes"],
            max_urls=60,
        ),
    },
    "nightforce optics": {
        "display": "Nightforce Optics",
        "aliases": ["nightforce"],
        "loader": _make_sitemap_loader(
            "Nightforce Optics",
            "https://www.nightforceoptics.com/sitemap.xml",
            ["/riflescope", "/riflescopes"],
            max_urls=60,
        ),
    },
    "swarovski optik": {
        "display": "Swarovski Optik",
        "aliases": ["swarovski", "swarovski optics"],
        "loader": _make_sitemap_loader(
            "Swarovski Optik",
            "https://www.swarovskioptik.com/sitemap.xml",
            ["/riflescopes/"],
            max_urls=60,
        ),
    },
    "bushnell": {
        "display": "Bushnell",
        "aliases": ["bushnell optics"],
        "loader": _make_sitemap_loader(
            "Bushnell",
            "https://www.bushnell.com/sitemap.xml",
            ["/riflescopes/"],
            max_urls=60,
        ),
    },
    "zeiss": {
        "display": "ZEISS",
        "aliases": ["carl zeiss", "zeiss optics"],
        "loader": _make_sitemap_loader(
            "ZEISS",
            "https://www.zeiss.com/consumer-products/int/sitemap.xml",
            ["/riflescopes"],
            max_urls=60,
        ),
    },
    "sig sauer": {
        "display": "SIG Sauer",
        "aliases": ["sig"],
        "loader": _make_sitemap_loader(
            "SIG Sauer",
            "https://www.sigsauer.com/sitemap.xml",
            ["/riflescopes", "/electro-optics/riflescopes"],
            max_urls=60,
        ),
    },
    "firefield": {
        "display": "Firefield",
        "aliases": ["firefield optics"],
        "loader": _make_sitemap_loader(
            "Firefield",
            "https://firefield.com/sitemap.xml",
            ["https://firefield.com/products/", "https://firefield.com/es/products/"],
            max_urls=200,
            filter_func=lambda entry: "riflescope" in (entry.get("url") or "").lower(),
        ),
    },
    "pulsar": {
        "display": "Pulsar",
        "aliases": [],
        "loader": None,
    },
    "atn corp": {
        "display": "ATN Corp",
        "aliases": ["atn"],
        "loader": None,
    },
    "agm global vision": {
        "display": "AGM Global Vision",
        "aliases": ["agm", "agm vision"],
        "loader": None,
    },
    "sightmark": {
        "display": "Sightmark",
        "aliases": [],
        "loader": None,
    },
    "iray usa": {
        "display": "iRay USA",
        "aliases": ["iray", "infiray", "infiray outdoor"],
        "loader": None,
    },
    "flir systems": {
        "display": "FLIR Systems",
        "aliases": ["flir"],
        "loader": None,
    },
    "hawke optics": {
        "display": "Hawke Optics",
        "aliases": ["hawke"],
        "loader": None,
    },
    "armasight": {
        "display": "Armasight",
        "aliases": [],
        "loader": None,
    },
    "holosun": {
        "display": "Holosun",
        "aliases": [],
        "loader": None,
    },
}


def _load_marlin_lever_models() -> list[dict[str, Any]]:
    base = "https://marlinfirearms.com"
    start_pages = [
        f"{base}/s/leverAction/",
        f"{base}/s/leverAction-SBLSeries/",
        f"{base}/s/leverAction-DarkSeries/",
        f"{base}/s/leverAction-ClassicSeries/",
        f"{base}/s/leverAction-TrapperSeries/",
        f"{base}/s/leverAction-GuideGunSeries/",
    ]
    model_urls: set[str] = set()
    for page in start_pages:
        try:
            html = _fetch_text(page)
        except Exception:
            continue
        soup = _make_soup(html)
        for tag in soup.select("a[href*='/s/model_']"):
            href = tag.get("href")
            if not href:
                continue
            absolute = urllib.parse.urljoin(page, href).split("#", 1)[0]
            model_urls.add(absolute)
    entries: list[dict[str, Any]] = []
    for url in sorted(model_urls):
        try:
            entry = _build_rifle_entry_from_url("Marlin Firearms", url)
        except Exception as exc:
            entry = {
                "brand": "Marlin Firearms",
                "label": _clean_rifle_label(_slug_to_title(url) or url),
                "url": url,
                "source": url,
                "error": str(exc),
            }
        entries.append(entry)
    return entries


def _load_rossi_lever_models() -> list[dict[str, Any]]:
    base = "https://rossiusa.com"
    seed_pages = [
        base,
        f"{base}/journal/rifles/",
    ]
    links: set[str] = set()
    for seed in seed_pages:
        try:
            html = _fetch_text(seed)
        except Exception:
            continue
        soup = _make_soup(html)
        for tag in soup.select("a[href*='/product/rifles/lever-action/']"):
            href = tag.get("href")
            if not href:
                continue
            absolute = urllib.parse.urljoin(seed, href).split("#", 1)[0]
            links.add(absolute)
    entries: list[dict[str, Any]] = []
    for url in sorted(links):
        try:
            entry = _build_rifle_entry_from_url("Rossi", url)
        except Exception as exc:
            entry = {
                "brand": "Rossi",
                "label": _clean_rifle_label(_slug_to_title(url) or url),
                "url": url,
                "source": url,
                "error": str(exc),
            }
        entries.append(entry)
    return entries


def _henry_lever_filter(entry: dict[str, Any]) -> bool:
    label = (entry.get("label") or "").lower()
    url = (entry.get("url") or "").lower()
    return "lever" in label or "lever" in url or "rifle" in label


def _clean_rifle_label(text: str | None) -> str:
    if not text:
        return ""
    normalized = _normalize_scope_label(text)
    normalized = (
        normalized.replace("\u2122", "")
        .replace("\u00ae", "")
        .replace("\u00a9", "")
        .replace("  ", " ")
    )
    return " ".join(normalized.split())


def _scrape_rifle_label_from_page(url: str) -> tuple[str | None, str | None]:
    label, error = _scrape_scope_label_from_page(url)
    if label:
        label = _clean_rifle_label(label)
    return label, error


def _build_rifle_entry_from_url(brand_display: str, url: str) -> dict[str, Any]:
    label, error = _scrape_rifle_label_from_page(url)
    if not label:
        label = _clean_rifle_label(_slug_to_title(url) or url)
    return {
        "brand": brand_display,
        "label": label,
        "url": url,
        "source": url,
        "error": error,
    }


def _make_rifle_sitemap_loader(
    brand_display: str,
    sitemap_url: str,
    include_keywords: list[str] | None = None,
    max_urls: int = 60,
    filter_func: Optional[Callable[[dict[str, Any]], bool]] = None,
):
    keywords = include_keywords or []

    def _loader() -> list[dict[str, Any]]:
        urls = _collect_sitemap_scope_urls(sitemap_url, keywords, max_urls=max_urls)
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for url in urls:
            trimmed = url.split("#", 1)[0]
            if trimmed in seen:
                continue
            seen.add(trimmed)
            try:
                entry = _build_rifle_entry_from_url(brand_display, trimmed)
            except Exception as exc:
                entry = {
                    "brand": brand_display,
                    "label": _clean_rifle_label(_slug_to_title(trimmed) or trimmed),
                    "url": trimmed,
                    "source": trimmed,
                    "error": str(exc),
                }
            if filter_func and not filter_func(entry):
                continue
            entries.append(entry)
        return entries

    return _loader


def _make_rifle_category_loader(
    brand_display: str,
    start_urls: list[str],
    link_filter: Callable[[str], bool],
    max_links: int = 60,
):
    normalized_starts = [url.strip() for url in start_urls if url]

    def _loader() -> list[dict[str, Any]]:
        gathered: set[str] = set()
        for seed in normalized_starts:
            try:
                html = _fetch_text(seed)
            except Exception:
                continue
            soup = _make_soup(html)
            for tag in soup.select("a[href]"):
                href = tag.get("href")
                if not href:
                    continue
                absolute = urllib.parse.urljoin(seed, href)
                absolute = absolute.split("#", 1)[0]
                if not link_filter(absolute):
                    continue
                gathered.add(absolute)
                if len(gathered) >= max_links:
                    break
            if len(gathered) >= max_links:
                break
        entries: list[dict[str, Any]] = []
        for url in sorted(gathered):
            try:
                entry = _build_rifle_entry_from_url(brand_display, url)
            except Exception as exc:
                entry = {
                    "brand": brand_display,
                    "label": _clean_rifle_label(_slug_to_title(url) or url),
                    "url": url,
                    "source": url,
                    "error": str(exc),
                }
            entries.append(entry)
        return entries

    return _loader


LEVER_RIFLE_SOURCES: dict[str, dict[str, Any]] = {
    "winchester": {
        "display": "Winchester",
        "aliases": ["winchester repeating arms"],
        "loader": _make_rifle_sitemap_loader(
            "Winchester",
            "https://www.winchesterguns.com/sitemap.xml",
            [
                "/products/rifles/model-94",
                "/products/rifles/model-1892",
                "/products/rifles/model-1895",
                "/products/rifles/model-1886",
                "/products/rifles/model-1873",
                "/products/rifles/model-9422",
                "/products/discontinued/rifles/model-94",
                "/products/discontinued/rifles/model-1892",
                "/products/discontinued/rifles/model-1895",
                "/products/discontinued/rifles/model-1886",
            ],
            max_urls=180,
        ),
    },
    "marlin firearms": {
        "display": "Marlin Firearms",
        "aliases": ["marlin"],
        "loader": _load_marlin_lever_models,
    },
    "henry repeating arms": {
        "display": "Henry Repeating Arms",
        "aliases": ["henry"],
        "loader": _make_rifle_sitemap_loader(
            "Henry Repeating Arms",
            "https://www.henryusa.com/firearm-sitemap.xml",
            ["/firearm/"],
            max_urls=200,
            filter_func=_henry_lever_filter,
        ),
    },
    "rossi": {
        "display": "Rossi",
        "aliases": ["rossi usa"],
        "loader": _load_rossi_lever_models,
    },
    "uberti usa": {
        "display": "Uberti USA",
        "aliases": ["uberti"],
        "loader": _make_rifle_category_loader(
            "Uberti USA",
            ["https://www.uberti-usa.com/cartridge-rifles"],
            lambda url: "/cartridge-rifles/" in url,
        ),
    },
    "browning lever": {
        "display": "Browning (Lever)",
        "aliases": ["browning lever action"],
        "loader": _make_rifle_sitemap_loader(
            "Browning",
            "https://www.browning.com/sitemap.xml",
            ["/products/firearms/rifles/lever-action/"],
            max_urls=120,
        ),
    },
}


def _make_generic_bolt_loader(
    brand_display: str,
    sitemap_urls: list[str],
    include_keywords: list[str],
    max_urls: int = 120,
):
    def _loader() -> list[dict[str, Any]]:
        gathered_urls: list[str] = []
        for sitemap in sitemap_urls:
            try:
                gathered_urls.extend(_collect_sitemap_scope_urls(sitemap, include_keywords, max_urls=max_urls))
            except Exception:
                continue
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for url in gathered_urls:
            trimmed = url.split("#", 1)[0]
            if trimmed in seen:
                continue
            seen.add(trimmed)
            try:
                entry = _build_rifle_entry_from_url(brand_display, trimmed)
            except Exception as exc:
                entry = {
                    "brand": brand_display,
                    "label": _clean_rifle_label(_slug_to_title(trimmed) or trimmed),
                    "url": trimmed,
                    "source": trimmed,
                    "error": str(exc),
                }
            entries.append(entry)
        return entries

    return _loader


BOLT_RIFLE_SOURCES: dict[str, dict[str, Any]] = {
    "remington": {
        "display": "Remington",
        "aliases": ["remarms"],
        "loader": _make_rifle_sitemap_loader(
            "Remington",
            "https://www.remarms.com/sitemap.xml",
            ["/rifles/bolt-action/"],
            max_urls=160,
        ),
    },
    "savage arms": {
        "display": "Savage Arms",
        "aliases": ["savage"],
        "loader": _make_rifle_category_loader(
            "Savage Arms",
            ["https://www.savagearms.com/"],
            lambda url: "/firearms/rifles/" in url,
        ),
    },
    "tikka": {
        "display": "Tikka",
        "aliases": [],
        "loader": _make_rifle_sitemap_loader(
            "Tikka",
            "https://www.tikka.fi/en/sitemap.xml",
            ["/rifle", "/products/"],
            max_urls=120,
        ),
    },
    "browning bolt": {
        "display": "Browning",
        "aliases": ["browning bolt"],
        "loader": _make_rifle_sitemap_loader(
            "Browning",
            "https://www.browning.com/sitemap.xml",
            ["/products/firearms/rifles/bolt-action/"],
            max_urls=160,
        ),
    },
    "weatherby": {
        "display": "Weatherby",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Weatherby",
            ["https://weatherby.com/sitemap_index.xml"],
            ["/store/mark-v", "/store/vanguard"],
        ),
    },
    "ruger": {
        "display": "Ruger",
        "aliases": ["sturm ruger"],
        "loader": _make_generic_bolt_loader(
            "Ruger",
            ["https://ruger.com/sitemap.xml"],
            ["/products/precisionRifle", "/products/americanRifle", "/products/hawkeye"],
        ),
    },
    "winchester bolt": {
        "display": "Winchester",
        "aliases": ["winchester bolt"],
        "loader": _make_rifle_sitemap_loader(
            "Winchester",
            "https://www.winchesterguns.com/sitemap.xml",
            ["/products/rifles/model-70", "/products/rifles/xpr"],
            max_urls=160,
        ),
    },
    "cz": {
        "display": "CZ (Česká zbrojovka)",
        "aliases": ["cz-usa", "cz usa"],
        "loader": _make_generic_bolt_loader(
            "CZ (Česká zbrojovka)",
            ["https://cz-usa.com/sitemap_index.xml"],
            ["/product", "/rifle"],
        ),
    },
    "nightforce": {
        "display": "Nightforce",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Nightforce",
            ["https://www.nightforceoptics.com/sitemap.xml"],
            ["/products/", "/rifle"],
            max_urls=80,
        ),
    },
    "blaser": {
        "display": "Blaser",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Blaser",
            ["https://www.blaser.de/en/sitemap.xml"],
            ["/hunting-rifles", "/rifle"],
        ),
    },
    "sako": {
        "display": "Sako",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Sako",
            ["https://www.sako.fi/en/sitemap.xml"],
            ["/rifle", "/product"],
        ),
    },
    "steyr": {
        "display": "Steyr",
        "aliases": ["steyr arms"],
        "loader": _make_generic_bolt_loader(
            "Steyr",
            ["https://www.steyr-arms.com/us/sitemap_index.xml"],
            ["/us/product/"],
        ),
    },
    "christensen arms": {
        "display": "Christensen Arms",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Christensen Arms",
            ["https://christensenarms.com/page-sitemap.xml", "https://christensenarms.com/post-sitemap.xml"],
            ["/product/"],
        ),
    },
    "proof research": {
        "display": "Proof Research",
        "aliases": [],
        "loader": _make_generic_bolt_loader(
            "Proof Research",
            ["https://proofresearch.com/sitemap_index.xml"],
            ["/rifle", "/product"],
        ),
    },
    "xlr industries": {
        "display": "XLR Industries",
        "aliases": ["xlr"],
        "loader": _make_generic_bolt_loader(
            "XLR Industries",
            ["https://xlrindustries.com/sitemap.xml"],
            ["/product", "/rifle"],
            max_urls=80,
        ),
    },
}


SEMI_AUTO_RIFLE_SOURCES: dict[str, dict[str, Any]] = {
    "colt": {
        "display": "Colt",
        "aliases": [],
        "loader": _make_rifle_sitemap_loader(
            "Colt",
            "https://www.colt.com/sitemap.xml",
            ["/product-category/commercial/rifles", "/product-category/commercial/carbines", "/msr"],
            max_urls=160,
        ),
    },
    "smith & wesson": {
        "display": "Smith & Wesson",
        "aliases": ["smith and wesson", "s&w"],
        "loader": _make_rifle_sitemap_loader(
            "Smith & Wesson",
            "https://www.smith-wesson.com/sitemap.xml",
            ["/firearms/rifles", "/product/m-p15", "/product/mp-15", "/firearms/modern-sporting-rifles"],
            max_urls=160,
        ),
    },
    "ruger semi-auto": {
        "display": "Ruger",
        "aliases": ["ruger semi", "ruger ar"],
        "loader": _make_generic_bolt_loader(
            "Ruger",
            ["https://ruger.com/sitemap.xml"],
            ["/products/ar", "/products/mini", "/products/sfarr"],
        ),
    },
    "sig sauer rifles": {
        "display": "SIG Sauer",
        "aliases": ["sig sauer", "sig"],
        "loader": _make_rifle_sitemap_loader(
            "SIG Sauer",
            "https://www.sigsauer.com/sitemap.xml",
            ["/rifles", "/tread", "/mcx", "/spear"],
            max_urls=160,
        ),
    },
    "fn herstal": {
        "display": "FN Herstal",
        "aliases": ["fn", "fn america", "fn usa"],
        "loader": _make_generic_bolt_loader(
            "FN Herstal",
            ["https://fnamerica.com/sitemap_index.xml"],
            ["/rifles", "/fn-15", "/scar", "/carbines"],
        ),
    },
    "springfield armory": {
        "display": "Springfield Armory",
        "aliases": ["springfield"],
        "loader": _make_generic_bolt_loader(
            "Springfield Armory",
            ["https://www.springfield-armory.com/sitemap_index.xml"],
            ["/saint", "/hellion", "/rifles"],
        ),
    },
    "bushmaster": {
        "display": "Bushmaster",
        "aliases": [],
        "loader": _make_rifle_sitemap_loader(
            "Bushmaster",
            "https://www.bushmaster.com/sitemap.xml",
            ["/firearms", "/product"],
            max_urls=120,
        ),
    },
    "benelli": {
        "display": "Benelli",
        "aliases": [],
        "loader": _make_rifle_sitemap_loader(
            "Benelli",
            "https://www.benelliusa.com/sitemap.xml",
            ["/rifle", "/rifles"],
            max_urls=120,
        ),
    },
    "iwi": {
        "display": "IWI (Israel Weapon Industries)",
        "aliases": ["iwi", "israel weapon industries"],
        "loader": _make_generic_bolt_loader(
            "IWI (Israel Weapon Industries)",
            ["https://iwi.us/sitemap_index.xml"],
            ["/firearms", "/tavor", "/galil", "/zion"],
        ),
    },
    "beretta": {
        "display": "Beretta",
        "aliases": [],
        "loader": _make_rifle_sitemap_loader(
            "Beretta",
            "https://www.beretta.com/en-us/sitemap.xml",
            ["/rifle", "/product"],
            max_urls=160,
        ),
    },
    "zastava arms": {
        "display": "Zastava Arms",
        "aliases": ["zastava"],
        "loader": _make_generic_bolt_loader(
            "Zastava Arms",
            ["https://zastavaarmsusa.com/sitemap_index.xml"],
            ["/product", "/zpap", "/m90", "/rifle"],
        ),
    },
    "ptr industries": {
        "display": "PTR Industries",
        "aliases": ["ptr"],
        "loader": _make_generic_bolt_loader(
            "PTR Industries",
            ["https://ptr-us.com/sitemap_index.xml"],
            ["/product", "/ptr"],
        ),
    },
    "browning semi-auto": {
        "display": "Browning",
        "aliases": ["browning semi"],
        "loader": _make_rifle_sitemap_loader(
            "Browning",
            "https://www.browning.com/sitemap.xml",
            ["/products/firearms/rifles/semi-auto"],
            max_urls=160,
        ),
    },
    "mossberg": {
        "display": "Mossberg",
        "aliases": [],
        "loader": _make_rifle_category_loader(
            "Mossberg",
            ["https://www.mossberg.com/"],
            lambda url: "/product/" in url and "rifle" in url,
        ),
    },
    "tikka semi": {
        "display": "Tikka",
        "aliases": ["tikka"],
        "loader": _make_generic_bolt_loader(
            "Tikka",
            ["https://www.tikka.fi/en/sitemap.xml"],
            ["/tikka-t3x", "/product"],
        ),
    },
    "savage arms semi": {
        "display": "Savage Arms",
        "aliases": ["savage"],
        "loader": _make_rifle_category_loader(
            "Savage Arms",
            ["https://www.savagearms.com/"],
            lambda url: "/firearms/rifles/" in url,
        ),
    },
    "kahr arms": {
        "display": "Kahr Arms",
        "aliases": ["kahr"],
        "loader": _make_generic_bolt_loader(
            "Kahr Arms",
            ["https://www.kahr.com/wp-sitemap.xml"],
            ["/product", "/rifle"],
            max_urls=80,
        ),
    },
}


RIFLE_CATEGORY_CONFIG = {
    "lever": {"label": "Lever-action", "sources": LEVER_RIFLE_SOURCES},
    "bolt": {"label": "Bolt-action", "sources": BOLT_RIFLE_SOURCES},
    "semi": {"label": "Semi-auto", "sources": SEMI_AUTO_RIFLE_SOURCES},
}

_RIFLE_CATALOGS: dict[str, dict[str, list[dict[str, Any]]]] = {
    key: {} for key in RIFLE_CATEGORY_CONFIG
}
_RIFLE_ERRORS: dict[str, dict[str, str]] = {
    key: {} for key in RIFLE_CATEGORY_CONFIG
}


def _rifle_category_labels() -> list[str]:
    return [meta["label"] for meta in RIFLE_CATEGORY_CONFIG.values()]


def _rifle_category_key_from_label(label: str) -> str | None:
    normalized = (label or "").strip().lower()
    for key, meta in RIFLE_CATEGORY_CONFIG.items():
        if normalized == meta["label"].lower():
            return key
    return None


def _rifle_sources_for_category(category: str) -> dict[str, dict[str, Any]]:
    return RIFLE_CATEGORY_CONFIG.get(category, {}).get("sources", {})


def _canonical_rifle_brand_key(category: str, name: str | None) -> str | None:
    if not name:
        return None
    normalized = name.strip().lower()
    sources = _rifle_sources_for_category(category)
    for key, meta in sources.items():
        if normalized == key:
            return key
        for alias in meta.get("aliases", []):
            if normalized == alias.lower():
                return key
    return normalized if normalized in sources else None


def _rifle_brands_for_category(category: str) -> list[str]:
    sources = _rifle_sources_for_category(category)
    names: set[str] = set()
    for meta in sources.values():
        display = meta.get("display")
        if display:
            names.add(display)
    return sorted(names)


def _rifle_brand_error(category: str, brand: str) -> Optional[str]:
    key = _canonical_rifle_brand_key(category, brand)
    if not key:
        return None
    errors = _RIFLE_ERRORS.get(category, {})
    return errors.get(key)


def _ensure_rifle_brand_catalog(category: str, brand: str) -> None:
    sources = _rifle_sources_for_category(category)
    key = _canonical_rifle_brand_key(category, brand)
    if not key or key not in sources:
        return
    cache = _RIFLE_CATALOGS.setdefault(category, {})
    errors = _RIFLE_ERRORS.setdefault(category, {})
    if key in cache:
        return
    loader = sources.get(key, {}).get("loader")
    if not loader:
        cache[key] = []
        errors[key] = "Automatic catalog unavailable."
        return
    try:
        entries = loader()
        cache[key] = entries
        errors.pop(key, None)
    except Exception as exc:
        cache[key] = []
        errors[key] = str(exc)


def _rifle_models_for_brand(category: str, brand: str) -> list[str]:
    key = _canonical_rifle_brand_key(category, brand)
    if not key:
        return []
    cache = _RIFLE_CATALOGS.get(category, {})
    return [entry.get("label") for entry in cache.get(key, []) if entry.get("label")]


def _find_rifle_entry(category: str, brand: str, label: str) -> Optional[dict[str, Any]]:
    key = _canonical_rifle_brand_key(category, brand)
    if not key:
        return None
    cache = _RIFLE_CATALOGS.get(category, {})
    for entry in cache.get(key, []):
        if entry.get("label") == label:
            return entry
    return None


SCOPE_BRAND_DETAIL_LOADERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "vortex optics": _extract_vortex_product_specs,
    "leupold": _extract_leupold_product_specs,
}


def _canonical_scope_brand_key(name: str | None) -> str | None:
    normalized = (name or "").strip().lower()
    if not normalized:
        return None
    for key, meta in SCOPE_BRAND_SOURCES.items():
        if normalized == key:
            return key
        for alias in meta.get("aliases", []):
            if normalized == alias.lower():
                return key
    return normalized


def _brand_display_name_for_key(key: str, fallback: str | None = None) -> str:
    meta = SCOPE_BRAND_SOURCES.get(key)
    if meta:
        display = meta.get("display")
        if display:
            return display
    return fallback or (key.title() if key else "")


def _brand_display_name(brand: str) -> str:
    key = _canonical_scope_brand_key(brand)
    return _brand_display_name_for_key(key, brand)

def _match_scope_preset(scope_text: str) -> tuple[str, float, str] | None:
    tokens = set(re.findall(r"[a-z0-9]+", scope_text.lower()))
    if not tokens:
        return None
    best_entry = None
    best_score = 0
    for spec in SCOPE_SPEC_PRESETS:
        score = len(tokens & spec["keywords"])
        if score > best_score:
            best_entry = spec
            best_score = score
    if not best_entry or best_score == 0:
        return None
    return best_entry["label"], float(best_entry["recommended_height"]), best_entry.get("source", "manufacturer data")


def _infer_scope_height(scope_text: str) -> tuple[str, float, str] | None:
    """
    Estimate a reasonable center height when a scope isn't in the preset list.
    Uses the objective diameter (mm) parsed from the text.
    """
    text = scope_text.lower()
    match = re.search(r"x\s*(\d{2,3})(?:\s*mm)?", text)
    if not match:
        match = re.search(r"(\d{2,3})\s*mm", text)
    if not match:
        return None
    try:
        objective_mm = float(match.group(1))
    except ValueError:
        return None
    if objective_mm >= 55:
        height = 1.80
    elif objective_mm >= 50:
        height = 1.70
    elif objective_mm >= 44:
        height = 1.60
    elif objective_mm >= 36:
        height = 1.55
    else:
        height = 1.50
    label = f"{scope_text.strip()} (objective {objective_mm:.0f} mm)"
    source = f"Estimated from {objective_mm:.0f} mm objective"
    return label, height, source


def _normalize_scope_lookup_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _guess_scope_brand_from_text(text: str) -> Optional[str]:
    lookup = _normalize_scope_lookup_text(text)
    if not lookup:
        return None
    best_brand: Optional[str] = None
    best_score = 0.0
    for brand in _scope_brands():
        if brand == CUSTOM_SCOPE_BRAND:
            continue
        brand_lower = brand.lower()
        if brand_lower in lookup:
            score = len(brand_lower)
            if score > best_score:
                best_brand = brand
                best_score = score
    if best_brand:
        return best_brand
    tokens = lookup.split()
    if tokens:
        first = tokens[0]
        for brand in _scope_brands():
            if brand == CUSTOM_SCOPE_BRAND:
                continue
            brand_lower = brand.lower()
            if brand_lower.startswith(first) or first.startswith(brand_lower):
                return brand
    return None


def _best_scope_label_match(brand: str, text: str) -> Optional[str]:
    lookup = _normalize_scope_lookup_text(text)
    if not lookup:
        return None
    models = _scope_models_for_brand(brand)
    if not models:
        return None
    best_label: Optional[str] = None
    best_score = 0.0
    for label in models:
        label_norm = _normalize_scope_lookup_text(label)
        score = difflib.SequenceMatcher(None, lookup, label_norm).ratio()
        if lookup in label_norm:
            score += 0.2
        if score > best_score:
            best_score = score
            best_label = label
    if best_score < 0.45:
        return None
    return best_label


def _lookup_scope_spec_from_text(text: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    query = text.strip()
    if not query:
        return None, "Describe the scope (brand + model) first."
    brand = _guess_scope_brand_from_text(query)
    reason: Optional[str] = None
    if brand:
        try:
            _ensure_scope_brand_catalog(brand)
            label = _best_scope_label_match(brand, query)
            if label:
                spec = _find_scope_spec(brand, label, ensure_detail=True)
                if spec and spec.get("recommended_height"):
                    return spec, None
                if spec and spec.get("error"):
                    reason = spec["error"]
                else:
                    reason = f"{brand} specs missing recommended height."
            else:
                reason = f"No {brand} model matches “{query}”."
        except Exception as exc:
            reason = f"{brand} catalog unavailable ({exc})"
    else:
        reason = "Could not detect the manufacturer—include the brand name."
    fallback = _infer_scope_height(query)
    if fallback:
        label, height, source = fallback
        return {"label": label, "recommended_height": height, "source": source}, reason
    return None, reason


def _ammo_manufacturers() -> list[str]:
    return sorted(MANUAL_AMMO_CATALOG.keys())


def _ammo_load_names(brand: str) -> list[str]:
    names: list[str] = []
    for entry in MANUAL_AMMO_CATALOG.get(brand, []):
        label = (entry.get("name") or "").strip()
        if label:
            names.append(label)
    return names


def _manual_ammo_entry(brand: str, load_name: str) -> Optional[dict[str, Any]]:
    for entry in MANUAL_AMMO_CATALOG.get(brand, []):
        if (entry.get("name") or "").strip() == load_name:
            return entry
    return None


def _scope_brands() -> list[str]:
    names: set[str] = set()
    for meta in SCOPE_BRAND_SOURCES.values():
        display = meta.get("display")
        if display:
            names.add(display)
    for spec in SCOPE_SPEC_PRESETS:
        spec_brand = spec.get("brand")
        if spec_brand:
            names.add(spec_brand)
    sorted_names = sorted(names)
    if CUSTOM_SCOPE_BRAND not in sorted_names:
        sorted_names.append(CUSTOM_SCOPE_BRAND)
    return sorted_names


def _scope_models_for_brand(brand: str) -> list[str]:
    seen: set[str] = set()
    labels: list[str] = []
    for entry in _scope_catalog_entries(brand):
        label = entry.get("label")
        if label and label not in seen:
            seen.add(label)
            labels.append(label)
    key = _canonical_scope_brand_key(brand)
    for spec in SCOPE_SPEC_PRESETS:
        spec_brand = spec.get("brand")
        spec_key = _canonical_scope_brand_key(spec_brand)
        if key and spec_key != key:
            continue
        if not key and (spec_brand or "").lower() != (brand or "").lower():
            continue
        label = spec["label"]
        if label not in seen:
            seen.add(label)
            labels.append(label)
    return labels


PDF_TEXT_REPLACEMENTS = {
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\u2212": "-",
    "\u00b7": "-",
    "\u2018": "'",
    "\u2019": "'",
    "\u201a": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u201e": '"',
    "\u2026": "...",
    "\u2122": "TM",
}


def _pdf_safe_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    for src, replacement in PDF_TEXT_REPLACEMENTS.items():
        text = text.replace(src, replacement)
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        return text.encode("latin-1", "ignore").decode("latin-1")


class SafeFPDF(FPDF):
    def cell(self, w=0, h=0, txt="", border=0, ln=0, align="", fill=False, link=""):
        return super().cell(w, h, _pdf_safe_text(txt), border, ln, align, fill, link)

    def multi_cell(self, w, h, txt="", border=0, align="J", fill=False):
        return super().multi_cell(w, h, _pdf_safe_text(txt), border, align, fill)

    def text(self, x, y, txt=""):
        return super().text(x, y, _pdf_safe_text(txt))

    def set_title(self, title, *args, **kwargs):
        return super().set_title(_pdf_safe_text(title), *args, **kwargs)

    def set_author(self, author, *args, **kwargs):
        return super().set_author(_pdf_safe_text(author), *args, **kwargs)


def _targets_only_path(pdf_path: Path) -> Path:
    return pdf_path.with_name(f"{pdf_path.stem}{TARGETS_ONLY_SUFFIX}")


def _ensure_targets_only_pdf(pdf_path: Path) -> Path | None:
    """
    Create a targets-only PDF for legacy files so we can print additional copies
    without repeating the instruction page.
    """
    targets_only = _targets_only_path(pdf_path)
    if targets_only.exists():
        return targets_only
    if PdfReader is None or PdfWriter is None:
        return None
    try:
        reader = PdfReader(str(pdf_path))
        if len(reader.pages) <= 1:
            return None
        writer = PdfWriter()
        writer.add_page(reader.pages[0])
        with targets_only.open("wb") as fh:
            writer.write(fh)
        return targets_only
    except Exception:
        try:
            if targets_only.exists():
                targets_only.unlink()
        except Exception:
            pass
        return None


def _is_targets_only_file(pdf_path: Path) -> bool:
    return pdf_path.name.endswith(TARGETS_ONLY_SUFFIX)


def _extension_path(pdf_path: Path) -> Path:
    return pdf_path.with_name(f"{pdf_path.stem}{EXTENSION_SUFFIX}")


def _is_extension_file(pdf_path: Path) -> bool:
    return pdf_path.name.endswith(EXTENSION_SUFFIX)


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
        result = {
            "temp_F": float(cur.get("temperature_2m")) if cur.get("temperature_2m") is not None else None,
            "wind_speed_mph": float(cur.get("wind_speed_10m")) if cur.get("wind_speed_10m") is not None else None,
            "wind_dir_deg": float(cur.get("wind_direction_10m")) if cur.get("wind_direction_10m") is not None else None,
            "wind_gust_mph": float(cur.get("wind_gusts_10m")) if cur.get("wind_gusts_10m") is not None else None,
            "source": "open-meteo",
        }
        WEATHER_CACHE.remember(lat, lon, result)
        return result

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
            result = {
                "temp_F": float(temp) if temp is not None else None,
                "wind_speed_mph": speed,
                "wind_dir_deg": float(direction) if direction is not None else None,
                "wind_gust_mph": gust,
                "source": "met.no",
            }
            WEATHER_CACHE.remember(lat, lon, result)
            return result
        except Exception:
            pass

    cached, age = WEATHER_CACHE.fetch(lat, lon)
    if cached:
        cached.setdefault("source", "cache")
        cached["stale_minutes"] = round((age or 0) / 60.0, 1)
        cached["stale"] = True
        return cached

    return {"temp_F": None, "wind_speed_mph": None, "wind_dir_deg": None, "wind_gust_mph": None, "source": "unavailable"}


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
                value = float(meters) * 3.28084
                ELEVATION_CACHE.remember(lat, lon, {"value": value})
                return value
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
                    value = float(meters) * 3.28084
                    ELEVATION_CACHE.remember(lat, lon, {"value": value})
                    return value
                except Exception:
                    return None
    cached, _age = ELEVATION_CACHE.fetch(lat, lon)
    if cached and cached.get("value") is not None:
        return cached.get("value")
    return None
def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _select_sample_indices(count: int, max_samples: int) -> list[int]:
    if count <= max_samples:
        return list(range(count))
    if max_samples < 2:
        return [0, count - 1]
    step = (count - 1) / (max_samples - 1)
    indices = sorted({round(i * step) for i in range(max_samples)})
    if indices[-1] != count - 1:
        indices[-1] = count - 1
    if indices[0] != 0:
        indices[0] = 0
    return indices


def sample_weather_along_path(path_points: list[dict[str, float]], max_samples: int = 10) -> dict:
    """
    Fetch weather/elevation for up to max_samples points along the path and return aggregated values.
    """
    if not path_points:
        raise ValueError("No path points available for weather sampling.")
    indices = _select_sample_indices(len(path_points), max_samples)
    temps: list[float] = []
    gusts: list[float] = []
    altitudes: list[float] = []
    wind_u = 0.0
    wind_v = 0.0
    wind_count = 0
    samples: list[dict[str, Any]] = []

    for idx in indices:
        point = path_points[idx]
        lat = point.get("lat")
        lon = point.get("lon")
        if lat is None or lon is None:
            continue
        weather = fetch_weather(lat, lon)
        elevation = fetch_elevation(lat, lon)
        sample = {
            "index": idx + 1,
            "lat": lat,
            "lon": lon,
            "temp_F": weather.get("temp_F"),
            "wind_speed_mph": weather.get("wind_speed_mph"),
            "wind_dir_deg": weather.get("wind_dir_deg"),
            "wind_gust_mph": weather.get("wind_gust_mph"),
            "altitude_ft": elevation,
        }
        samples.append(sample)
        if weather.get("temp_F") is not None:
            temps.append(weather["temp_F"])
        if weather.get("wind_gust_mph") is not None:
            gusts.append(weather["wind_gust_mph"])
        if weather.get("wind_speed_mph") is not None and weather.get("wind_dir_deg") is not None:
            speed = weather["wind_speed_mph"]
            direction = weather["wind_dir_deg"]
            rad = math.radians(direction)
            # Convert FROM-direction to vector components (meteorological convention).
            wind_u += -speed * math.sin(rad)
            wind_v += -speed * math.cos(rad)
            wind_count += 1
        if elevation is not None:
            altitudes.append(elevation)

    if not samples:
        raise RuntimeError("Weather services did not return data for any sampled points.")

    avg_temp = _mean(temps)
    avg_gust = _mean(gusts)
    avg_alt = _mean(altitudes)
    if wind_count:
        wind_u /= wind_count
        wind_v /= wind_count
        avg_speed = math.hypot(wind_u, wind_v)
        avg_dir = (math.degrees(math.atan2(-wind_u, -wind_v)) + 360.0) % 360.0
    else:
        avg_speed = None
        avg_dir = None

    return {
        "samples_requested": len(indices),
        "samples_with_weather": len([s for s in samples if s.get("temp_F") is not None or s.get("wind_speed_mph") is not None]),
        "temp_F": avg_temp,
        "wind_speed_mph": avg_speed,
        "wind_dir_deg": avg_dir,
        "wind_gust_mph": avg_gust,
        "altitude_ft": avg_alt,
        "details": samples,
    }


def bearing_to_cardinal(bearing: float | None) -> str:
    if bearing is None:
        return "-"
    bearing = bearing % 360.0
    best_label = "N"
    best_diff = 360.0
    for label, deg in CARDINAL_BEARINGS.items():
        diff = abs((deg - bearing + 180.0) % 360.0 - 180.0)
        if diff < best_diff:
            best_diff = diff
            best_label = label
    return best_label

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
                                 wind_speed: float = 0.0, wind_dir: float = 0.0, wind_gust: float = 0.0,
                                 scope_click_moa: float = 0.25, barrel_length: Optional[float] = None,
                                 twist_rate: Optional[float] = None, twist_note: Optional[str] = None):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    scope_click_moa = max(0.001, float(scope_click_moa))
    scope_click_label = f"{scope_click_moa:.3f}".rstrip("0").rstrip(".")
    colors = {
        50: (255, 0, 0),
        100: (0, 0, 255),
        200: (0, 150, 0),
        300: (255, 165, 0),
        400: (160, 0, 160),
    }
    column_top_mm = 70.0
    column_spacing_mm = 34.0
    margin_mm = 12.0

    def _render(
        distances_list: list[int],
        priority_note: Optional[str] = None,
        include_usage_page: bool = True,
    ):
        pdf = SafeFPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=False)
        pdf.set_title("Ballistic Sight-In Target")
        pdf.add_page()

        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"Ballistic Sight-In Target - {rifle}", ln=True, align="C")
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 6, f"Ammo: {ammo}", ln=True)
        pdf.cell(
            0,
            6,
            f"MV: {velocity} fps | BC(G1): {bc} | Sight Height: {sight_height} in | Zero: {zero_range} yd",
            ln=True,
        )
        pdf.cell(
            0,
            6,
            f"Temp: {temp} F | Altitude: {altitude} ft | Wind: {wind_speed:.1f} mph @ {wind_dir:.0f}\u00B0 (FROM) | Gust: {wind_gust:.1f} mph",
            ln=True,
        )
        line_parts = []
        if barrel_length is not None:
            line_parts.append(f"Barrel: {barrel_length:.2f} in")
        if twist_rate is not None:
            line_parts.append(f"Twist: 1:{twist_rate:.2f}\"")
        if line_parts:
            pdf.cell(0, 6, " | ".join(line_parts), ln=True)
        pdf.ln(3)

        distances = list(distances_list)
        column_indices = {distance: idx for idx, distance in enumerate(distances)}
        column_x_mm = pdf.w / 2.0
        page_bottom_limit = pdf.h - margin_mm

        ballistic_rows = build_ballistic_rows(distances, velocity, bc, sight_height, zero_range, temp, altitude)

        pdf.set_font("Arial", "B", 12)
        included_distances: list[int] = []
        excluded_distances: list[int] = []
        dot_layouts: list[tuple[int, float, float, float]] = []
        radius_map: dict[int, float] = {}

        for d in distances:
            row = ballistic_rows[d]
            idx = column_indices[d]
            if d == 50:
                diameter_mm = 1.5 * INCH_TO_MM
            else:
                base_diameter_mm = moa_diameter_mm(d, 1.0)
                diameter_mm = max(base_diameter_mm, 6.0)
            radius_mm = diameter_mm / 2.0
            cx = min(max(column_x_mm, margin_mm + radius_mm), pdf.w - margin_mm - radius_mm)
            cy = column_top_mm + idx * column_spacing_mm
            radius_map[d] = radius_mm
            if cy + radius_mm > page_bottom_limit:
                excluded_distances.append(d)
                continue
            dot_layouts.append((d, cx, cy, radius_mm))
            included_distances.append(d)

        if not included_distances:
            fallback = min(distances, key=lambda d: ballistic_rows[d]["drop_moa"])
            row = ballistic_rows[fallback]
            if fallback == 50:
                diameter_mm = 1.5 * INCH_TO_MM
            else:
                diameter_mm = max(moa_diameter_mm(fallback, 1.0), 6.0)
            radius_mm = diameter_mm / 2.0
            cx = min(max(column_x_mm, margin_mm + radius_mm), pdf.w - margin_mm - radius_mm)
            cy = min(
                max(column_top_mm + radius_mm, column_top_mm + column_indices[fallback] * column_spacing_mm),
                page_bottom_limit - radius_mm,
            )
            dot_layouts.append((fallback, cx, cy, radius_mm))
            included_distances.append(fallback)
            excluded_distances = [d for d in distances if d != fallback]
            radius_map[fallback] = radius_mm

        for d, cx, cy, radius_mm in dot_layouts:
            row = ballistic_rows[d]
            diameter_mm = radius_mm * 2.0
            r, g, b = colors.get(d, (120, 120, 120))
            pdf.set_fill_color(r, g, b)
            pdf.ellipse(cx - radius_mm, cy - radius_mm, diameter_mm, diameter_mm, style="F")
            pdf.set_draw_color(255, 255, 255)
            pdf.set_line_width(0.4)
            pdf.line(cx - radius_mm, cy, cx + radius_mm, cy)
            pdf.line(cx, cy - radius_mm, cx, cy + radius_mm)
            pdf.set_fill_color(0, 0, 0)
            pdf.ellipse(cx - 1.5, cy - 1.5, 3.0, 3.0, style="F")
            label = f"{d} yd | Hold {row['drop_moa']:.2f} MOA"
            pdf.set_xy(cx - radius_mm, cy + radius_mm + 2)
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(diameter_mm, 4.2, label, align="C")
            pdf.set_font("Arial", "B", 12)
        pdf.set_font("Arial", "B", 12)
        draw_alignment_hash_line(
            pdf,
            page_bottom_limit,
            margin_mm,
            "ALIGN: line this edge up with the top hash on the extension sheet for more yardages.",
        )

        if include_usage_page:
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
            pdf.multi_cell(
                0,
                5.5,
                f"The Clicks column converts those MOA holds into turret clicks using the scope click value you entered "
                f"({scope_click_label} MOA per click - many Vortex scopes use 0.25). Adjust the input if your scope uses a different step size.",
            )
            pdf.ln(2)
            if priority_note or excluded_distances:
                pdf.set_font("Arial", "I", 9)
                if priority_note:
                    pdf.multi_cell(0, 4.5, priority_note)
                if excluded_distances:
                    excluded_text = ", ".join(f"{d} yd" for d in excluded_distances)
                    pdf.multi_cell(
                        0,
                        4.5,
                        "Omitted from the printable column due to space constraints: "
                        f"{excluded_text}. Use the alignment sheet or re-run with shorter max distance if needed.",
                    )
                pdf.ln(1)

            headers = [
                "Yds",
                "Drop (in)",
                "Drop (MOA)",
                "Vel @ range (fps)",
                "TOF (sec)",
                "Angle (deg)",
                f"Clicks ({scope_click_label} MOA/click)",
            ]
            widths = [16, 28, 28, 34, 28, 28, 28]
            row_h = 6

            pdf.set_font("Arial", "B", 10)
            pdf.set_x(10)
            for header, w in zip(headers, widths):
                pdf.cell(w, row_h, header, border=1, align="C")
            pdf.ln(row_h)

            pdf.set_font("Arial", "", 10)
            for d in included_distances:
                row = ballistic_rows[d]
                clicks = row["drop_moa"] / scope_click_moa
                pdf.set_x(10)
                pdf.cell(widths[0], row_h, f"{d}", border=1, align="C")
                pdf.cell(widths[1], row_h, f"{row['drop']:.2f}", border=1, align="R")
                pdf.cell(widths[2], row_h, f"{row['drop_moa']:.2f}", border=1, align="R")
                pdf.cell(widths[3], row_h, f"{row['velocity']:.0f}", border=1, align="R")
                pdf.cell(widths[4], row_h, f"{row['tof']:.3f}", border=1, align="R")
                pdf.cell(widths[5], row_h, f"{row['angle']:.3f}", border=1, align="R")
                pdf.cell(widths[6], row_h, f"{clicks:.1f}", border=1, align="R")
                pdf.ln(row_h)

            pdf.ln(5)
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 6, "How to use the MOA dots", ln=True)
            pdf.set_font("Arial", "", 10)
            steps = [
                "Zero on the 50 yard dot (or whatever zero distance you entered). That dot is intentionally larger for easier confirmation.",
                "Keep aiming at the 50 yard dot while you dial the MOA/click value shown for the distance you are checking. "
                "The vertically stacked dots simply remind you of the order of distances.",
                "Print this target at 100% scale on US Letter / A4 paper so the subtensions remain accurate.",
                "If a dialed shot is consistently high/low, adjust your ballistic inputs (velocity, BC, sight height) and reprint.",
                "Optional: print the extension alignment sheet if additional distances exceed the first page. Align the gray hashes when taping pages.",
            ]
            for step in steps:
                pdf.multi_cell(0, 5, f"• {step}")

            pdf.ln(3)
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 6, "Per-distance quick reference", ln=True)
            pdf.set_font("Arial", "", 10)
            for d in included_distances:
                row = ballistic_rows[d]
                clicks = row["drop_moa"] / scope_click_moa
                pdf.multi_cell(
                    0,
                    5,
                    f"{d} yd dot: hold/dial {row['drop_moa']:.2f} MOA up "
                    f"({row['drop']:.2f} in of drop, MV {row['velocity']:.0f} fps, "
                    f"≈ {clicks:.1f} clicks @ {scope_click_label} MOA/click).",
                )

            if twist_note:
                pdf.ln(3)
                pdf.set_font("Arial", "I", 9)
                pdf.multi_cell(0, 4.5, twist_note)

        layout_info = {
            "column_indices": column_indices,
            "column_top_mm": column_top_mm,
            "column_spacing_mm": column_spacing_mm,
            "page_bottom_limit_mm": page_bottom_limit,
            "column_x_mm": column_x_mm,
            "margin_mm": margin_mm,
            "radius_map": radius_map,
        }
        return pdf, included_distances, excluded_distances, ballistic_rows, layout_info

    base_distances = [50, 100, 200, 300, 400]
    active_priority_note: Optional[str] = None
    active_distances: list[int] = base_distances
    pdf_obj, included_distances, excluded_distances, ballistic_rows, layout_info = _render(base_distances)
    if 400 in base_distances and 400 not in included_distances and 200 in base_distances:
        reduced_distances = [d for d in base_distances if d != 200]
        note = "Removed the 200 yd dot automatically to keep the 400 yd dot on the main page."
        alt_pdf, alt_included, alt_excluded, alt_rows, alt_layout = _render(reduced_distances, note)
        if 400 in alt_included:
            pdf_obj = alt_pdf
            included_distances = alt_included
            excluded_distances = alt_excluded
            ballistic_rows = alt_rows
            layout_info = alt_layout
            active_distances = reduced_distances
            active_priority_note = note

    pdf_obj.output(str(pdf_path))
    targets_only_pdf, *_ = _render(active_distances, active_priority_note, include_usage_page=False)
    targets_only_path = _targets_only_path(pdf_path)
    targets_only_pdf.output(str(targets_only_path))
    return included_distances, excluded_distances, ballistic_rows, layout_info


def generate_extension_sheet(extension_path: Path, rifle: str, ammo: str, velocity: float, bc: float,
                             sight_height: float, zero_range: float, temp: float, altitude: float,
                             wind_speed: float, wind_dir: float, wind_gust: float, scope_click_moa: float,
                             ballistic_rows: dict[int, dict[str, float]], included_distances: list[int],
                             excluded_distances: list[int], layout_info: dict[str, Any]) -> bool:
    if not excluded_distances:
        return False

    pdf = SafeFPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()
    pdf.set_title("Ballistic Target Extension Sheet")

    margin_mm = layout_info.get("margin_mm", 12.0)
    column_indices = layout_info.get("column_indices", {})
    column_top_mm = layout_info.get("column_top_mm", 70.0)
    column_spacing_mm = layout_info.get("column_spacing_mm", 34.0)
    page_bottom_limit_mm = layout_info.get("page_bottom_limit_mm", pdf.h - margin_mm)
    column_x_mm = layout_info.get("column_x_mm", pdf.w / 2.0)
    radius_map: dict[int, float] = layout_info.get("radius_map", {})

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Extension Alignment Sheet", ln=True, align="C")
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(
        0,
        5,
        "Slide this sheet beneath the main target so the gray ALIGN hashes touch. "
        "Keep aiming at the 50 yard dot while dialing the elevation listed for the distance you are confirming.",
    )
    pdf.ln(2)

    top_hash_y = 35.0
    bottom_hash_y = pdf.h - margin_mm
    draw_alignment_hash_line(pdf, top_hash_y, margin_mm, "ALIGN: match this hash to the bottom hash on the target page.")

    dot_colors = {
        50: (255, 0, 0),
        100: (0, 0, 255),
        200: (0, 150, 0),
        300: (255, 165, 0),
        400: (160, 0, 160),
    }
    still_omitted: list[int] = []

    for distance in excluded_distances:
        row = ballistic_rows.get(distance)
        if not row:
            continue
        idx = column_indices.get(distance)
        if idx is None:
            idx = len(included_distances)
        absolute_cy = column_top_mm + idx * column_spacing_mm
        offset_from_bottom = absolute_cy - page_bottom_limit_mm
        radius_mm = radius_map.get(distance, max(moa_diameter_mm(distance, 1.0), 8.0))
        cy = top_hash_y + offset_from_bottom
        if cy + radius_mm > bottom_hash_y - 6.0:
            still_omitted.append(distance)
            continue

        r, g, b = dot_colors.get(distance, (120, 120, 120))
        pdf.set_fill_color(r, g, b)
        pdf.ellipse(column_x_mm - radius_mm, cy - radius_mm, radius_mm * 2.0, radius_mm * 2.0, style="F")
        pdf.set_draw_color(255, 255, 255)
        pdf.set_line_width(0.4)
        pdf.line(column_x_mm - radius_mm, cy, column_x_mm + radius_mm, cy)
        pdf.line(column_x_mm, cy - radius_mm, column_x_mm, cy + radius_mm)
        pdf.set_fill_color(0, 0, 0)
        pdf.ellipse(column_x_mm - 1.5, cy - 1.5, 3.0, 3.0, style="F")

        pdf.set_font("Arial", "", 10)
        pdf.set_xy(column_x_mm - 35, cy + radius_mm + 2)
        pdf.multi_cell(
            70,
            5,
            f"{distance} yd | Hold/Dial {row['drop_moa']:.2f} MOA ({row['drop']:.2f} in)",
            align="C",
        )

    draw_alignment_hash_line(
        pdf,
        bottom_hash_y,
        margin_mm,
        "ALIGN: line this up with the top hash if you need another extension sheet.",
    )

    if still_omitted:
        pdf.set_text_color(180, 60, 60)
        pdf.multi_cell(
            0,
            5,
            "Some distances still exceed the extension sheet span: "
            + ", ".join(f"{d} yd" for d in still_omitted)
            + ". Reduce the zero range or request another extension.",
        )
        pdf.set_text_color(0, 0, 0)

    pdf.output(str(extension_path))
    return True


def draw_alignment_hash_line(pdf: FPDF, y_mm: float, margin_mm: float, label: str) -> None:
    pdf.set_draw_color(140, 140, 140)
    pdf.set_line_width(0.6)
    pdf.line(margin_mm, y_mm, pdf.w - margin_mm, y_mm)

    pdf.set_font("Arial", "I", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.text(margin_mm, y_mm - 2, label)

    hash_spacing_mm = 18.0
    hash_height_mm = 6.0
    x_positions = [margin_mm + 5, pdf.w / 2.0, pdf.w - margin_mm - 5]
    for x in x_positions:
        pdf.line(x, y_mm - hash_height_mm / 2.0, x, y_mm + hash_height_mm / 2.0)
    current = margin_mm + hash_spacing_mm
    while current < pdf.w - margin_mm:
        pdf.line(current, y_mm - hash_height_mm / 2.0, current, y_mm + hash_height_mm / 2.0)
        current += hash_spacing_mm
    pdf.set_text_color(0, 0, 0)

def _to_float(s: str, field_name: str) -> float:
    try:
        return float(s.strip())
    except Exception:
        raise ValueError(f"{field_name} must be a number.")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BallisticTarget - One Page PDF Target")
        self.geometry("1400x1050")
        self.minsize(1100, 880)
        self.resizable(True, True)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Menu
        menubar = tk.Menu(self)
        tools = tk.Menu(menubar, tearoff=0)
        tools.add_command(label='Environmentals + Geo', command=self.on_open_env_geo)
        tools.add_command(label='Mission Planner', command=self.on_open_mission_planner)
        menubar.add_cascade(label='Tools', menu=tools)
        self.config(menu=menubar)
        pad = {"padx": 10, "pady": 6}
        self.vars = {
            "rifle": tk.StringVar(value=""),
            "rifle_brand": tk.StringVar(value=""),
            "rifle_model": tk.StringVar(value=""),
            "ammo": tk.StringVar(value=""),
            "velocity": tk.StringVar(value=""),
            "bc": tk.StringVar(value=""),
            "sight_height": tk.StringVar(value=""),
            "zero_range": tk.StringVar(value="50"),
            "barrel_length": tk.StringVar(value=""),
            "twist_rate": tk.StringVar(value=""),
            "scope_click": tk.StringVar(value="0.25"),
            "temp": tk.StringVar(value="59"),
            "altitude": tk.StringVar(value="0"),
            "wind_speed": tk.StringVar(value="0"),
            "wind_dir": tk.StringVar(value="0"),
            "wind_gust": tk.StringVar(value="0"),
            "use_env": tk.StringVar(value="1"),
        }
        self.ammo_manufacturer_var = tk.StringVar(value=AMMO_MANUFACTURER_PLACEHOLDER)
        self.ammo_load_var = tk.StringVar(value=AMMO_LOAD_PLACEHOLDER)
        self.ammo_brand_combo: ttk.Combobox | None = None
        self.ammo_load_combo: ttk.Combobox | None = None
        self.telemetry_logger = TELEMETRY_LOGGER
        self.telemetry_opt_var = tk.BooleanVar(value=self.telemetry_logger.enabled)
        self.api_health_summary = tk.StringVar(value="API feeds: initializing…")
        self._api_health_thread: threading.Thread | None = None
        self.target_choice = tk.StringVar(value="")
        self.target_lookup = {}
        self.platform_choice = tk.StringVar(value=SIGHT_PLATFORM_OPTIONS[0][0])
        self.mount_choice = tk.StringVar(value=MOUNT_CENTER_OPTIONS[0][0])
        self.custom_platform_value = tk.StringVar(value="")
        self.custom_mount_value = tk.StringVar(value="")
        self.status = tk.StringVar(value=f"Output: {OUTPUT_DIR}")
        self._sight_dialog_open = False
        self._rifle_picker_open = False
        self.after(50, lambda: self.state("zoomed"))

        window_controls = ttk.Frame(self)
        window_controls.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 2))
        window_controls.columnconfigure(0, weight=1)
        controls_row = ttk.Frame(window_controls)
        controls_row.grid(row=0, column=1, sticky="e")
        ttk.Button(controls_row, text="Minimize", command=self.iconify).grid(row=0, column=0, padx=4)
        ttk.Button(controls_row, text="Maximize", command=lambda: self.state("zoomed")).grid(row=0, column=1, padx=4)
        ttk.Button(controls_row, text="Restore", command=lambda: self.state("normal")).grid(row=0, column=2, padx=4)

        paned = ttk.Panedwindow(self, orient="horizontal")
        paned.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        left_column = ttk.Frame(paned)
        left_column.columnconfigure(0, weight=1)
        left_column.rowconfigure(1, weight=1)
        paned.add(left_column, weight=3)

        action_btns = ttk.Frame(left_column)
        action_btns.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(action_btns, text="Generate PDF Target", command=self.on_generate).grid(row=0, column=0, padx=4)
        ttk.Button(action_btns, text="Environmentals + Geo", command=self.on_open_env_geo).grid(row=0, column=1, padx=4)
        ttk.Button(action_btns, text="Projection Tool", command=self.on_open_projection_tool).grid(row=0, column=2, padx=4)
        ttk.Button(action_btns, text="Second Page Info", command=self.show_extension_info).grid(row=0, column=3, padx=4)
        ttk.Button(action_btns, text="Quit", command=self.destroy).grid(row=0, column=4, padx=4)
        ttk.Button(action_btns, text="Mission Planner", command=self.on_open_mission_planner).grid(row=0, column=5, padx=4)
        left_scroll_container = ttk.Frame(left_column)
        left_scroll_container.grid(row=1, column=0, sticky="nsew")
        left_scroll_container.columnconfigure(0, weight=1)
        left_scroll_container.rowconfigure(0, weight=1)

        canvas = tk.Canvas(left_scroll_container, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(left_scroll_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        frm = ttk.Frame(canvas)
        frm_window = canvas.create_window((0, 0), window=frm, anchor="nw")

        def _sync_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _expand_frame(event):
            canvas.itemconfigure(frm_window, width=event.width)

        frm.bind("<Configure>", _sync_scroll_region)
        canvas.bind("<Configure>", _expand_frame)

        def _on_mousewheel(event):
            delta = event.delta
            if delta == 0:
                return
            if sys.platform == "darwin":
                step = int(delta)
            else:
                step = int(delta / 120)
                if step == 0:
                    step = 1 if delta > 0 else -1
            canvas.yview_scroll(-step, "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel, add="+")
        canvas.bind_all("<Button-4>", lambda _e: canvas.yview_scroll(-1, "units"), add="+")
        canvas.bind_all("<Button-5>", lambda _e: canvas.yview_scroll(1, "units"), add="+")

        right_panel = ttk.Frame(paned, padding=10)
        right_panel.columnconfigure(0, weight=1)
        paned.add(right_panel, weight=2)

        print_box = ttk.Labelframe(right_panel, text="Print Targets")
        print_box.grid(row=0, column=0, sticky="ew")
        print_box.columnconfigure(0, weight=1)
        btn_row = ttk.Frame(print_box)
        btn_row.grid(row=0, column=0, sticky="ew", pady=(4, 8))
        btn_row.columnconfigure((0, 1, 2), weight=1)
        ttk.Button(btn_row, text="Print Newest Target", command=self.on_print_newest).grid(row=0, column=0, padx=4, sticky="ew")
        ttk.Button(btn_row, text="Print Selected Target", command=self.on_print_selected).grid(row=0, column=1, padx=4, sticky="ew")
        ttk.Button(btn_row, text="Open Targets Folder", command=self.on_open_targets_folder).grid(row=0, column=2, padx=4, sticky="ew")
        self.print_copies = tk.IntVar(value=1)
        self.copy_status = tk.StringVar(value="")
        copies_box = ttk.Labelframe(print_box, text="Print Copies")
        copies_box.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 6))
        ttk.Label(copies_box, textvariable=self.copy_status).grid(row=0, column=0, padx=8, pady=(6, 2))
        ttk.Button(copies_box, text="Choose...", command=self.prompt_print_copies).grid(row=1, column=0, padx=8, pady=(0, 8))
        self.target_combo = ttk.Combobox(
            print_box,
            textvariable=self.target_choice,
            width=42,
            state="readonly",
            postcommand=lambda: self.refresh_target_dropdown(select_newest=False),
        )
        self.target_combo.grid(row=2, column=0, padx=4, pady=(0, 6), sticky="ew")
        self.target_combo.bind("<<ComboboxSelected>>", self.on_target_selected)
        ttk.Label(print_box, textvariable=self.status).grid(row=3, column=0, sticky="w", padx=4, pady=(0, 4))
        ttk.Label(
            print_box,
            text="Need a PDF viewer? Install Adobe Acrobat Reader:\nhttps://get.adobe.com/reader/",
            foreground="#444",
            wraplength=260,
            justify="left",
        ).grid(row=4, column=0, sticky="w", padx=4, pady=(0, 6))

        data_box = ttk.Labelframe(right_panel, text="Data Feeds + Telemetry")
        data_box.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(
            data_box,
            textvariable=self.api_health_summary,
            wraplength=260,
            justify="left",
            foreground="#333",
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(6, 2))
        ttk.Checkbutton(
            data_box,
            text="Share anonymous telemetry to improve presets",
            variable=self.telemetry_opt_var,
            command=self._on_toggle_telemetry,
        ).grid(row=1, column=0, sticky="w", padx=4)
        ttk.Label(
            data_box,
            text="Telemetry hashes coarse map zones + ballistic context; no raw coordinates are stored.",
            foreground="#555",
            wraplength=260,
            justify="left",
        ).grid(row=2, column=0, sticky="w", padx=4, pady=(0, 6))

        sight_box = ttk.Labelframe(right_panel, text="Sight Height Presets")
        sight_box.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        sight_box.columnconfigure(0, weight=1)
        ttk.Label(
            sight_box,
            text="Pick your rifle base and mount style to auto-fill sight height or choose Custom to type your measurements.",
            wraplength=260,
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(6, 4))
        ttk.Label(sight_box, text="Rifle Base / Rail:").grid(row=1, column=0, sticky="w", padx=4)
        self.platform_combo = ttk.Combobox(
            sight_box,
            textvariable=self.platform_choice,
            state="readonly",
            width=32,
            values=[label for label, _ in SIGHT_PLATFORM_OPTIONS],
        )
        self.platform_combo.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        ttk.Label(sight_box, text="Custom base offset (in) for 'Custom' option:").grid(row=3, column=0, sticky="w", padx=4)
        self.custom_platform_entry = ttk.Entry(sight_box, textvariable=self.custom_platform_value, width=18)
        self.custom_platform_entry.grid(row=4, column=0, sticky="w", padx=4, pady=(0, 6))
        ttk.Label(sight_box, text="Scope Mount / Rings:").grid(row=5, column=0, sticky="w", padx=4)
        self.mount_combo = ttk.Combobox(
            sight_box,
            textvariable=self.mount_choice,
            state="readonly",
            width=32,
            values=[label for label, _ in MOUNT_CENTER_OPTIONS],
        )
        self.mount_combo.grid(row=6, column=0, sticky="ew", padx=4, pady=(0, 4))
        ttk.Label(sight_box, text="Custom mount center height (in) for 'Custom':").grid(row=7, column=0, sticky="w", padx=4)
        self.custom_mount_entry = ttk.Entry(sight_box, textvariable=self.custom_mount_value, width=18)
        self.custom_mount_entry.grid(row=8, column=0, sticky="w", padx=4, pady=(0, 6))
        ttk.Button(
            sight_box,
            text="Apply Preset Combination",
            command=self._on_sight_dropdown_change,
        ).grid(row=9, column=0, pady=(2, 8))

        self.platform_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_sight_dropdown_change())
        self.mount_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_sight_dropdown_change())
        self.custom_platform_entry.bind("<FocusOut>", lambda _e: self._on_sight_dropdown_change())
        self.custom_mount_entry.bind("<FocusOut>", lambda _e: self._on_sight_dropdown_change())
        self._on_sight_dropdown_change()

        row = 0
        ttk.Label(frm, text="Rifle Brand:").grid(row=row, column=0, sticky="e", **pad)
        rifle_brand_entry = ttk.Entry(frm, textvariable=self.vars["rifle_brand"], width=45)
        rifle_brand_entry.grid(row=row, column=1, **pad); row += 1

        ttk.Label(frm, text="Rifle Model:").grid(row=row, column=0, sticky="e", **pad)
        rifle_model_entry = ttk.Entry(frm, textvariable=self.vars["rifle_model"], width=45)
        rifle_model_entry.grid(row=row, column=1, **pad)
        ttk.Button(frm, text="Pick Rifle…", command=self.open_rifle_picker).grid(row=row, column=2, sticky="w", padx=(0, 4))
        row += 1
        ttk.Label(
            frm,
            text="Brand + model are combined for the web lookup (e.g., Brand=\"Palmetto State Armory\", Model=\"PA-10\").",
            foreground="#555",
        ).grid(row=row, column=1, sticky="w", padx=10, pady=(0, 4)); row += 1
        self.rifle_entry = rifle_model_entry

        ttk.Label(frm, text="Ammunition:").grid(row=row, column=0, sticky="e", **pad)
        ammo_entry = ttk.Entry(frm, textvariable=self.vars["ammo"], width=45)
        ammo_entry.grid(row=row, column=1, **pad); row += 1
        self.ammo_entry = ammo_entry
        ammo_picker = ttk.Frame(frm)
        ammo_picker.grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=(0, 4))
        ttk.Label(ammo_picker, text="Manufacturer presets:").grid(row=0, column=0, sticky="w")
        manufacturer_values = [AMMO_MANUFACTURER_PLACEHOLDER] + _ammo_manufacturers()
        self.ammo_brand_combo = ttk.Combobox(
            ammo_picker,
            textvariable=self.ammo_manufacturer_var,
            state="readonly",
            width=28,
            values=manufacturer_values,
        )
        self.ammo_brand_combo.grid(row=0, column=1, sticky="w", padx=(6, 0))
        self.ammo_brand_combo.current(0)
        ttk.Label(ammo_picker, text="Load:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.ammo_load_combo = ttk.Combobox(
            ammo_picker,
            textvariable=self.ammo_load_var,
            state="disabled",
            width=42,
            values=[AMMO_LOAD_PLACEHOLDER],
        )
        self.ammo_load_combo.grid(row=1, column=1, sticky="w", padx=(6, 0), pady=(4, 0))
        self.ammo_load_combo.current(0)
        self.ammo_brand_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_ammo_manufacturer_change())
        self.ammo_load_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_ammo_load_selected())
        row += 1

        ttk.Label(frm, text="Muzzle Velocity (fps):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["velocity"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Ballistic Coefficient (G1):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["bc"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Sight Height (in):").grid(row=row, column=0, sticky="e", **pad)
        self.sight_height_entry = ttk.Entry(frm, textvariable=self.vars["sight_height"], width=20)
        self.sight_height_entry.grid(row=row, column=1, sticky="w", **pad)
        ttk.Button(frm, text="Set Height…", command=self.open_sight_height_dialog).grid(row=row, column=2, sticky="w")
        row += 1
        ttk.Label(
            frm,
            text="Enter a known value or click “Set Height…” to pull manufacturer scope + mount data from the web.",
            foreground="#555",
        ).grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=(0, 4))
        row += 1

        ttk.Label(frm, text="Zero Range (yd):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["zero_range"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Barrel Length (in):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["barrel_length"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Twist Rate (e.g., 1:8):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["twist_rate"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Label(frm, text="Enter your barrel's actual twist (manual entry only).", foreground="#555")\
            .grid(row=row, column=1, sticky="w", padx=10, pady=(0, 4)); row += 1

        ttk.Label(frm, text="Scope Click Value (MOA/click):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["scope_click"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Label(frm, text="Example: 0.25 = 1/4 MOA per click (common on Vortex turrets).", foreground="#444")\
            .grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Temperature (F):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["temp"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Altitude (ft):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["altitude"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Wind Speed (mph):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["wind_speed"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Wind Dir (deg FROM):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["wind_dir"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Wind Gust (mph):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.vars["wind_gust"], width=20).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Label(
            frm,
            text="Use degrees indicating where the wind is coming FROM (0° = due north).",
            foreground="#555",
        ).grid(row=row, column=1, sticky="w", padx=10, pady=(0, 4)); row += 1

        # Environmentals + Geo import
        ttk.Checkbutton(frm, text="Use Environmentals (Temp/Altitude)", variable=self.vars["use_env"],
                        onvalue="1", offvalue="0").grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Button(frm, text="Load Temp/Alt from Geo tool", command=self.load_env_from_config).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Button(frm, text="Fetch Weather (Open-Meteo)", command=self.fetch_weather_from_api).grid(row=row, column=1, sticky="w", **pad); row += 1

        ttk.Label(frm, text="Tip: Turn OFF VPN for accurate Geo location before sharing a Maps link.", foreground="#444")\
            .grid(row=row, column=1, sticky="w", **pad); row += 1

        self.web_status = tk.StringVar(value="Web data: not fetched.")
        ttk.Button(frm, text="Pull Rifle + Ammo Web Data", command=self.on_pull_web_data).grid(row=row, column=1, sticky="w", **pad); row += 1
        ttk.Label(frm, textvariable=self.web_status, foreground="#444").grid(row=row, column=1, sticky="w", **pad); row += 1

        self._extension_summary = "Extension sheet status unknown. Generate a target to see if extra yardages need the add-on page."

        self._update_copy_display()
        self.refresh_target_dropdown(select_newest=True)
        self.web_auto_context: dict[str, Any] = {}
        self._web_data_stale = True
        self._auto_fetch_job: Optional[str] = None
        self._suppress_auto_fetch = False
        self.vars["rifle"].trace_add("write", self._on_weapon_field_change)
        self.vars["rifle_brand"].trace_add("write", self._on_rifle_parts_change)
        self.vars["rifle_model"].trace_add("write", self._on_rifle_parts_change)
        self.vars["ammo"].trace_add("write", self._on_weapon_field_change)
        rifle_brand_entry.bind("<FocusOut>", lambda _e: self._schedule_web_auto_fetch())
        rifle_model_entry.bind("<FocusOut>", lambda _e: self._schedule_web_auto_fetch())
        self.ammo_entry.bind("<FocusOut>", lambda _e: self._schedule_web_auto_fetch())
        try:
            self.after(2000, self._schedule_api_health_check)
        except Exception:
            self._schedule_api_health_check()

    def _list_saved_targets(self):
        try:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        targets = [
            p
            for p in OUTPUT_DIR.glob("*.pdf")
            if p.is_file() and not _is_targets_only_file(p) and not _is_extension_file(p)
        ]

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

    def _on_toggle_telemetry(self) -> None:
        enabled = bool(self.telemetry_opt_var.get())
        self.telemetry_logger.set_enabled(enabled)
        status = "Telemetry logging enabled." if enabled else "Telemetry logging disabled."
        self.status.set(status)

    def _record_telemetry(self, event: str, payload: dict[str, Any]) -> None:
        logger = getattr(self, "telemetry_logger", None)
        if not logger or not logger.enabled:
            return
        enriched = dict(payload)
        geo_cfg = load_env_from_geo_config()
        lat = _maybe_float(geo_cfg.get("lat"))
        lon = _maybe_float(geo_cfg.get("lon"))
        enriched.update(anonymize_location(lat, lon))
        enriched["telemetry_opt_in"] = True
        try:
            logger.log(event, enriched)
        except Exception:
            pass

    def _schedule_api_health_check(self) -> None:
        if self._api_health_thread and self._api_health_thread.is_alive():
            return
        def worker():
            statuses = run_api_health_checks()
            try:
                self.after(0, lambda: self._apply_api_health(statuses))
            except Exception:
                pass
        self._api_health_thread = threading.Thread(target=worker, daemon=True)
        self._api_health_thread.start()
        try:
            self.after(API_HEALTH_INTERVAL_SECONDS * 1000, self._schedule_api_health_check)
        except Exception:
            pass

    def _apply_api_health(self, statuses: list[dict[str, Any]]) -> None:
        if not statuses:
            self.api_health_summary.set("API feeds: not checked.")
            return
        lines: list[str] = []
        for status in statuses:
            badge = "[OK]" if status.get("ok") else "[!!]"
            line = f"{badge} {status.get('label', 'Unknown')}"
            latency = status.get("latency_ms")
            if latency is not None:
                line += f" ({latency} ms)"
            if not status.get("ok") and status.get("message"):
                line += f" - {status['message']}"
            lines.append(line)
        self.api_health_summary.set("\n".join(lines))

    def _on_sight_dropdown_change(self) -> None:
        self._update_sight_dropdown_state()
        self._refresh_sight_height_from_dropdown()

    def _update_sight_dropdown_state(self) -> None:
        platform_custom = self._option_requires_custom(SIGHT_PLATFORM_OPTIONS, self.platform_choice.get())
        mount_custom = self._option_requires_custom(MOUNT_CENTER_OPTIONS, self.mount_choice.get())
        state_platform = "normal" if platform_custom else "disabled"
        state_mount = "normal" if mount_custom else "disabled"
        self.custom_platform_entry.configure(state=state_platform)
        self.custom_mount_entry.configure(state=state_mount)
        if not platform_custom:
            self.custom_platform_value.set("")
        if not mount_custom:
            self.custom_mount_value.set("")

    def _option_requires_custom(self, options: list[tuple[str, float | None]], label: str) -> bool:
        for option_label, option_value in options:
            if option_label == label:
                return option_value is None
        return False

    def _resolve_dropdown_value(
        self,
        options: list[tuple[str, float | None]],
        label: str,
        custom_value: str,
    ) -> float | None:
        for option_label, option_value in options:
            if option_label == label:
                if option_value is not None:
                    return float(option_value)
                text = (custom_value or "").strip()
                if not text:
                    return None
                try:
                    return float(text)
                except ValueError:
                    return None
        return None

    def _refresh_sight_height_from_dropdown(self) -> None:
        base = self._resolve_dropdown_value(
            SIGHT_PLATFORM_OPTIONS,
            self.platform_choice.get(),
            self.custom_platform_value.get(),
        )
        mount = self._resolve_dropdown_value(
            MOUNT_CENTER_OPTIONS,
            self.mount_choice.get(),
            self.custom_mount_value.get(),
        )
        if base is None or mount is None:
            return
        total = base + mount
        self.vars["sight_height"].set(f"{total:.2f}")
        self.status.set(f"Sight height presets applied: {total:.2f} in.")

    def _parse_optional_length(self, text: str, field_name: str) -> Optional[float]:
        raw = (text or "").strip()
        if not raw:
            return None
        cleaned = raw.lower().replace("inches", "").replace("inch", "").replace("in", "").replace('"', "").strip()
        try:
            return float(cleaned)
        except ValueError:
            raise ValueError(f"{field_name} must be a number of inches.")

    def _parse_twist_value(self, text: str) -> Optional[float]:
        raw = (text or "").strip()
        if not raw:
            return None
        match = re.search(r"1\s*[:/]\s*(\d+(?:\.\d+)?)", raw)
        if match:
            return float(match.group(1))
        match = re.search(r"(\d+(?:\.\d+)?)", raw)
        if match:
            return float(match.group(1))
        raise ValueError('Twist Rate must look like "1:8" or a plain number of inches.')

    def _twist_note_for_pdf(self) -> Optional[str]:
        report = self.web_auto_context.get("twist_report") if hasattr(self, "web_auto_context") else None
        if report and getattr(report, "note", None):
            return report.note
        return None

    def _update_extension_summary(self, excluded_distances: list[int], extension_created: bool,
                                  extension_path: Path | None):
        if not excluded_distances:
            self._extension_summary = (
                "All requested distances fit on the first page. No extension sheet was needed."
            )
            return
        distances = ", ".join(f"{d} yd" for d in excluded_distances)
        if extension_created and extension_path:
            summary = (
                "Additional yardages requiring the alignment sheet: "
                f"{distances}.\n\nExtension PDF saved beside the main target as:\n{extension_path}"
            )
        else:
            summary = (
                "Additional yardages exceed the first page: "
                f"{distances}.\n\nExtension sheet was skipped. Re-run Generate and choose Yes if you need those dots."
            )
        self._extension_summary = summary

    def show_extension_info(self):
        messagebox.showinfo("Second Page Info", self._extension_summary)

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
        if copies <= 0:
            return
        if not target_path.exists():
            raise FileNotFoundError(f"Target file not found:\n{target_path}")

        targets_only_path = _targets_only_path(target_path)
        if copies > 1 and not targets_only_path.exists():
            created = _ensure_targets_only_pdf(target_path)
            if created:
                targets_only_path = created
        if copies == 1 or not targets_only_path.exists():
            self._send_print_job(target_path, copies=copies)
            return

        self._send_print_job(target_path, copies=1)
        remaining = copies - 1
        if remaining > 0:
            self._send_print_job(targets_only_path, copies=remaining)

    def _send_print_job(self, pdf_path: Path, copies: int = 1) -> None:
        if copies <= 0:
            return
        if not pdf_path.exists():
            raise FileNotFoundError(f"Target file not found:\n{pdf_path}")

        if sys.platform.startswith("win"):
            try:
                for _ in range(copies):
                    os.startfile(str(pdf_path), "print")
                return
            except OSError as exc:
                win_err = getattr(exc, "winerror", None)
                missing_viewer = win_err in {2, 1155}
                if missing_viewer:
                    try:
                        os.startfile(str(pdf_path))
                    except Exception:
                        pass
                    raise RuntimeError(
                        "Windows could not find a PDF viewer with a working Print command. "
                        "Install a reader (Edge, Acrobat, SumatraPDF, etc.) or set a default PDF app, "
                        "then print from the window that just opened."
                    ) from exc
                raise

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
        subprocess.run([print_cmd, *args, str(pdf_path)], check=True)

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
            if "wind_speed_mph" in cfg and "wind_speed" in self.vars:
                self.vars["wind_speed"].set(str(cfg["wind_speed_mph"]))
            if "wind_dir_deg" in cfg and "wind_dir" in self.vars:
                self.vars["wind_dir"].set(str(cfg["wind_dir_deg"]))
            if "wind_gust_mph" in cfg and "wind_gust" in self.vars:
                self.vars["wind_gust"].set(str(cfg["wind_gust_mph"]))

            # Ensure environmentals enabled
            if "use_env" in self.vars:
                self.vars["use_env"].set("1")

            messagebox.showinfo("Loaded", f"Loaded environmentals (temp/alt/wind) from:\n{cfg_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config:\n{e}")

    def apply_mission_from_planner(self, mission: dict[str, Any]) -> None:
        point_a = mission.get("point_a") or {}
        lat = point_a.get("lat")
        lon = point_a.get("lon")
        if lat is None or lon is None:
            messagebox.showerror("Mission Planner", "Mission preset is missing Point A coordinates.")
            return
        cfg = load_env_from_geo_config()
        cfg.update(
            {
                "map_provider": point_a.get("provider") or cfg.get("map_provider") or "Google Maps",
                "location_name": point_a.get("location_name") or cfg.get("location_name") or "",
                "lat": lat,
                "lon": lon,
                "target_lat": mission.get("point_b", {}).get("lat"),
                "target_lon": mission.get("point_b", {}).get("lon"),
                "range_to_target_yd": mission.get("range_yd"),
                "bearing_to_target_deg": mission.get("bearing_deg"),
                "path_points": mission.get("path_points"),
                "use_pins_only": mission.get("use_pins_only", False),
                "target_elev_ft": mission.get("target_elev_ft"),
            }
        )
        env = mission.get("environment") or {}
        for key in ("temp_F", "altitude_ft", "wind_speed_mph", "wind_dir_deg", "wind_gust_mph"):
            if env.get(key) is not None:
                cfg[key] = env.get(key)
        try:
            CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showwarning("Mission Planner", f"Applied mission but could not write config:\n{exc}")

        if env.get("temp_F") is not None:
            self.vars["temp"].set(f"{env['temp_F']:.1f}")
        if env.get("altitude_ft") is not None:
            self.vars["altitude"].set(f"{env['altitude_ft']:.0f}")
        if env.get("wind_speed_mph") is not None:
            self.vars["wind_speed"].set(f"{env['wind_speed_mph']:.1f}")
        if env.get("wind_dir_deg") is not None:
            self.vars["wind_dir"].set(f"{env['wind_dir_deg']:.0f}")
        if env.get("wind_gust_mph") is not None:
            self.vars["wind_gust"].set(f"{env['wind_gust_mph']:.1f}")
        self.vars["use_env"].set("1")
        self.status.set(f"Mission '{mission.get('name')}' applied from planner.")
        self._record_telemetry(
            "mission_applied",
            {
                "path_points": mission.get("path_points"),
                "range_yd": mission.get("range_yd"),
            },
        )

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
            source = weather.get("source") or "Weather API"
            freshness = "cached" if weather.get("stale") else "live"
            if weather.get("stale_minutes") is not None:
                freshness += f" (~{weather['stale_minutes']:.1f} min old)"
            messagebox.showinfo("Weather Updated", f"Updated via {source} ({freshness}): {', '.join(updated)}")
        else:
            if weather.get("stale"):
                messagebox.showwarning(
                    "Cached Weather",
                    "Live weather failed, applied cached values already in the fields.",
                )
            else:
                messagebox.showwarning("No data", "Weather providers did not return usable data.")

    def on_pull_web_data(self):
        self._fetch_and_apply_web_data(silent=False)

    def _fetch_and_apply_web_data(self, silent: bool = True) -> bool:
        rifle = self.vars["rifle"].get().strip()
        ammo = self.vars["ammo"].get().strip()
        if not rifle and not ammo:
            if not silent:
                messagebox.showwarning("Missing info", "Enter a rifle or ammunition description first.")
            return False
        self.status.set("Fetching rifle/ammo data...")
        self.update_idletasks()
        self._clear_auto_fetch_job()
        previous_guard = self._suppress_auto_fetch
        self._suppress_auto_fetch = True
        try:
            ammo_data: AmmoWebData | None = None
            rifle_data: RifleWebData | None = None
            ammo_error = None
            rifle_error = None
            if ammo:
                try:
                    ammo_data = fetch_ammo_data(ammo)
                except (urllib.error.URLError, ValueError) as exc:
                    ammo_error = str(exc)
            if rifle:
                try:
                    rifle_data = fetch_rifle_data(rifle)
                except (urllib.error.URLError, ValueError) as exc:
                    rifle_error = str(exc)
            if not ammo_data and not rifle_data:
                self.status.set("Error.")
                self.web_status.set("Web data fetch failed.")
                if not silent:
                    problems = []
                    if ammo_error:
                        problems.append(f"Ammunition lookup failed: {ammo_error}")
                    if rifle_error:
                        problems.append(f"Rifle lookup failed: {rifle_error}")
                    messagebox.showerror("Web Data Error", "\n".join(problems) or "No matching data found.")
                self._web_data_stale = True
                return False

            applied = []
            if ammo_data and ammo_data.muzzle_velocity_fps:
                self.vars["velocity"].set(f"{ammo_data.muzzle_velocity_fps:.0f}")
                applied.append(f"Velocity {ammo_data.muzzle_velocity_fps:.0f} fps")
            if ammo_data and ammo_data.bc_g1:
                self.vars["bc"].set(f"{ammo_data.bc_g1:.3f}")
                applied.append(f"BC {ammo_data.bc_g1:.3f}")

            barrel_current = self.vars["barrel_length"].get().strip()
            if rifle_data and rifle_data.barrel_length_in and not barrel_current:
                self.vars["barrel_length"].set(f"{rifle_data.barrel_length_in:.2f}")
                applied.append(f"Barrel {rifle_data.barrel_length_in:.2f}\" (web)")

            twist_current = self.vars["twist_rate"].get().strip()
            if rifle_data and rifle_data.twist_rate_in and not twist_current:
                twist_label = f"1:{rifle_data.twist_rate_in:.2f}".rstrip("0").rstrip(".")
                self.vars["twist_rate"].set(twist_label)
                applied.append(f"Twist {twist_label}\" (reference)")

            twist_report = None
            if ammo_data:
                twist_report = build_twist_report(
                    ammo_data,
                    rifle_data or RifleWebData(None, None, None),
                    ammo_data.muzzle_velocity_fps,
                )
            self.web_auto_context = {
                "ammo": ammo_data,
                "rifle": rifle_data if rifle_data else None,
                "twist_report": twist_report,
            }

            summary = []
            if ammo_data and ammo_data.velocity_source:
                summary.append(ammo_data.velocity_source)
            if ammo_data and ammo_data.bc_source:
                summary.append(ammo_data.bc_source)
            if rifle_data and rifle_data.source:
                summary.append(rifle_data.source)
            errors = []
            if ammo_error:
                errors.append(f"Ammunition lookup failed: {ammo_error}")
            if rifle_error:
                errors.append(f"Rifle lookup failed: {rifle_error}")
            if summary:
                self.web_status.set(" | ".join(summary))
            elif errors:
                self.web_status.set(" | ".join(errors))
            else:
                self.web_status.set("Web data refreshed.")
            self.status.set("Ready.")
            success = bool(ammo_data or rifle_data)
            self._web_data_stale = not success

            if not silent:
                detail_lines = []
                if applied:
                    detail_lines.append("Applied: " + ", ".join(applied))
                if twist_report and twist_report.note:
                    detail_lines.append(twist_report.note)
                if errors and not applied:
                    messagebox.showwarning("Web Data", "\n".join(errors))
                elif detail_lines:
                    messagebox.showinfo("Web Data", "\n".join(detail_lines))
                elif errors:
                    messagebox.showwarning("Web Data", "\n".join(errors))
                else:
                    messagebox.showwarning(
                        "Web Data",
                        "No matching web data was found for this combination. Try adjusting cartridge keywords.",
                    )
            return success
        finally:
            self._suppress_auto_fetch = previous_guard


    def _requires_auto_fill(self, value: str) -> bool:
        text = (value or "").strip()
        if not text:
            return True
        try:
            float(text)
            return False
        except ValueError:
            return True

    def _needs_web_data(self, velocity_text: str, bc_text: str) -> bool:
        if self._requires_auto_fill(velocity_text):
            return True
        if self._requires_auto_fill(bc_text):
            return True
        return False

    def open_sight_height_dialog(self):
        if self._sight_dialog_open:
            return
        self._sight_dialog_open = True
        try:
            dialog = SightHeightDialog(self)
            self.wait_window(dialog)
            if dialog.result is not None:
                self.vars["sight_height"].set(f"{dialog.result:.2f}")
                self.status.set(f"Sight height updated to {dialog.result:.2f} in (estimated).")
        except Exception as exc:
            messagebox.showerror("Sight Height", f"Failed to open wizard:\n{exc}")
        finally:
            self._sight_dialog_open = False

    def open_rifle_picker(self):
        if self._rifle_picker_open:
            return
        self._rifle_picker_open = True
        try:
            dialog = RiflePickerDialog(self)
            self.wait_window(dialog)
            if dialog.result:
                brand, model = dialog.result
                self.vars["rifle_brand"].set(brand)
                self.vars["rifle_model"].set(model)
                self.status.set(f"Selected {brand} {model} from manufacturer catalog.")
        except Exception as exc:
            messagebox.showerror("Rifle Picker", f"Unable to open catalog:\n{exc}")
        finally:
            self._rifle_picker_open = False

    def _clear_auto_fetch_job(self) -> None:
        if self._auto_fetch_job:
            try:
                self.after_cancel(self._auto_fetch_job)
            except Exception:
                pass
            self._auto_fetch_job = None

    def _on_rifle_parts_change(self, *_args):
        brand = self.vars.get("rifle_brand", tk.StringVar()).get().strip()
        model = self.vars.get("rifle_model", tk.StringVar()).get().strip()
        combined = f"{brand} {model}".strip()
        if combined != self.vars["rifle"].get().strip():
            self.vars["rifle"].set(combined)

    def _on_weapon_field_change(self, *_args):
        self._web_data_stale = True
        self.web_auto_context.clear()
        self.web_status.set("Web data: pending refresh for new rifle/ammo.")
        if not self._suppress_auto_fetch:
            self._schedule_web_auto_fetch()

    def _on_ammo_manufacturer_change(self):
        combo = self.ammo_load_combo
        if combo is None:
            return
        brand = self.ammo_manufacturer_var.get().strip()
        if not brand or brand == AMMO_MANUFACTURER_PLACEHOLDER:
            combo.configure(state="disabled", values=[AMMO_LOAD_PLACEHOLDER])
            self.ammo_load_var.set(AMMO_LOAD_PLACEHOLDER)
            return
        loads = _ammo_load_names(brand)
        if not loads:
            combo.configure(state="disabled", values=[AMMO_LOAD_PLACEHOLDER])
            self.ammo_load_var.set(AMMO_LOAD_PLACEHOLDER)
            return
        combo.configure(state="readonly", values=[AMMO_LOAD_PLACEHOLDER] + loads)
        self.ammo_load_var.set(AMMO_LOAD_PLACEHOLDER)

    def _on_ammo_load_selected(self):
        brand = self.ammo_manufacturer_var.get().strip()
        load_name = self.ammo_load_var.get().strip()
        if (
            not brand
            or brand == AMMO_MANUFACTURER_PLACEHOLDER
            or not load_name
            or load_name == AMMO_LOAD_PLACEHOLDER
        ):
            return
        entry = _manual_ammo_entry(brand, load_name)
        if not entry:
            self.status.set("Preset not available. Choose another load or type manually.")
            return
        self._apply_manual_ammo_entry(brand, entry)

    def _apply_manual_ammo_entry(self, brand: str, entry: dict[str, Any]) -> None:
        previous_guard = self._suppress_auto_fetch
        self._suppress_auto_fetch = True
        self.vars["ammo"].set(entry.get("name", ""))
        self._suppress_auto_fetch = previous_guard
        velocity = entry.get("velocity_fps")
        if velocity:
            self.vars["velocity"].set(f"{float(velocity):.0f}")
        bc_value = entry.get("bc_g1")
        if bc_value:
            bc_text = f"{float(bc_value):.3f}".rstrip("0").rstrip(".")
            self.vars["bc"].set(bc_text)
        manual_data = AmmoWebData()
        manual_data.cartridge_title = entry.get("cartridge")
        manual_data.muzzle_velocity_fps = entry.get("velocity_fps")
        manual_data.velocity_source = f"{brand} preset"
        manual_data.reference_barrel_in = entry.get("reference_barrel_in")
        manual_data.fps_per_inch = entry.get("fps_per_inch") or 20.0
        manual_data.bc_g1 = entry.get("bc_g1")
        manual_data.bc_source = f"{brand} preset"
        manual_data.bullet_weight_gr = entry.get("weight_gr")
        manual_data.bullet_diameter_in = entry.get("bullet_diameter_in")
        manual_data.bullet_description = entry.get("name")
        self.web_auto_context["ammo"] = manual_data
        self.web_status.set(f"{brand} preset applied: {entry.get('name')}")
        self._web_data_stale = False
        self.status.set(f"Loaded {entry.get('name')} from {brand}.")

    def _schedule_web_auto_fetch(self, delay_ms: int = 800) -> None:
        if self._suppress_auto_fetch:
            return
        self._clear_auto_fetch_job()

        def _run():
            self._auto_fetch_job = None
            if self._suppress_auto_fetch:
                return
            rifle = self.vars["rifle"].get().strip()
            ammo = self.vars["ammo"].get().strip()
            if (not rifle and not ammo) or not self._web_data_stale:
                return
            success = self._fetch_and_apply_web_data(silent=True)
            self._web_data_stale = not success
            if success:
                self.web_status.set("Web data refreshed automatically.")

        try:
            self._auto_fetch_job = self.after(delay_ms, _run)
        except Exception:
            _run()


    def on_open_env_geo(self):
        try:
            EnvGeoDialog(self)
        except Exception as e:
            messagebox.showerror("Env+Geo Error", str(e))

    def on_open_projection_tool(self):
        try:
            TargetProjectionDialog(self)
        except Exception as e:
            messagebox.showerror("Projection Tool Error", str(e))

    def on_open_mission_planner(self):
        try:
            MissionPlannerDialog(self)
        except Exception as e:
            messagebox.showerror("Mission Planner Error", str(e))

    def on_generate(self):
        try:
            rifle = self.vars["rifle"].get().strip()
            ammo = self.vars["ammo"].get().strip()
            if not rifle:
                raise ValueError("Rifle Model is required.")
            if not ammo:
                raise ValueError("Ammunition is required.")

            velocity_text = self.vars["velocity"].get()
            bc_text = self.vars["bc"].get()
            twist_text = self.vars["twist_rate"].get()
            need_auto_data = self._needs_web_data(velocity_text, bc_text)
            if need_auto_data:
                fetched = self._fetch_and_apply_web_data(silent=True)
                velocity_text = self.vars["velocity"].get()
                bc_text = self.vars["bc"].get()
                if not fetched:
                    raise ValueError("Web lookup failed; adjust rifle/ammo description and try Pull Rifle + Ammo again.")
                errors = []
                if self._requires_auto_fill(velocity_text):
                    errors.append("muzzle velocity")
                if self._requires_auto_fill(bc_text):
                    errors.append("G1 BC")
                if errors:
                    missing = ", ".join(errors)
                    raise ValueError(f"Missing web data for: {missing}. Try refining the rifle/ammo input and pull again.")
            barrel_text = self.vars["barrel_length"].get().strip()
            twist_text = self.vars["twist_rate"].get().strip()
            velocity = _to_float(velocity_text, "Muzzle Velocity (fps)")
            bc = _to_float(bc_text, "Ballistic Coefficient (G1)")
            sight_height = _to_float(self.vars["sight_height"].get(), "Sight Height (in)")
            zero_range = _to_float(self.vars["zero_range"].get(), "Zero Range (yd)")
            barrel_length = self._parse_optional_length(barrel_text, "Barrel Length (in)")
            twist_value = self._parse_twist_value(twist_text) if twist_text else None
            temp = _to_float(self.vars["temp"].get(), "Temperature (F)")
            altitude = _to_float(self.vars["altitude"].get(), "Altitude (ft)")
            wind_speed = _to_float(self.vars["wind_speed"].get(), "Wind Speed (mph)")
            wind_dir   = _to_float(self.vars["wind_dir"].get(), "Wind Direction (deg)")
            wind_gust  = _to_float(self.vars["wind_gust"].get(), "Wind Gust (mph)")
            scope_click = _to_float(self.vars["scope_click"].get(), "Scope Click (MOA per click)")
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
            rifle_ctx = self.web_auto_context.get("rifle") if hasattr(self, "web_auto_context") else None
            if barrel_length is None:
                if rifle_ctx and getattr(rifle_ctx, "barrel_length_in", None):
                    barrel_length = float(rifle_ctx.barrel_length_in)
                    self.vars["barrel_length"].set(f"{barrel_length:.2f}")
                else:
                    raise ValueError("Barrel length is still missing. Use Pull Rifle + Ammo or enter a manual value.")
            if twist_value is None:
                if rifle_ctx and getattr(rifle_ctx, "twist_rate_in", None):
                    twist_value = float(rifle_ctx.twist_rate_in)
                    twist_label = f"1:{twist_value:.2f}".rstrip("0").rstrip(".")
                    self.vars["twist_rate"].set(twist_label)
                else:
                    raise ValueError("Twist rate is still missing. Use Pull Rifle + Ammo or enter a manual value (e.g., 1:8).")
            if self.web_auto_context:
                ammo_ctx = self.web_auto_context.get("ammo")
                if ammo_ctx and ammo_ctx.reference_barrel_in and barrel_length is not None:
                    fps_per_inch = ammo_ctx.fps_per_inch or 20.0
                    velocity += (barrel_length - ammo_ctx.reference_barrel_in) * fps_per_inch
            if scope_click <= 0:
                raise ValueError("Scope Click (MOA per click) must be greater than zero.")
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            filename = f"BallisticTarget_{_safe_filename(rifle)}_{_safe_filename(ammo)}.pdf"
            pdf_path = OUTPUT_DIR / filename

            self.status.set("Generating PDF...")
            self.update_idletasks()

            included_distances, excluded_distances, ballistic_rows, layout_info = generate_one_page_target_pdf(
                pdf_path,
                rifle,
                ammo,
                velocity,
                bc,
                sight_height,
                zero_range,
                temp,
                altitude,
                wind_speed,
                wind_dir,
                wind_gust,
                scope_click_moa=scope_click,
                barrel_length=barrel_length,
                twist_rate=twist_value,
                twist_note=self._twist_note_for_pdf(),
            )

            extension_created = False
            extension_path = _extension_path(pdf_path)
            if excluded_distances:
                excluded_text = ", ".join(f"{d} yd" for d in excluded_distances)
                want_extension = messagebox.askyesno(
                    "Extension Sheet",
                    "Some yardages extend beyond the first sheet:\n"
                    f"{excluded_text}\n\nGenerate the alignment sheet so you can tape it under the target and continue dialing?",
                )
                if want_extension:
                    try:
                        extension_created = generate_extension_sheet(
                            extension_path,
                            rifle,
                            ammo,
                            velocity,
                            bc,
                            sight_height,
                            zero_range,
                            temp,
                            altitude,
                            wind_speed,
                            wind_dir,
                            wind_gust,
                            scope_click,
                            ballistic_rows,
                            included_distances,
                            excluded_distances,
                            layout_info,
                        )
                    except Exception as err:
                        extension_created = False
                        messagebox.showwarning(
                            "Extension Sheet Error",
                            f"Failed to build extension sheet:\n{err}",
                        )
                else:
                    try:
                        extension_path.unlink()
                    except FileNotFoundError:
                        pass
                    except Exception:
                        pass
            else:
                try:
                    extension_path.unlink()
                except FileNotFoundError:
                    pass
                except Exception:
                    pass

            self._update_extension_summary(excluded_distances, extension_created, extension_path)

            mirrored_paths, mirror_errors = mirror_pdf_to_peer_desktops(pdf_path)
            targets_only_path = _targets_only_path(pdf_path)
            if targets_only_path.exists():
                _, targets_only_errors = mirror_pdf_to_peer_desktops(targets_only_path)
                mirror_errors.extend(targets_only_errors)
            if extension_created:
                _, ext_errors = mirror_pdf_to_peer_desktops(extension_path)
                mirror_errors.extend(ext_errors)
            if mirrored_paths:
                count = len(mirrored_paths)
                plural = "s" if count != 1 else ""
                self.status.set(f"Saved: {pdf_path} (mirrored to {count} desktop{plural})")
            else:
                self.status.set(f"Saved: {pdf_path}")

            self.refresh_target_dropdown(select_newest=True)
            detail = f"PDF saved here:\n{pdf_path}"
            if extension_created:
                detail += f"\nExtension sheet:\n{extension_path}"
            if mirrored_paths:
                other = "\n".join(str(p) for p in mirrored_paths)
                detail += f"\n\nAlso copied to:\n{other}"
            messagebox.showinfo("Done", detail)
            if mirror_errors:
                error_lines = "\n".join(f"{dest}: {err}" for dest, err in mirror_errors)
                messagebox.showwarning("Copy Warning", f"Some desktop copies failed:\n{error_lines}")
            self._record_telemetry(
                "generate_target",
                {
                    "zero_range_yd": zero_range,
                    "scope_click_moa": scope_click,
                    "temp_F": temp,
                    "altitude_ft": altitude,
                    "wind_speed_mph": wind_speed,
                    "wind_dir_deg": wind_dir,
                    "wind_gust_mph": wind_gust,
                    "min_distance": min(included_distances) if included_distances else None,
                    "max_distance": max(included_distances) if included_distances else None,
                    "excluded_count": len(excluded_distances),
                    "extension_created": extension_created,
                    "mirrored_count": len(mirrored_paths),
                },
            )

        except Exception as e:
            self.status.set("Error.")
            self._extension_summary = (
                "Extension sheet status unavailable because target generation failed."
            )
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
        self.point_b_link = tk.StringVar(value="")
        self.target_lat = tk.StringVar(value="")
        self.target_lon = tk.StringVar(value="")
        self.range_to_target = tk.StringVar(value="100")
        self.bearing_to_target = tk.StringVar(value="0")
        self.path_points = tk.StringVar(value="5")
        self.use_pins_only = tk.BooleanVar(value=False)
        self.target_elev = tk.StringVar(value="")
        self.project_status = tk.StringVar(value="Projection: idle")
        self._projection_thread: threading.Thread | None = None
        self._bearing_display = tk.StringVar(value="Bearing: -")

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

        ttk.Checkbutton(
            frm,
            text="Use Point A/B pins to compute distance + direction automatically",
            variable=self.use_pins_only,
            command=self._on_use_pins_toggle,
        ).grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 6))
        r += 1

        ttk.Label(frm, text="Range to Point B (yd):").grid(row=r, column=0, sticky="e", **pad)
        self.range_entry = ttk.Entry(frm, textvariable=self.range_to_target, width=20)
        self.range_entry.grid(row=r, column=1, sticky="w", **pad); r += 1
        ttk.Label(frm, text="(All distances are entered/displayed in yards)").grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 8))
        r += 1

        ttk.Label(frm, text="Compass bearing to Point B (deg, 0° = North):").grid(row=r, column=0, sticky="e", **pad)
        self.bearing_entry = ttk.Entry(frm, textvariable=self.bearing_to_target, width=20)
        self.bearing_entry.grid(row=r, column=1, sticky="w", **pad); r += 1
        bearing_btns = ttk.Frame(frm)
        bearing_btns.grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 6))
        for label, deg in [("N", 0), ("E", 90), ("S", 180), ("W", 270)]:
            ttk.Button(
                bearing_btns,
                text=label,
                width=4,
                command=lambda d=deg: self.bearing_to_target.set(f"{d:.0f}")
            ).pack(side="left", padx=2)
        r += 1
        ttk.Label(frm, textvariable=self._bearing_display, foreground="#444").grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 6))
        r += 1

        ttk.Label(frm, text="Path sample points:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.path_points, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Separator(frm, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", padx=10, pady=8); r += 1

        ttk.Label(frm, text="Point B link OR lat,lon:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.point_b_link, width=35).grid(row=r, column=1, sticky="w", **pad); r += 1
        ttk.Button(frm, text="Extract Point B", command=lambda: self.on_extract_point_b()).grid(row=r, column=1, sticky="e", padx=10, pady=(0, 6)); r += 1

        ttk.Label(frm, text="Point B Latitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.target_lat, width=20, state="readonly").grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Point B Longitude:").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.target_lon, width=20, state="readonly").grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Label(frm, text="Point B elevation (optional, ft):").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.target_elev, width=20).grid(row=r, column=1, sticky="w", **pad); r += 1

        ttk.Button(
            frm,
            text="Project + Sample Weather",
            command=self.on_project_and_sample,
        ).grid(row=r, column=0, columnspan=2, pady=(4, 0))
        r += 1
        ttk.Label(frm, textvariable=self.project_status, foreground="#444").grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 8)); r += 1

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

        save_row = ttk.Frame(frm)
        save_row.grid(row=r, column=0, columnspan=2, pady=10)
        ttk.Button(save_row, text="Save to USB config.json", command=self.on_save).grid(row=0, column=0, padx=4)
        ttk.Button(save_row, text="Save Mission Preset…", command=self.on_save_mission).grid(row=0, column=1, padx=4)

        self.bearing_to_target.trace_add("write", lambda *_: self._update_bearing_display())
        self._update_bearing_display()
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
                if cfg.get("target_lat") is not None:
                    self.target_lat.set(str(cfg.get("target_lat")))
                if cfg.get("target_lon") is not None:
                    self.target_lon.set(str(cfg.get("target_lon")))
                if cfg.get("range_to_target_yd") is not None:
                    self.range_to_target.set(str(cfg.get("range_to_target_yd")))
                elif cfg.get("range_to_target") is not None:
                    self.range_to_target.set(str(cfg.get("range_to_target")))
                if cfg.get("bearing_to_target_deg") is not None:
                    self.bearing_to_target.set(str(cfg.get("bearing_to_target_deg")))
                if cfg.get("path_points") is not None:
                    self.path_points.set(str(cfg.get("path_points")))
                if cfg.get("use_pins_only") is not None:
                    self.use_pins_only.set(bool(cfg.get("use_pins_only")))
                    self._on_use_pins_toggle()
                if cfg.get("target_elev_ft") is not None:
                    self.target_elev.set(str(cfg.get("target_elev_ft")))
        except Exception:
            pass

    def on_open_provider(self):
        prov = (self.provider.get() or "Google Maps").lower()
        if "apple" in prov:
            webbrowser.open("https://maps.apple.com/")
        else:
            webbrowser.open("https://maps.google.com/")

    def on_extract(self):
        lat, lon = extract_lat_lon_from_text(self.maps_link.get())
        if lat is None or lon is None:
            messagebox.showerror(
                "Could not extract",
                "Could not extract lat/lon.\n\nPaste:\n- a Google/Apple Maps share link, OR\n- '32.214666, -95.455974'"
            )
            return
        self.lat.set(str(lat)); self.lon.set(str(lon))
        messagebox.showinfo("Extracted", f"Latitude: {lat}\nLongitude: {lon}")

    def on_extract_point_b(self):
        lat, lon = extract_lat_lon_from_text(self.point_b_link.get())
        if lat is None or lon is None:
            messagebox.showerror(
                "Could not extract Point B",
                "Could not extract lat/lon for Point B.\n\nPaste a Google/Apple Maps share link or 'lat, lon'."
            )
            return
        self.target_lat.set(f"{lat:.6f}")
        self.target_lon.set(f"{lon:.6f}")
        messagebox.showinfo("Extracted", f"Point B Latitude: {lat}\nPoint B Longitude: {lon}")

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
            tgt_lat = (self.target_lat.get() or "").strip()
            tgt_lon = (self.target_lon.get() or "").strip()
            target_lat = float(tgt_lat) if tgt_lat else None
            target_lon = float(tgt_lon) if tgt_lon else None
            range_raw = (self.range_to_target.get() or "").strip()
            range_yd = float(range_raw) if range_raw else None
            bearing_raw = (self.bearing_to_target.get() or "").strip()
            bearing_deg = float(bearing_raw) if bearing_raw else None
            target_elev = (self.target_elev.get() or "").strip()
            target_elev_ft = float(target_elev) if target_elev else None
            path_points = int(float(self.path_points.get() or "5"))

            if lat is not None and not (-90 <= lat <= 90): raise ValueError("Latitude must be between -90 and 90.")
            if lon is not None and not (-180 <= lon <= 180): raise ValueError("Longitude must be between -180 and 180.")
            if target_lat is not None and not (-90 <= target_lat <= 90):
                raise ValueError("Point B latitude must be between -90 and 90.")
            if target_lon is not None and not (-180 <= target_lon <= 180):
                raise ValueError("Point B longitude must be between -180 and 180.")
            if bearing_deg is not None and not (0 <= bearing_deg < 360):
                raise ValueError("Bearing must be between 0° and 359.99°.")
            if path_points < 2:
                raise ValueError("Path points must be at least 2.")

            cfg = {
                "map_provider": self.provider.get().strip() or "Google Maps",
                "location_name": self.location_name.get().strip(),
                "lat": lat,
                "lon": lon,
                "target_lat": target_lat,
                "target_lon": target_lon,
                "range_to_target_yd": range_yd,
                "bearing_to_target_deg": bearing_deg,
                "path_points": path_points,
                "use_pins_only": bool(self.use_pins_only.get()),
                "target_elev_ft": target_elev_ft,
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

    def _parse_optional_float(self, value: str) -> float | None:
        value = (value or "").strip()
        if not value:
            return None
        return float(value)

    def _build_mission_payload(self) -> dict[str, Any]:
        lat = self._parse_optional_float(self.lat.get())
        lon = self._parse_optional_float(self.lon.get())
        if lat is None or lon is None:
            raise ValueError("Enter Point A latitude/longitude before saving a mission preset.")
        target_lat = self._parse_optional_float(self.target_lat.get())
        target_lon = self._parse_optional_float(self.target_lon.get())
        range_yd = self._parse_optional_float(self.range_to_target.get()) or 0.0
        bearing = self._parse_optional_float(self.bearing_to_target.get())
        payload = {
            "point_a": {
                "lat": lat,
                "lon": lon,
                "location_name": self.location_name.get().strip() or None,
                "provider": self.provider.get().strip() or "Google Maps",
            },
            "point_b": {"lat": target_lat, "lon": target_lon},
            "range_yd": range_yd,
            "bearing_deg": bearing,
            "path_points": max(2, int(float(self.path_points.get() or "5"))),
            "use_pins_only": bool(self.use_pins_only.get()),
            "target_elev_ft": self._parse_optional_float(self.target_elev.get()),
            "environment": {
                "temp_F": self._parse_optional_float(self.temp.get()),
                "altitude_ft": self._parse_optional_float(self.alt.get()),
                "wind_speed_mph": self._parse_optional_float(self.wind_speed.get()),
                "wind_dir_deg": self._parse_optional_float(self.wind_dir.get()),
                "wind_gust_mph": self._parse_optional_float(self.wind_gust.get()),
            },
        }
        return payload

    def on_save_mission(self):
        try:
            payload = self._build_mission_payload()
        except ValueError as exc:
            messagebox.showerror("Mission Preset", str(exc), parent=self)
            return
        suggested = self.location_name.get().strip() or datetime.now().strftime("Mission %m-%d %H:%M")
        name = simpledialog.askstring("Mission Preset", "Name this mission preset:", initialvalue=suggested, parent=self)
        if not name:
            return
        entry = finalize_mission_entry(payload, name)
        store_mission_entry(entry)
        if hasattr(self.master, "_record_telemetry"):
            try:
                self.master._record_telemetry("mission_saved", {"path_points": payload.get("path_points", 0)})
            except Exception:
                pass
        messagebox.showinfo("Mission Preset", f"Saved mission '{entry['name']}'. Use Mission Planner to reuse it.", parent=self)

    def _update_bearing_display(self):
        text = (self.bearing_to_target.get() or "").strip()
        try:
            bearing = float(text)
        except ValueError:
            self._bearing_display.set("Bearing: -")
            return
        self._bearing_display.set(f"Bearing: {bearing:.1f}° ({bearing_to_cardinal(bearing)})")

    def _apply_weather_summary(self, summary: dict[str, Any]) -> None:
        updated = []
        if summary.get("temp_F") is not None:
            self.temp.set(f"{summary['temp_F']:.1f}")
            updated.append("temperature")
        if summary.get("altitude_ft") is not None:
            self.alt.set(f"{summary['altitude_ft']:.0f}")
            updated.append("altitude")
        if summary.get("wind_speed_mph") is not None:
            self.wind_speed.set(f"{summary['wind_speed_mph']:.1f}")
            updated.append("wind speed")
        if summary.get("wind_dir_deg") is not None:
            self.wind_dir.set(f"{summary['wind_dir_deg']:.0f}")
            updated.append("wind direction")
        if summary.get("wind_gust_mph") is not None:
            self.wind_gust.set(f"{summary['wind_gust_mph']:.1f}")
            updated.append("wind gust")
        if updated:
            messagebox.showinfo("Weather Updated", f"Applied from projection: {', '.join(updated)}")
        else:
            messagebox.showwarning("Weather", "No weather samples were available.")

    def on_project_and_sample(self):
        if self._projection_thread and self._projection_thread.is_alive():
            messagebox.showinfo("Projection", "Projection already running.")
            return
        try:
            lat = float(self.lat.get())
            lon = float(self.lon.get())
        except (TypeError, ValueError):
            messagebox.showerror("Projection", "Enter valid Point A latitude and longitude first.")
            return
        try:
            yards = float(self.range_to_target.get())
            if yards <= 0:
                raise ValueError
        except (TypeError, ValueError):
            messagebox.showerror("Projection", "Enter a positive yardage to Point B.")
            return
        try:
            points = max(2, int(float(self.path_points.get())))
        except (TypeError, ValueError):
            points = 5
            self.path_points.set("5")
        bearing_override = None
        if not self.use_pins_only.get():
            bearing_text = self.bearing_to_target.get().strip()
            if not bearing_text:
                messagebox.showerror("Projection", "Enter a compass bearing (degrees) or enable the pin-only option.")
                return
            try:
                bearing_override = float(bearing_text)
            except ValueError:
                messagebox.showerror("Projection", "Compass bearing must be a number between 0 and 359.")
                return
            if not (0 <= bearing_override < 360):
                messagebox.showerror("Projection", "Compass bearing must be between 0° and 359.99°.")
                return
        start_elev = None
        try:
            if self.alt.get().strip():
                start_elev = float(self.alt.get())
        except ValueError:
            start_elev = None
        end_elev = None
        try:
            if self.target_elev.get().strip():
                end_elev = float(self.target_elev.get())
        except ValueError:
            end_elev = None

        target_lat = None
        target_lon = None
        if self.target_lat.get().strip() and self.target_lon.get().strip():
            try:
                target_lat = float(self.target_lat.get())
                target_lon = float(self.target_lon.get())
            except ValueError:
                target_lat = None
                target_lon = None

        try:
            if target_lat is not None and target_lon is not None:
                projection = project_path_between_points(
                    lat,
                    lon,
                    target_lat,
                    target_lon,
                    points=points,
                    start_elev=start_elev,
                    end_elev=end_elev,
                    elev_unit="ft",
                )
            else:
                projection = project_path(
                    lat,
                    lon,
                    yards,
                    direction=None,
                    bearing_deg=bearing_override,
                    points=points,
                    start_elev=start_elev,
                    end_elev=end_elev,
                    elev_unit="ft",
                )
                target_lat = projection["target"]["lat"]
                target_lon = projection["target"]["lon"]
                self.target_lat.set(f"{target_lat:.6f}")
                self.target_lon.set(f"{target_lon:.6f}")
        except ProjectionError as exc:
            messagebox.showerror("Projection", str(exc))
            return

        if projection["input"].get("bearing_deg") is not None:
            self.bearing_to_target.set(f"{projection['input']['bearing_deg']:.2f}")

        self.project_status.set("Projection ready. Sampling weather...")

        def worker():
            try:
                summary = sample_weather_along_path(projection.get("path", []))
                err = None
            except Exception as exc:
                summary = None
                err = exc
            self.after(0, lambda: self._on_project_sample_complete(summary, err))

        self._projection_thread = threading.Thread(target=worker, daemon=True)
        self._projection_thread.start()

    def _on_project_sample_complete(self, summary: dict[str, Any] | None, error: Exception | None):
        if error or not summary:
            self.project_status.set("Projection: failed to sample weather")
            messagebox.showerror("Weather Sampling", f"Unable to sample weather:\n{error}")
            return
        self.project_status.set(
            f"Projection: averaged {summary.get('samples_with_weather', 0)}/{summary.get('samples_requested', 0)} samples."
        )
        self._apply_weather_summary(summary)

class TargetProjectionDialog(tk.Toplevel):
    """
    Dialog for projecting Point A (shooter) to Point B (target) coordinates, sampling
    weather along the path, and pushing the averaged environmentals back into the main app.
    """

    def __init__(self, master: "App"):
        super().__init__(master)
        self.title("Target Projection Tool")
        self.resizable(False, False)
        self._last_result: dict[str, Any] | None = None
        self._last_weather: dict[str, Any] | None = None
        self._weather_thread: threading.Thread | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 10, "pady": 4}
        frm = ttk.Frame(self)
        frm.grid(row=0, column=0, sticky="nsew")

        self.point_a_link_var = tk.StringVar()
        self.point_b_link_var = tk.StringVar()
        self.lat_var = tk.StringVar()
        self.lon_var = tk.StringVar()
        self.target_lat_var = tk.StringVar()
        self.target_lon_var = tk.StringVar()
        self.range_var = tk.StringVar(value="100")
        self.points_var = tk.StringVar(value="5")
        self.bearing_var = tk.StringVar(value="0")
        self.start_elev_var = tk.StringVar(value="")
        self.end_elev_var = tk.StringVar(value="")
        self.elev_unit_var = tk.StringVar(value="ft")
        self.weather_status = tk.StringVar(value="Weather: not sampled")
        self._bearing_display = tk.StringVar(value="Bearing: -")

        r = 0
        ttk.Label(frm, text="Point A = Shooter, Point B = Target").grid(row=r, column=0, columnspan=3, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point A link or 'lat, lon'").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.point_a_link_var, width=40).grid(row=r, column=1, sticky="w", **pad)
        ttk.Button(frm, text="Extract A", command=lambda: self._extract_link("A")).grid(row=r, column=2, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point A Latitude").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lat_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point A Longitude").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.lon_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Separator(frm, orient="horizontal").grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        r += 1

        ttk.Label(frm, text="Point B link or 'lat, lon'").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.point_b_link_var, width=40).grid(row=r, column=1, sticky="w", **pad)
        ttk.Button(frm, text="Extract B", command=lambda: self._extract_link("B")).grid(row=r, column=2, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point B Latitude").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.target_lat_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point B Longitude").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.target_lon_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Separator(frm, orient="horizontal").grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        r += 1

        ttk.Label(frm, text="Range to Point B (yd)").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.range_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        ttk.Label(frm, text="(Ignored if Point B lat/lon provided)").grid(row=r, column=2, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Path Points").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.points_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Compass bearing (deg, 0° = North)").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.bearing_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        bearing_btns = ttk.Frame(frm)
        bearing_btns.grid(row=r, column=2, sticky="w", padx=4)
        for label, deg in [("N", 0), ("E", 90), ("S", 180), ("W", 270)]:
            ttk.Button(
                bearing_btns,
                text=label,
                width=3,
                command=lambda d=deg: self.bearing_var.set(f"{d:.0f}")
            ).pack(side="left", padx=1)
        r += 1
        ttk.Label(frm, textvariable=self._bearing_display, foreground="#444").grid(row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 6))
        r += 1

        ttk.Label(frm, text="Elevation unit").grid(row=r, column=0, sticky="e", **pad)
        ttk.Combobox(frm, textvariable=self.elev_unit_var, values=["ft", "m"], width=6, state="readonly").grid(
            row=r, column=1, sticky="w", **pad
        )
        r += 1

        ttk.Label(frm, text="Point A elevation").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.start_elev_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        ttk.Label(frm, text="Point B elevation").grid(row=r, column=0, sticky="e", **pad)
        ttk.Entry(frm, textvariable=self.end_elev_var, width=16).grid(row=r, column=1, sticky="w", **pad)
        r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=3, sticky="ew", padx=10, pady=(4, 0))
        ttk.Button(btns, text="Compute Path", command=self._compute).grid(row=0, column=0, padx=3)
        ttk.Button(btns, text="Sample Weather", command=self._sample_weather).grid(row=0, column=1, padx=3)
        ttk.Button(btns, text="Apply Weather to Target", command=self._apply_weather_to_target).grid(row=0, column=2, padx=3)
        ttk.Button(btns, text="Copy JSON", command=self._copy_json).grid(row=0, column=3, padx=3)
        r += 1

        ttk.Label(frm, textvariable=self.weather_status, foreground="#444").grid(row=r, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 4))
        r += 1

        self.output = tk.Text(frm, height=18, width=78, state="disabled")
        self.output.configure(font=("Consolas", 10))
        self.output.grid(row=r, column=0, columnspan=3, padx=10, pady=(4, 10))

        self.bearing_var.trace_add("write", lambda *_: self._update_projection_bearing())
        self._update_projection_bearing()

    def _require_float(self, value: str, label: str) -> float:
        try:
            return float(value)
        except Exception:
            raise ValueError(f"{label} must be a number.")

    def _extract_link(self, which: str) -> None:
        text = self.point_a_link_var.get() if which == "A" else self.point_b_link_var.get()
        lat, lon = extract_lat_lon_from_text(text)
        if lat is None or lon is None:
            messagebox.showerror("Extract Error", f"Could not parse coordinates for Point {which}.", parent=self)
            return
        target = (self.lat_var, self.lon_var) if which == "A" else (self.target_lat_var, self.target_lon_var)
        target[0].set(f"{lat:.6f}")
        target[1].set(f"{lon:.6f}")
        messagebox.showinfo("Extracted", f"Point {which} set to:\nLat {lat:.6f}\nLon {lon:.6f}", parent=self)

    def _update_projection_bearing(self) -> None:
        text = (self.bearing_var.get() or "").strip()
        try:
            bearing = float(text)
        except ValueError:
            self._bearing_display.set("Bearing: -")
            return
        self._bearing_display.set(f"Bearing: {bearing:.1f}° ({bearing_to_cardinal(bearing)})")

    def _compute(self) -> None:
        try:
            lat = self._require_float(self.lat_var.get(), "Point A latitude")
            lon = self._require_float(self.lon_var.get(), "Point A longitude")
            points = int(self._require_float(self.points_var.get(), "Path points"))
            if points < 2:
                raise ValueError("Path points must be at least 2.")
            start_raw = self.start_elev_var.get().strip()
            end_raw = self.end_elev_var.get().strip()
            start_elev = float(start_raw) if start_raw else None
            end_elev = float(end_raw) if end_raw else None
            target_lat_text = self.target_lat_var.get().strip()
            target_lon_text = self.target_lon_var.get().strip()
            use_map_pins = bool(target_lat_text and target_lon_text)
            if use_map_pins:
                target_lat = float(target_lat_text)
                target_lon = float(target_lon_text)
                result = project_path_between_points(
                    lat,
                    lon,
                    target_lat,
                    target_lon,
                    points=points,
                    start_elev=start_elev,
                    end_elev=end_elev,
                    elev_unit=self.elev_unit_var.get(),
                )
                computed_yards = result["input"]["yards"]
                self.range_to_target.set(f"{computed_yards:.2f}")
                if result["input"].get("bearing_deg") is not None:
                    self.bearing_var.set(f"{result['input']['bearing_deg']:.2f}")
            else:
                yards = self._require_float(self.range_var.get(), "Range to Point B")
                bearing_text = self.bearing_var.get().strip()
                if not bearing_text:
                    raise ValueError("Enter a compass bearing (degrees) or provide Point B pins.")
                bearing = float(bearing_text)
                if not (0 <= bearing < 360):
                    raise ValueError("Compass bearing must be between 0° and 359.99°.")
                result = project_path(
                    lat,
                    lon,
                    yards,
                    direction=None,
                    bearing_deg=bearing,
                    points=points,
                    start_elev=start_elev,
                    end_elev=end_elev,
                    elev_unit=self.elev_unit_var.get(),
                )
        except (ValueError, ProjectionError) as exc:
            messagebox.showerror("Projection Error", str(exc), parent=self)
            return

        self._last_result = result
        self._last_weather = None
        self.weather_status.set("Weather: not sampled")
        self._set_output(self._format_result(result))

    def _format_result(self, result: dict[str, Any]) -> str:
        precision = 6
        fmt = f"{{:.{precision}f}}"
        shooter = result["shooter"]
        target = result["target"]
        computed = result["computed"]
        unit = self.elev_unit_var.get()
        lines = [
            f"Point A (Shooter): {fmt.format(shooter['lat'])}, {fmt.format(shooter['lon'])}",
            f"Point B (Target) : {fmt.format(target['lat'])}, {fmt.format(target['lon'])}",
            f"Bearing          : {result['input']['bearing_deg']:.2f}° ({result['input'].get('direction') or '-'})",
            f"Distance         : {result['input']['yards']:.2f} yd = {computed['distance_m']:.2f} m",
            f"Return Bearing   : {computed['return_bearing_deg']:.2f}°",
        ]
        shooter_elev = shooter.get("elev_m")
        target_elev = target.get("elev_m")
        if shooter_elev is not None:
            lines.append(f"Point A Elev    : {format_elevation(shooter_elev, unit, 2)}")
        if target_elev is not None:
            lines.append(f"Point B Elev    : {format_elevation(target_elev, unit, 2)}")
        slope = computed.get("slope_percent")
        if slope is not None:
            slope_desc = "uphill" if slope > 0 else "downhill" if slope < 0 else "level"
            lines.append(f"Slope           : {slope:.2f}% ({slope_desc})")

        path = result.get("path") or []
        if len(path) > 2:
            lines.append("")
            lines.append("Path points:")
            for idx, point in enumerate(path, start=1):
                entry = f"  {idx:02d}. {fmt.format(point['lat'])}, {fmt.format(point['lon'])}"
                elev_m = point.get("elev_m")
                if elev_m is not None:
                    entry += f" ({format_elevation(elev_m, unit, 2)})"
                lines.append(entry)
        return "\n".join(lines)

    def _set_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", text.strip() + "\n")
        self.output.configure(state="disabled")

    def _append_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text.strip() + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def _copy_json(self) -> None:
        if not self._last_result:
            messagebox.showinfo("Copy JSON", "Run a projection first.", parent=self)
            return
        try:
            payload = json.dumps(self._last_result, indent=2, sort_keys=True)
        except Exception as exc:
            messagebox.showerror("Copy JSON", f"Unable to serialize result: {exc}", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(payload)
        messagebox.showinfo("Copy JSON", "Projection copied to clipboard.", parent=self)

    def _sample_weather(self) -> None:
        if not self._last_result:
            messagebox.showwarning("Sample Weather", "Compute a path first.", parent=self)
            return
        if self._weather_thread and self._weather_thread.is_alive():
            messagebox.showinfo("Sample Weather", "Weather sampling already in progress.", parent=self)
            return
        path = self._last_result.get("path") or []
        if not path:
            messagebox.showerror("Sample Weather", "No path coordinates available.", parent=self)
            return

        self.weather_status.set("Weather: sampling…")
        self._append_output("Sampling weather along the path...")

        def worker():
            try:
                summary = sample_weather_along_path(path)
                error = None
            except Exception as exc:
                summary = None
                error = exc
            self.after(0, lambda: self._on_weather_sample_complete(summary, error))

        self._weather_thread = threading.Thread(target=worker, daemon=True)
        self._weather_thread.start()

    def _on_weather_sample_complete(self, summary: dict[str, Any] | None, error: Exception | None) -> None:
        if error or not summary:
            self.weather_status.set("Weather: failed")
            messagebox.showerror("Sample Weather", f"Unable to sample weather:\n{error}", parent=self)
            return
        self._last_weather = summary
        self.weather_status.set(
            f"Weather: averaged {summary.get('samples_with_weather', 0)}/{summary.get('samples_requested', 0)} points."
        )
        self._append_output(self._format_weather_summary(summary))
        if hasattr(self.master, "_record_telemetry"):
            try:
                yards = None
                bearing = None
                if self._last_result:
                    yards = self._last_result.get("input", {}).get("yards")
                    bearing = self._last_result.get("input", {}).get("bearing_deg")
                self.master._record_telemetry(
                    "projection_sample",
                    {
                        "path_points": len(self._last_result.get("path", [])) if self._last_result else None,
                        "range_yd": yards,
                        "bearing_deg": bearing,
                        "weather_samples": summary.get("samples_with_weather"),
                    },
                )
            except Exception:
                pass

    def _format_weather_summary(self, summary: dict[str, Any]) -> str:
        def fmt(value, unit="", digits=1):
            if value is None:
                return "n/a"
            return f"{value:.{digits}f}{unit}"

        lines = ["Weather summary:"]
        lines.append(f"  Avg Temp    : {fmt(summary.get('temp_F'), ' °F')}")
        lines.append(f"  Avg Wind    : {fmt(summary.get('wind_speed_mph'), ' mph')} @ {fmt(summary.get('wind_dir_deg'), '°', 0)}")
        lines.append(f"  Avg Gust    : {fmt(summary.get('wind_gust_mph'), ' mph')}")
        lines.append(f"  Avg Altitude: {fmt(summary.get('altitude_ft'), ' ft', 0)}")
        lines.append(
            f"  Samples     : {summary.get('samples_with_weather', 0)}/{summary.get('samples_requested', 0)}"
        )
        return "\n".join(lines)

    def _apply_weather_to_target(self) -> None:
        if not self._last_weather:
            messagebox.showwarning("Apply Weather", "Sample weather first.", parent=self)
            return
        parent = self.master
        if not hasattr(parent, "vars"):
            messagebox.showerror("Apply Weather", "Parent window is unavailable.", parent=self)
            return
        summary = self._last_weather
        applied = []
        if summary.get("temp_F") is not None:
            parent.vars["temp"].set(f"{summary['temp_F']:.1f}")
            applied.append("temperature")
        if summary.get("altitude_ft") is not None:
            parent.vars["altitude"].set(f"{summary['altitude_ft']:.0f}")
            applied.append("altitude")
        if summary.get("wind_speed_mph") is not None and "wind_speed" in parent.vars:
            parent.vars["wind_speed"].set(f"{summary['wind_speed_mph']:.1f}")
            applied.append("wind speed")
        if summary.get("wind_dir_deg") is not None and "wind_dir" in parent.vars:
            parent.vars["wind_dir"].set(f"{summary['wind_dir_deg']:.0f}")
            applied.append("wind direction")
        if summary.get("wind_gust_mph") is not None and "wind_gust" in parent.vars:
            parent.vars["wind_gust"].set(f"{summary['wind_gust_mph']:.1f}")
            applied.append("wind gust")
        if "use_env" in parent.vars:
            parent.vars["use_env"].set("1")
        if applied:
            self.weather_status.set("Weather: applied to target inputs")
            messagebox.showinfo("Apply Weather", f"Updated: {', '.join(applied)}", parent=self)
            parent.status.set("Projection weather applied to target inputs.")
        else:
            messagebox.showwarning("Apply Weather", "No weather values were available to apply.", parent=self)


class RiflePickerDialog(tk.Toplevel):
    def __init__(self, parent: "App"):
        super().__init__(parent)
        self.title("Select Rifle")
        self.parent = parent
        self.resizable(False, False)
        self.result: Optional[tuple[str, str]] = None
        self._brand_loading: set[tuple[str, str]] = set()

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        self.category_values = _rifle_category_labels()
        initial_category_label = self.category_values[0] if self.category_values else ""
        initial_category_key = _rifle_category_key_from_label(initial_category_label) or "lever"

        self.category_var = tk.StringVar(value=initial_category_label)
        self.brand_var = tk.StringVar(value="")
        self.model_var = tk.StringVar(value="")
        self.custom_model = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")

        row = 0
        ttk.Label(frm, text="Rifle category:").grid(row=row, column=0, sticky="w")
        self.category_combo = ttk.Combobox(
            frm,
            textvariable=self.category_var,
            state="readonly",
            width=28,
            values=self.category_values,
        )
        self.category_combo.grid(row=row, column=1, padx=(6, 0), sticky="w"); row += 1

        ttk.Label(frm, text="Manufacturer:").grid(row=row, column=0, sticky="w")
        self.brand_combo = ttk.Combobox(frm, textvariable=self.brand_var, state="readonly", width=32, values=[])
        self.brand_combo.grid(row=row, column=1, padx=(6, 0), sticky="w"); row += 1

        ttk.Label(frm, text="Model from catalog:").grid(row=row, column=0, sticky="w")
        self.model_combo = ttk.Combobox(frm, textvariable=self.model_var, state="readonly", width=40, values=[])
        self.model_combo.grid(row=row, column=1, padx=(6, 0), sticky="w"); row += 1

        ttk.Label(frm, text="Or type a custom model description:").grid(row=row, column=0, columnspan=2, sticky="w")
        ttk.Entry(frm, textvariable=self.custom_model, width=44).grid(row=row + 1, column=0, columnspan=2, sticky="w")
        row += 2

        ttk.Label(frm, textvariable=self.status_var, foreground="#2a5b84", wraplength=360).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(4, 6)
        )
        row += 1

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=2, sticky="e")
        ttk.Button(btns, text="Use Selection", command=self._on_accept).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Cancel", command=self._on_cancel).grid(row=0, column=1)

        self.category_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_category_change())
        self.brand_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_brand_change())

        self._set_category(initial_category_key)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _current_category_key(self) -> str:
        label = self.category_var.get()
        return _rifle_category_key_from_label(label) or "lever"

    def _set_category(self, category_key: str) -> None:
        brands = _rifle_brands_for_category(category_key)
        self.brand_combo.configure(values=brands)
        if brands:
            self.brand_var.set(brands[0])
            self._populate_model_combo(category_key, brands[0], initial=True)
        else:
            self.brand_var.set("")
            self.model_combo.configure(values=[])
            self.model_var.set("")
            self.status_var.set("No manufacturers available for this category.")

    def _on_category_change(self) -> None:
        self.model_var.set("")
        self.custom_model.set("")
        category_key = self._current_category_key()
        self._set_category(category_key)

    def _on_brand_change(self) -> None:
        category_key = self._current_category_key()
        brand = self.brand_var.get().strip()
        if brand:
            self._populate_model_combo(category_key, brand)

    def _populate_model_combo(self, category_key: str, brand: str, initial: bool = False) -> None:
        models = _rifle_models_for_brand(category_key, brand)
        if models:
            self.model_combo.configure(values=models)
            if self.model_var.get() not in models:
                self.model_var.set(models[0])
            plural = "s" if len(models) != 1 else ""
            self.status_var.set(f"Loaded {len(models)} model{plural} from {brand}.")
            return
        error = _rifle_brand_error(category_key, brand)
        if error:
            self.model_combo.configure(values=[])
            self.model_var.set("")
            self.status_var.set(f"{brand} catalog unavailable ({error}). Enter a custom description.")
            return
        self.model_combo.configure(values=[])
        self.model_var.set("")
        self.status_var.set(f"Loading {brand} catalog…")
        self._load_brand_async(category_key, brand)

    def _load_brand_async(self, category_key: str, brand: str) -> None:
        key = _canonical_rifle_brand_key(category_key, brand) or brand.lower()
        cache_key = (category_key, key)
        if cache_key in self._brand_loading:
            return
        self._brand_loading.add(cache_key)

        def worker() -> None:
            err = None
            try:
                _ensure_rifle_brand_catalog(category_key, brand)
            except Exception as exc:
                err = str(exc)

            def finish() -> None:
                if not self.winfo_exists():
                    return
                self._brand_loading.discard(cache_key)
                if err and not _rifle_brand_error(category_key, brand):
                    errors = _RIFLE_ERRORS.setdefault(category_key, {})
                    canon = _canonical_rifle_brand_key(category_key, brand)
                    if canon:
                        errors[canon] = err
                self._populate_model_combo(category_key, brand)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _on_accept(self) -> None:
        brand = self.brand_var.get().strip()
        model = self.model_var.get().strip()
        custom = self.custom_model.get().strip()
        if not brand:
            messagebox.showwarning("Rifle Catalog", "Select a manufacturer first.", parent=self)
            return
        if not model and not custom:
            messagebox.showwarning("Rifle Catalog", "Select a model or enter a custom description.", parent=self)
            return
        if not model:
            model = custom
        self.result = (brand, model)
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.destroy()


class MissionPlannerDialog(tk.Toplevel):
    def __init__(self, master: "App"):
        super().__init__(master)
        self.title("Mission Planner")
        self.resizable(True, True)
        self.geometry("780x460")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.missions: list[dict[str, Any]] = []
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(6, 4), padx=8)
        ttk.Label(header, text="Store reusable Point A/B presets with saved environmentals.", foreground="#444").grid(
            row=0, column=0, sticky="w"
        )

        body = ttk.Frame(self)
        body.grid(row=1, column=0, sticky="nsew", padx=8)
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)

        columns = ("name", "range", "bearing", "updated")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=8)
        self.tree.heading("name", text="Mission")
        self.tree.heading("range", text="Range (yd)")
        self.tree.heading("bearing", text="Bearing (°)")
        self.tree.heading("updated", text="Last Saved")
        self.tree.column("name", width=200, anchor="w")
        self.tree.column("range", width=80, anchor="center")
        self.tree.column("bearing", width=90, anchor="center")
        self.tree.column("updated", width=140, anchor="center")
        tree_scroll = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_detail())
        self.tree.bind("<Double-1>", lambda _e: self._apply_selected())

        self.detail = tk.Text(body, height=10, wrap="none")
        self.detail.configure(font=("Consolas", 10))
        self.detail.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

        btns = ttk.Frame(self)
        btns.grid(row=2, column=0, sticky="ew", pady=8, padx=8)
        btns.columnconfigure((0, 1, 2, 3), weight=1)
        ttk.Button(btns, text="Add from Geo Config", command=self._add_from_config).grid(row=0, column=0, padx=4, sticky="ew")
        ttk.Button(btns, text="Apply to App", command=self._apply_selected).grid(row=0, column=1, padx=4, sticky="ew")
        ttk.Button(btns, text="Delete", command=self._delete_selected).grid(row=0, column=2, padx=4, sticky="ew")
        ttk.Button(btns, text="Refresh", command=self._refresh).grid(row=0, column=3, padx=4, sticky="ew")

        self._refresh()

    def _refresh(self) -> None:
        self.missions = load_missions()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for mission in self.missions:
            mid = mission.get("id") or str(uuid.uuid4())
            range_yd = mission.get("range_yd")
            bearing = mission.get("bearing_deg")
            updated = mission.get("created_ts", "")[:19].replace("T", " ")
            self.tree.insert(
                "",
                "end",
                iid=mid,
                values=(
                    mission.get("name") or "(unnamed)",
                    f"{range_yd:.1f}" if isinstance(range_yd, (int, float)) else "-",
                    f"{bearing:.1f}" if isinstance(bearing, (int, float)) else "-",
                    updated,
                ),
            )
        self._update_detail()

    def _get_selected_mission(self) -> dict[str, Any] | None:
        selection = self.tree.selection()
        if not selection:
            return None
        selected_id = selection[0]
        for mission in self.missions:
            if mission.get("id") == selected_id:
                return mission
        return None

    def _update_detail(self) -> None:
        mission = self._get_selected_mission()
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if mission:
            self.detail.insert("end", json.dumps(mission, indent=2))
        self.detail.configure(state="disabled")

    def _add_from_config(self) -> None:
        cfg = load_env_from_geo_config()
        try:
            payload = build_mission_payload_from_config(cfg)
        except ValueError as exc:
            messagebox.showerror("Mission Planner", str(exc), parent=self)
            return
        suggested = cfg.get("location_name") or datetime.now().strftime("Mission %m-%d %H:%M")
        name = simpledialog.askstring("Mission Name", "Name this mission preset:", initialvalue=suggested, parent=self)
        if not name:
            return
        entry = finalize_mission_entry(payload, name)
        store_mission_entry(entry)
        self._refresh()
        messagebox.showinfo("Mission Planner", f"Saved mission '{name}'.", parent=self)

    def _apply_selected(self) -> None:
        mission = self._get_selected_mission()
        if not mission:
            messagebox.showwarning("Mission Planner", "Select a mission to apply.", parent=self)
            return
        try:
            self.master.apply_mission_from_planner(mission)
        except Exception as exc:
            messagebox.showerror("Mission Planner", f"Unable to apply mission:\n{exc}", parent=self)

    def _delete_selected(self) -> None:
        mission = self._get_selected_mission()
        if not mission:
            messagebox.showwarning("Mission Planner", "Select a mission to delete.", parent=self)
            return
        confirm = messagebox.askyesno(
            "Delete Mission",
            f"Delete mission '{mission.get('name')}'?",
            parent=self,
        )
        if not confirm:
            return
        remaining = [m for m in self.missions if m.get("id") != mission.get("id")]
        replace_all_missions(remaining)
        self._refresh()


def _load_custom_sight_presets() -> tuple[list[tuple[str, float | None]], list[tuple[str, float | None]]]:
    if not SIGHT_PRESETS_PATH.exists():
        return [], []
    try:
        data = json.loads(SIGHT_PRESETS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return [], []
    platform_entries: list[tuple[str, float | None]] = []
    mount_entries: list[tuple[str, float | None]] = []

    def _normalize(entries: list[dict[str, Any]], key: str) -> list[tuple[str, float | None]]:
        normalized: list[tuple[str, float | None]] = []
        for entry in entries:
            try:
                label = str(entry.get("label", "")).strip()
            except Exception:
                label = ""
            if not label:
                continue
            raw_value = entry.get(key)
            if raw_value in (None, ""):
                normalized.append((label, None))
                continue
            try:
                normalized.append((label, float(raw_value)))
            except Exception:
                normalized.append((label, None))
        return normalized

    platform_entries = _normalize(list(data.get("platforms", [])), "offset")
    mount_entries = _normalize(list(data.get("mounts", [])), "height")
    return platform_entries, mount_entries


class SightHeightDialog(tk.Toplevel):

    def __init__(self, parent: "App"):
        super().__init__(parent)
        self.title("Estimate Sight Height")
        self.parent = parent
        self.resizable(False, False)
        self.result: Optional[float] = None
        custom_platforms, custom_mounts = _load_custom_sight_presets()
        preset_mounts = [(spec["label"], spec["height"]) for spec in MOUNT_SPEC_PRESETS]
        self.platform_options = SIGHT_PLATFORM_OPTIONS + custom_platforms
        self.mount_options = MOUNT_CENTER_OPTIONS + preset_mounts + custom_mounts
        self.mount_sources: dict[str, str | None] = {label: None for label, _ in self.mount_options}
        for preset in MOUNT_SPEC_PRESETS:
            self.mount_sources[preset["label"]] = preset.get("source")
            if all(existing[0] != preset["label"] for existing in self.mount_options):
                self.mount_options.append((preset["label"], preset["height"]))
        default_platform_label = self.platform_options[0][0]
        default_mount_label = self.mount_options[1][0] if len(self.mount_options) > 1 else self.mount_options[0][0]
        self.platform_var = tk.StringVar(value=default_platform_label)
        self.mount_var = tk.StringVar(value=default_mount_label)
        self.custom_platform = tk.StringVar(value="")
        self.custom_mount = tk.StringVar(value="")
        self.manual_total_height = tk.StringVar(value="")
        brand_values = _scope_brands()
        initial_brand = brand_values[0] if brand_values else CUSTOM_SCOPE_BRAND
        self.scope_brand_var = tk.StringVar(value=initial_brand)
        self.scope_model_var = tk.StringVar(value="")
        self.scope_custom_text = tk.StringVar(value="")
        self.scope_status = tk.StringVar(value="")

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        row = 0
        ttk.Label(frm, text="Question 1 of 3: Pick your scope manufacturer/model (data sourced from the manufacturer).").grid(row=row, column=0, sticky="w"); row += 1
        brand_row = ttk.Frame(frm)
        brand_row.grid(row=row, column=0, sticky="ew", pady=(0, 4)); row += 1
        ttk.Label(brand_row, text="Manufacturer:").grid(row=0, column=0, sticky="w")
        self.scope_brand_combo = ttk.Combobox(brand_row, textvariable=self.scope_brand_var, state="readonly", width=28, values=brand_values)
        self.scope_brand_combo.grid(row=0, column=1, padx=(6, 0), sticky="w")

        model_row = ttk.Frame(frm)
        model_row.grid(row=row, column=0, sticky="ew", pady=(0, 4)); row += 1
        ttk.Label(model_row, text="Model:").grid(row=0, column=0, sticky="w")
        self.scope_model_combo = ttk.Combobox(model_row, textvariable=self.scope_model_var, state="readonly", width=34, values=[])
        self.scope_model_combo.grid(row=0, column=1, padx=(6, 0), sticky="w")

        custom_row = ttk.Frame(frm)
        custom_row.grid(row=row, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(
            custom_row,
            text="Type your scope (brand + model) to search automatically (optional):",
        ).grid(row=0, column=0, sticky="w")
        self.scope_custom_entry = ttk.Entry(custom_row, textvariable=self.scope_custom_text, width=38)
        self.scope_custom_entry.grid(row=1, column=0, sticky="w")
        ttk.Label(
            custom_row,
            text="Example: “Vortex Strike Eagle 1-6x24”. Leave blank to use the dropdowns.",
            foreground="#555",
            wraplength=320,
        ).grid(row=2, column=0, sticky="w", pady=(2, 0))
        row += 1

        self.scope_brand_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_scope_brand_change())

        ttk.Button(frm, text="Lookup Scope", command=self._on_scope_lookup).grid(row=row, column=0, sticky="w", pady=(0, 4)); row += 1
        ttk.Label(frm, textvariable=self.scope_status, foreground="#2a5b84", wraplength=320).grid(row=row, column=0, sticky="w", pady=(0, 8)); row += 1
        self._brand_loading: set[str] = set()
        self._populate_model_combo(initial_brand, initial=True)

        ttk.Label(frm, text="Question 2 of 3: Which rifle platform best matches your setup?").grid(row=row, column=0, sticky="w"); row += 1
        platform_combo = ttk.Combobox(
            frm,
            textvariable=self.platform_var,
            state="readonly",
            width=32,
            values=[label for label, _ in self.platform_options],
        )
        platform_combo.grid(row=row, column=0, sticky="ew", pady=(0, 6)); row += 1
        platform_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_state())

        ttk.Label(
            frm,
            text="Custom base offset (inches) — leave blank to keep the preset value:",
        ).grid(row=row, column=0, sticky="w"); row += 1
        self.custom_platform_entry = ttk.Entry(frm, textvariable=self.custom_platform, width=15)
        self.custom_platform_entry.grid(row=row, column=0, sticky="w", pady=(0, 8)); row += 1

        ttk.Label(frm, text="Question 3 of 3: Select your scope mount/rings.").grid(row=row, column=0, sticky="w"); row += 1
        self.mount_combo = ttk.Combobox(
            frm,
            textvariable=self.mount_var,
            state="readonly",
            width=32,
            values=[label for label, _ in self.mount_options],
        )
        self.mount_combo.grid(row=row, column=0, sticky="ew", pady=(0, 6)); row += 1
        self.mount_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_state())

        ttk.Label(
            frm,
            text="Custom mount center height (inches) — leave blank to keep the preset:",
        ).grid(row=row, column=0, sticky="w"); row += 1
        self.custom_mount_entry = ttk.Entry(frm, textvariable=self.custom_mount, width=15)
        self.custom_mount_entry.grid(row=row, column=0, sticky="w", pady=(0, 8)); row += 1

        ttk.Label(
            frm,
            text="Tip: most AR mounts list the rail-to-optic-center height (e.g., 1.50\"). "
            "Bolt gun ring specs vary; use calipers if unsure.",
            wraplength=320,
            foreground="#444",
        ).grid(row=row, column=0, sticky="w", pady=(0, 8)); row += 1
        manual_row = ttk.Frame(frm)
        manual_row.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(
            manual_row,
            text="Already know the total sight height? Enter it (inches) to override:",
            wraplength=320,
        ).grid(row=0, column=0, sticky="w")
        ttk.Entry(manual_row, textvariable=self.manual_total_height, width=12).grid(row=1, column=0, sticky="w", pady=(2, 0))
        row += 1

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, pady=(4, 0), sticky="e")
        ttk.Button(btns, text="Use Value", command=self._on_accept).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Cancel", command=self._on_cancel).grid(row=0, column=1)

        self._update_state()
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _update_state(self):
        # Manual overrides stay available at all times; nothing to toggle.
        pass

    def _resolve_platform_offset(self) -> float:
        manual = self.custom_platform.get().strip()
        if manual:
            return self._to_float(manual, "Custom base offset")
        label = self.platform_var.get()
        for name, offset in self.platform_options:
            if name == label:
                if offset is not None:
                    return float(offset)
                break
        raise ValueError("Select a rifle platform or enter a custom base offset.")

    def _resolve_mount_height(self) -> float:
        manual = self.custom_mount.get().strip()
        if manual:
            return self._to_float(manual, "Custom mount center height")
        label = self.mount_var.get()
        for name, height in self.mount_options:
            if name == label:
                if height is not None:
                    return float(height)
                break
        raise ValueError("Select a mount profile or enter a custom height.")

    def _to_float(self, value: str, label: str) -> float:
        try:
            return float(value)
        except Exception:
            raise ValueError(f"{label} must be a number.")

    def _on_accept(self):
        try:
            manual = self.manual_total_height.get().strip()
            if manual:
                try:
                    total = float(manual)
                except ValueError:
                    raise ValueError("Manual sight height must be a number.")
            else:
                base = self._resolve_platform_offset()
                mount = self._resolve_mount_height()
                total = base + mount
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
            return
        self.result = total
        messagebox.showinfo("Sight Height", f"Estimated sight height: {total:.2f} inches.", parent=self)
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

    def _populate_model_combo(self, brand: str, initial: bool = False) -> None:
        if brand == CUSTOM_SCOPE_BRAND:
            self.scope_model_combo.configure(values=[])
            self.scope_model_var.set("")
            if not initial:
                self.scope_status.set("")
            return

        models = _scope_models_for_brand(brand)
        if models:
            self.scope_model_combo.configure(values=models)
            if self.scope_model_var.get() not in models:
                self.scope_model_var.set(models[0])
            if not initial:
                plural = "s" if len(models) != 1 else ""
                self.scope_status.set(f"Loaded {len(models)} {brand} model{plural} from cache.")
            return

        error = _scope_brand_error(brand)
        if error:
            self.scope_model_combo.configure(values=[])
            self.scope_model_var.set("")
            self.scope_status.set(f"{brand} catalog unavailable ({error}). Using presets/manual entry.")
            return

        self.scope_model_combo.configure(values=[])
        self.scope_model_var.set("")
        self.scope_status.set(f"Loading {brand} catalog…")
        self._load_brand_catalog_async(brand)

    def _load_brand_catalog_async(self, brand: str) -> None:
        key = _canonical_scope_brand_key(brand)
        if not key or key == CUSTOM_SCOPE_BRAND.lower():
            return
        if key in self._brand_loading:
            return
        self._brand_loading.add(key)

        def worker() -> None:
            err = None
            try:
                _ensure_scope_brand_catalog(brand)
            except Exception as exc:
                err = str(exc)

            def finish() -> None:
                if not self.winfo_exists():
                    return
                self._brand_loading.discard(key)
                if err and not _scope_brand_error(brand):
                    _SCOPE_BRAND_ERRORS[key] = err
                self._populate_model_combo(brand)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _on_scope_brand_change(self):
        brand = self.scope_brand_var.get()
        self._populate_model_combo(brand)

    def _on_scope_lookup(self):
        typed_text = self.scope_custom_text.get().strip()
        if typed_text:
            self._lookup_scope_from_text_async(typed_text)
            return
        brand = self.scope_brand_var.get()
        if brand == CUSTOM_SCOPE_BRAND:
            messagebox.showwarning("Lookup", "Type your scope above or choose a manufacturer.", parent=self)
            return
        model = self.scope_model_var.get().strip()
        if not model:
            messagebox.showwarning("Lookup", "Select a scope model.", parent=self)
            return
        spec = _find_scope_spec(brand, model, ensure_detail=False)
        if spec and spec.get("recommended_height"):
            self._apply_scope_height(spec["label"], float(spec["recommended_height"]), spec.get("source", "manufacturer data"))
            return
        if spec and spec.get("error"):
            self.scope_status.set(f"Unable to read manufacturer specs for {model}: {spec['error']}")
            return
        self.scope_status.set(f"Fetching {model} specs from {brand}…")
        self._fetch_scope_detail_async(brand, model)

    def _lookup_scope_from_text_async(self, query: str) -> None:
        self.scope_status.set(f"Searching for “{query}”…")

        def worker():
            spec = None
            note = None
            try:
                spec, note = _lookup_scope_spec_from_text(query)
            except Exception as exc:
                spec = None
                note = f"Lookup failed: {exc}"

            def finish():
                if not self.winfo_exists():
                    return
                if spec and spec.get("recommended_height"):
                    self._apply_scope_height(spec["label"], float(spec["recommended_height"]), spec.get("source"))
                    if note:
                        current = self.scope_status.get()
                        self.scope_status.set(f"{current}\n{note}")
                else:
                    self.scope_status.set(note or "No scope data found. Refine the description or use the dropdowns.")

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _fetch_scope_detail_async(self, brand: str, model: str) -> None:
        def worker():
            error = None
            spec = None
            try:
                spec = _find_scope_spec(brand, model, ensure_detail=True)
            except Exception as exc:
                error = str(exc)

            def finish():
                if not self.winfo_exists():
                    return
                if error:
                    self.scope_status.set(f"Unable to read manufacturer specs for {model}: {error}")
                    return
                if not spec:
                    fallback = _infer_scope_height(f"{brand} {model}")
                    if not fallback:
                        self.scope_status.set("No manufacturer data for that model. Enter the height manually.")
                        return
                    label, height, source = fallback
                    self._apply_scope_height(label, height, source)
                    return
                if spec.get("recommended_height"):
                    self._apply_scope_height(spec["label"], float(spec["recommended_height"]), spec.get("source", "manufacturer data"))
                elif spec.get("error"):
                    self.scope_status.set(f"Unable to read manufacturer specs for {model}: {spec['error']}")
                else:
                    fallback = _infer_scope_height(f"{brand} {model}")
                    if not fallback:
                        self.scope_status.set("No manufacturer data for that model. Enter the height manually.")
                        return
                    label, height, source = fallback
                    self._apply_scope_height(label, height, source)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _apply_scope_height(self, label: str, height: float, source: Optional[str]) -> None:
        entry_label = f"{label} ({height:.2f}\" center)"
        self._ensure_mount_option(entry_label, height, source)
        self.mount_var.set(entry_label)
        info = source or "manufacturer data"
        self.scope_status.set(f"{label}: using {height:.2f}\" center ({info}).")
        self._update_state()

    def _ensure_mount_option(self, label: str, height: float | None, source: str | None) -> None:
        for existing_label, _ in self.mount_options:
            if existing_label == label:
                if source:
                    self.mount_sources[existing_label] = source
                return
        self.mount_options.append((label, height))
        self.mount_sources[label] = source
        values = [name for name, _ in self.mount_options]
        self.mount_combo.configure(values=values)

def main():
    App().mainloop()


if __name__ == "__main__":
    main()
    def _on_use_pins_toggle(self) -> None:
        use_pins = self.use_pins_only.get()
        state = "disabled" if use_pins else "normal"
        self.range_entry.configure(state=state)
        self.bearing_entry.configure(state=state)
