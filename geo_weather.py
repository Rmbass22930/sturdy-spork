from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from typing import Any


HTTP_USER_AGENT = "BallisticTarget/2026.02 (support@ballistictarget.app)"
DEFAULT_HTTP_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}
METNO_HEADERS = {
    "User-Agent": HTTP_USER_AGENT,
    "Accept": "application/json",
}


def fetch_json(url: str, extra_headers: dict | None = None, timeout: int = 10) -> dict | None:
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


def ms_to_mph(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value) * 2.236936
    except Exception:
        return None


def extract_lat_lon_from_text(text: str) -> tuple[float | None, float | None]:
    raw = (text or "").strip()
    if not raw:
        return None, None
    manual = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$", raw)
    if manual:
        lat = float(manual.group(1))
        lon = float(manual.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon
        return None, None
    at_pattern = re.search(r"/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if at_pattern:
        return float(at_pattern.group(1)), float(at_pattern.group(2))
    q_pattern = re.search(r"[?&](?:q|ll|query|daddr)=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if q_pattern:
        return float(q_pattern.group(1)), float(q_pattern.group(2))
    apple_pattern = re.search(r"(?:loc|address)=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", raw)
    if apple_pattern:
        return float(apple_pattern.group(1)), float(apple_pattern.group(2))
    try:
        parsed = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qs(parsed.query)
        for key in ("q", "ll", "query", "daddr", "loc", "address"):
            if key not in qs or not qs[key]:
                continue
            candidate = qs[key][0]
            match = re.search(r"(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)", candidate)
            if match:
                return float(match.group(1)), float(match.group(2))
    except Exception:
        return None, None
    return None, None


def fetch_weather_from_services(
    lat: float,
    lon: float,
    *,
    fetch_json_fn=fetch_json,
    weather_cache: Any | None = None,
) -> dict[str, Any]:
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
    data = fetch_json_fn(url)
    if data:
        cur = data.get("current") or {}
        result = {
            "temp_F": float(cur.get("temperature_2m")) if cur.get("temperature_2m") is not None else None,
            "wind_speed_mph": float(cur.get("wind_speed_10m")) if cur.get("wind_speed_10m") is not None else None,
            "wind_dir_deg": float(cur.get("wind_direction_10m")) if cur.get("wind_direction_10m") is not None else None,
            "wind_gust_mph": float(cur.get("wind_gusts_10m")) if cur.get("wind_gusts_10m") is not None else None,
            "source": "open-meteo",
        }
        if weather_cache is not None:
            weather_cache.remember(lat, lon, result)
        return result

    fallback_url = f"https://api.met.no/weatherapi/locationforecast/2.0/compact?lat={lat:.4f}&lon={lon:.4f}"
    fallback = fetch_json_fn(fallback_url, extra_headers=METNO_HEADERS, timeout=12)
    if fallback:
        try:
            times = fallback.get("properties", {}).get("timeseries") or []
            latest = times[0]
            details = latest.get("data", {}).get("instant", {}).get("details", {})
            temp = details.get("air_temperature")
            speed = ms_to_mph(details.get("wind_speed"))
            gust = ms_to_mph(details.get("wind_speed_of_gust"))
            direction = details.get("wind_from_direction")
            result = {
                "temp_F": float(temp) if temp is not None else None,
                "wind_speed_mph": speed,
                "wind_dir_deg": float(direction) if direction is not None else None,
                "wind_gust_mph": gust,
                "source": "met.no",
            }
            if weather_cache is not None:
                weather_cache.remember(lat, lon, result)
            return result
        except Exception:
            pass

    if weather_cache is not None:
        cached, age = weather_cache.fetch(lat, lon)
        if cached:
            cached.setdefault("source", "cache")
            cached["stale_minutes"] = round((age or 0) / 60.0, 1)
            cached["stale"] = True
            return cached

    return {
        "temp_F": None,
        "wind_speed_mph": None,
        "wind_dir_deg": None,
        "wind_gust_mph": None,
        "source": "unavailable",
    }


def fetch_elevation_feet(
    lat: float,
    lon: float,
    *,
    fetch_json_fn=fetch_json,
    elevation_cache: Any | None = None,
) -> float | None:
    base = "https://api.open-meteo.com/v1/elevation"
    params = urllib.parse.urlencode({"latitude": lat, "longitude": lon})
    url = f"{base}?{params}"
    data = fetch_json_fn(url)
    if data:
        elevations = data.get("elevation")
        if isinstance(elevations, list) and elevations:
            meters = elevations[0]
            try:
                value = float(meters) * 3.28084
                if elevation_cache is not None:
                    elevation_cache.remember(lat, lon, {"value": value})
                return value
            except Exception:
                return None

    fallback_url = f"https://api.opentopodata.org/v1/aster30m?locations={lat:.6f},{lon:.6f}"
    fallback = fetch_json_fn(fallback_url, timeout=12)
    if fallback:
        results = fallback.get("results")
        if isinstance(results, list) and results:
            meters = results[0].get("elevation")
            if meters is not None:
                try:
                    value = float(meters) * 3.28084
                    if elevation_cache is not None:
                        elevation_cache.remember(lat, lon, {"value": value})
                    return value
                except Exception:
                    return None

    if elevation_cache is not None:
        cached, _age = elevation_cache.fetch(lat, lon)
        if cached and cached.get("value") is not None:
            return cached.get("value")
    return None
