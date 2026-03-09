from __future__ import annotations

from typing import Any, Final

from geographiclib.geodesic import Geodesic

CARDINAL_BEARINGS: Final[dict[str, float]] = {
    "N": 0.0,
    "NNE": 22.5,
    "NE": 45.0,
    "ENE": 67.5,
    "E": 90.0,
    "ESE": 112.5,
    "SE": 135.0,
    "SSE": 157.5,
    "S": 180.0,
    "SSW": 202.5,
    "SW": 225.0,
    "WSW": 247.5,
    "W": 270.0,
    "WNW": 292.5,
    "NW": 315.0,
    "NNW": 337.5,
}

YARDS_TO_METERS: Final[float] = 0.9144
FEET_TO_METERS: Final[float] = 0.3048


class ProjectionError(ValueError):
    """Domain-specific error for projection inputs."""


def resolve_bearing(direction: str | None, bearing: float | None) -> float:
    if bearing is not None:
        return float(bearing) % 360.0
    if not direction:
        raise ProjectionError("Provide either a cardinal direction or an explicit bearing.")
    value = CARDINAL_BEARINGS.get(direction.strip().upper())
    if value is None:
        raise ProjectionError(
            f"Unknown direction '{direction}'. Expected one of: {', '.join(CARDINAL_BEARINGS.keys())}"
        )
    return value


def yards_to_meters(yards: float) -> float:
    return float(yards) * YARDS_TO_METERS


def convert_elevation_to_meters(value: float | None, unit: str) -> float | None:
    if value is None:
        return None
    key = (unit or "").lower()
    if key in {"ft", "feet", "foot"}:
        return float(value) * FEET_TO_METERS
    if key in {"m", "meter", "meters"}:
        return float(value)
    raise ProjectionError(f"Unsupported elevation unit '{unit}'. Use 'ft' or 'm'.")


def format_elevation(elev_m: float | None, unit: str, precision: int = 2) -> str:
    if elev_m is None:
        return "n/a"
    key = (unit or "").lower()
    if key in {"ft", "feet", "foot"}:
        value = elev_m / FEET_TO_METERS
        suffix = "ft"
    else:
        value = elev_m
        suffix = "m"
    fmt = f"{{:.{precision}f}}"
    return f"{fmt.format(value)} {suffix}"


def project_path(
    shooter_lat: float,
    shooter_lon: float,
    distance_yards: float,
    *,
    direction: str | None = None,
    bearing_deg: float | None = None,
    points: int = 2,
    start_elev: float | None = None,
    end_elev: float | None = None,
    elev_unit: str = "ft",
    target_lat: float | None = None,
    target_lon: float | None = None,
) -> dict[str, Any]:
    if points < 2:
        raise ProjectionError("points must be at least 2 (shooter and target).")
    bearing = resolve_bearing(direction, bearing_deg)
    distance_m = yards_to_meters(distance_yards)

    start_elev_m = convert_elevation_to_meters(start_elev, elev_unit)
    end_elev_m = convert_elevation_to_meters(end_elev, elev_unit)

    line = Geodesic.WGS84.Line(shooter_lat, shooter_lon, bearing)
    coords: list[dict[str, float]] = []
    for idx in range(points):
        frac = idx / (points - 1) if points > 1 else 0.0
        dist = distance_m * frac
        pos = line.Position(dist, Geodesic.STANDARD | Geodesic.LONG_UNROLL)
        point = {"lat": pos["lat2"], "lon": pos["lon2"]}
        if start_elev_m is not None and end_elev_m is not None:
            point["elev_m"] = start_elev_m + (end_elev_m - start_elev_m) * frac
        elif start_elev_m is not None:
            point["elev_m"] = start_elev_m
        elif end_elev_m is not None:
            point["elev_m"] = end_elev_m
        coords.append(point)

    shooter_point = coords[0]
    target_point = coords[-1]

    back = Geodesic.WGS84.Inverse(target_point["lat"], target_point["lon"], shooter_point["lat"], shooter_point["lon"])
    back_az = back["azi1"] % 360.0

    result: dict[str, Any] = {
        "shooter": shooter_point.copy(),
        "target": target_point.copy(),
        "input": {
            "yards": float(distance_yards),
            "bearing_deg": bearing,
            "direction": direction.upper() if direction else None,
            "points": points,
            "target_lat": target_lat,
            "target_lon": target_lon,
        },
        "computed": {
            "distance_m": distance_m,
            "return_bearing_deg": back_az,
        },
        "path": coords,
    }

    if start_elev_m is not None:
        result["shooter"]["elev_m"] = start_elev_m
    if end_elev_m is not None:
        result["target"]["elev_m"] = end_elev_m
    if start_elev_m is not None and end_elev_m is not None and distance_m > 0:
        grade = (end_elev_m - start_elev_m) / distance_m * 100.0
        result["computed"]["slope_percent"] = grade

    return result


def project_path_between_points(
    shooter_lat: float,
    shooter_lon: float,
    target_lat: float,
    target_lon: float,
    *,
    points: int = 2,
    start_elev: float | None = None,
    end_elev: float | None = None,
    elev_unit: str = "ft",
) -> dict[str, Any]:
    inverse = Geodesic.WGS84.Inverse(shooter_lat, shooter_lon, target_lat, target_lon)
    distance_m = inverse["s12"]
    bearing = inverse["azi1"] % 360.0
    distance_yards = distance_m / YARDS_TO_METERS
    return project_path(
        shooter_lat,
        shooter_lon,
        distance_yards,
        direction=None,
        bearing_deg=bearing,
        points=points,
        start_elev=start_elev,
        end_elev=end_elev,
        elev_unit=elev_unit,
        target_lat=target_lat,
        target_lon=target_lon,
    )
