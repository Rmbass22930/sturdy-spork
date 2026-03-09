#!/usr/bin/env python3
"""
Compute target + path pins for ballistic planning using lat/lon, rangefinder distance,
and a cardinal direction or explicit bearing. Mirrors the GUI helper so you can test
from the CLI or integrate with other scripts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from geo_projection import (
    ProjectionError,
    format_elevation,
    project_path,
    project_path_between_points,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Project a target pin using rangefinder distance and direction. "
            "Provide shooter latitude/longitude, a direction (N/NE/etc.), or an explicit bearing."
        )
    )
    parser.add_argument("--lat", type=float, required=True, help="Shooter latitude in decimal degrees.")
    parser.add_argument("--lon", type=float, required=True, help="Shooter longitude in decimal degrees.")
    parser.add_argument(
        "--yards",
        type=float,
        default=None,
        help="Rangefinder distance in yards (required unless Point B lat/lon are provided).",
    )
    parser.add_argument(
        "--direction",
        type=str,
        default=None,
        help="Cardinal/ordinal direction (e.g., N, S, E, W, NE, SW). Case-insensitive.",
    )
    parser.add_argument(
        "--bearing",
        type=float,
        default=None,
        help="Optional explicit bearing in degrees (0°=north, 90°=east). Overrides --direction if set.",
    )
    parser.add_argument(
        "--points",
        type=int,
        default=2,
        help="Number of equally spaced points to report along the path (>=2, default: 2 for shooter+target).",
    )
    parser.add_argument(
        "--start-elev",
        type=float,
        default=None,
        help="Shooter elevation above sea level (numeric value in --elev-unit).",
    )
    parser.add_argument(
        "--end-elev",
        type=float,
        default=None,
        help="Target elevation above sea level (numeric value in --elev-unit).",
    )
    parser.add_argument(
        "--target-lat",
        type=float,
        default=None,
        help="Optional Point B latitude. If both lat/lon are provided, overrides direction/bearing.",
    )
    parser.add_argument(
        "--target-lon",
        type=float,
        default=None,
        help="Optional Point B longitude. Requires --target-lat.",
    )
    parser.add_argument(
        "--elev-unit",
        type=str,
        default="ft",
        choices=["ft", "feet", "foot", "m", "meter", "meters"],
        help="Input/output unit for elevations (default: feet).",
    )
    parser.add_argument(
        "--precision",
        type=int,
        default=6,
        help="Decimal places for printed latitude/longitude (default: 6).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the result as compact JSON instead of human-readable text.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.target_lat is not None and args.target_lon is not None:
            result = project_path_between_points(
                args.lat,
                args.lon,
                args.target_lat,
                args.target_lon,
                points=args.points,
                start_elev=args.start_elev,
                end_elev=args.end_elev,
                elev_unit=args.elev_unit,
            )
        else:
            if args.yards is None:
                raise ProjectionError("Specify --yards when Point B latitude/longitude are omitted.")
            result = project_path(
                args.lat,
                args.lon,
                args.yards,
                direction=args.direction,
                bearing_deg=args.bearing,
                points=args.points,
                start_elev=args.start_elev,
                end_elev=args.end_elev,
                elev_unit=args.elev_unit,
            )
    except ProjectionError as exc:
        raise SystemExit(str(exc))

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    precision = max(0, args.precision)
    fmt = f"{{:.{precision}f}}"
    shooter = result["shooter"]
    target = result["target"]
    computed = result["computed"]
    print("Shooter pin : ", fmt.format(shooter["lat"]), ", ", fmt.format(shooter["lon"]), sep="")
    print("Target pin  : ", fmt.format(target["lat"]), ", ", fmt.format(target["lon"]), sep="")
    bearing_value = result["input"]["bearing_deg"]
    direction = result["input"].get("direction") or "-"
    print(f"Bearing     : {bearing_value:.2f}° ({direction})")
    print(f"Distance    : {result['input']['yards']:.2f} yd = {computed['distance_m']:.2f} m")
    print(f"Return az   : {computed['return_bearing_deg']:.2f}° (from target back to shooter)")
    shooter_elev = shooter.get("elev_m")
    target_elev = target.get("elev_m")
    if shooter_elev is not None:
        print("Shooter elev: ", format_elevation(shooter_elev, args.elev_unit, precision), sep="")
    if target_elev is not None:
        print("Target elev : ", format_elevation(target_elev, args.elev_unit, precision), sep="")
    slope = computed.get("slope_percent")
    if slope is not None:
        slope_desc = "uphill" if slope > 0 else "downhill" if slope < 0 else "level"
        print(f"Slope       : {slope:.2f}% ({slope_desc})")

    path = result["path"]
    if len(path) > 2:
        print("Path points :")
        for idx, point in enumerate(path, start=1):
            line = f"  {idx:02d}: {fmt.format(point['lat'])}, {fmt.format(point['lon'])}"
            elev_m = point.get("elev_m")
            if elev_m is not None:
                line += f", elev={format_elevation(elev_m, args.elev_unit, precision)}"
            print(line)


if __name__ == "__main__":
    main()
