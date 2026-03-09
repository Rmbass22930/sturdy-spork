import math

import pytest

from BallisticTargetGUI import EnvGeoDialog, bearing_to_cardinal
from geo_projection import ProjectionError, project_path, project_path_between_points, resolve_bearing


def test_bearing_to_cardinal_primary_axes():
    assert bearing_to_cardinal(0.0) == "N"
    assert bearing_to_cardinal(90.0) == "E"
    assert bearing_to_cardinal(180.0) == "S"
    assert bearing_to_cardinal(270.0) == "W"


def test_bearing_to_cardinal_midpoints_round():
    assert bearing_to_cardinal(33.0) == "NNE"
    assert bearing_to_cardinal(359.0) == "N"


def test_env_geo_dialog_exposes_projection_pin_toggle_callback():
    assert callable(getattr(EnvGeoDialog, "_on_use_pins_toggle", None))


def test_resolve_bearing_from_direction():
    assert resolve_bearing("SE", None) == pytest.approx(135.0)
    with pytest.raises(ProjectionError):
        resolve_bearing("BAD", None)


def test_project_path_even_spacing():
    result = project_path(32.21, -95.45, distance_yards=1200, bearing_deg=45.0, points=4)
    path = result["path"]
    assert len(path) == 4
    # Ensure shooter and target anchors line up with inputs
    assert math.isclose(path[0]["lat"], 32.21, rel_tol=0, abs_tol=1e-6)
    assert math.isclose(path[0]["lon"], -95.45, rel_tol=0, abs_tol=1e-6)
    assert math.isclose(result["input"]["yards"], 1200.0, rel_tol=1e-9)
    # Step vectors between waypoints should progress linearly along the bearing
    lon_steps = [path[i + 1]["lon"] - path[i]["lon"] for i in range(len(path) - 1)]
    lat_steps = [path[i + 1]["lat"] - path[i]["lat"] for i in range(len(path) - 1)]
    assert lon_steps[1] == pytest.approx(lon_steps[0], rel=0.05)
    assert lat_steps[1] == pytest.approx(lat_steps[0], rel=0.05)


def test_project_path_between_points_matches_direct():
    a_lat, a_lon = 32.214, -95.466
    b_lat, b_lon = 32.210, -95.440
    between = project_path_between_points(a_lat, a_lon, b_lat, b_lon, points=3)
    direct = project_path(
        a_lat,
        a_lon,
        distance_yards=between["input"]["yards"],
        bearing_deg=between["input"]["bearing_deg"],
        points=3,
    )
    assert math.isclose(between["target"]["lat"], b_lat, abs_tol=1e-6)
    assert math.isclose(between["target"]["lon"], b_lon, abs_tol=1e-6)
    assert math.isclose(between["input"]["yards"], direct["input"]["yards"], rel_tol=1e-9)
