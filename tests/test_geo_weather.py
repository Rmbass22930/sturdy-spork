import pytest

from geo_weather import extract_lat_lon_from_text, fetch_weather_from_services


def test_extract_lat_lon_from_text_supports_apple_loc_query():
    lat, lon = extract_lat_lon_from_text("https://maps.apple.com/?ll=32.214,-95.466&loc=32.210,-95.440")
    assert lat == pytest.approx(32.214)
    assert lon == pytest.approx(-95.466)


def test_extract_lat_lon_from_text_supports_apple_loc_field():
    lat, lon = extract_lat_lon_from_text("https://maps.apple.com/?loc=32.210,-95.440")
    assert lat == pytest.approx(32.210)
    assert lon == pytest.approx(-95.440)


def test_fetch_weather_from_services_returns_unavailable_when_all_providers_fail():
    def fake_fetch_json(_url, extra_headers=None, timeout=10):
        return None

    result = fetch_weather_from_services(32.21, -95.45, fetch_json_fn=fake_fetch_json)
    assert result["source"] == "unavailable"
    assert result["temp_F"] is None
    assert result["wind_speed_mph"] is None


def test_fetch_weather_from_services_parses_open_meteo_payload():
    def fake_fetch_json(url, extra_headers=None, timeout=10):
        if "open-meteo.com" not in url:
            return None
        return {
            "current": {
                "temperature_2m": 71.5,
                "wind_speed_10m": 12.3,
                "wind_direction_10m": 185,
                "wind_gusts_10m": 18.4,
            }
        }

    result = fetch_weather_from_services(32.21, -95.45, fetch_json_fn=fake_fetch_json)
    assert result["source"] == "open-meteo"
    assert result["temp_F"] == pytest.approx(71.5)
    assert result["wind_speed_mph"] == pytest.approx(12.3)
    assert result["wind_dir_deg"] == pytest.approx(185)
    assert result["wind_gust_mph"] == pytest.approx(18.4)
