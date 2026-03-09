import pytest

from web_ballistics import fetch_ammo_data


def test_fetch_ammo_data_uses_manual_pistol_catalog():
    ammo = fetch_ammo_data("Federal HST 9mm 124gr +P")

    assert ammo.cartridge_title == "9mm Luger"
    assert ammo.muzzle_velocity_fps == pytest.approx(1150.0)
    assert ammo.reference_barrel_in == pytest.approx(4.0)
    assert ammo.bc_g1 == pytest.approx(0.15, abs=1e-6)
    assert ammo.bc_source == "Federal Ammunition preset"
    assert ammo.bullet_description and "Federal HST" in ammo.bullet_description


def test_fetch_ammo_data_handles_steel_case_brand():
    ammo = fetch_ammo_data("Tula 9mm 115gr FMJ range")

    assert ammo.cartridge_title == "9mm Luger"
    assert ammo.muzzle_velocity_fps == pytest.approx(1180.0)
    assert ammo.bc_g1 == pytest.approx(0.14, abs=1e-6)
    assert ammo.reference_barrel_in == pytest.approx(4.0)
    assert ammo.bullet_diameter_in == pytest.approx(0.355, abs=1e-6)
    assert ammo.bullet_description and "Tula" in ammo.bullet_description
