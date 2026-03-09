import json
import math
import re
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from bs4 import BeautifulSoup


HOME_CACHE = Path.home() / ".ballistictarget" / "cache"
HOME_CACHE.mkdir(parents=True, exist_ok=True)

HTTP_USER_AGENT = "BallisticTarget/2026.02 (support@ballistictarget.app)"
SEARCH_HEADERS = {"User-Agent": HTTP_USER_AGENT, "Accept-Language": "en-US,en;q=0.8"}

PROJECTILES_VERSION = "1.0.0"
PROJECTILES_TAR = f"https://registry.npmjs.org/projectiles/-/projectiles-{PROJECTILES_VERSION}.tgz"
PROJECTILES_JSON = HOME_CACHE / "projectiles.json"

PROJECTILES_CACHE: Optional[list[dict[str, Any]]] = None

BRAND_KEYWORDS = {
    "hornady": "Hornady",
    "federal": "Federal Ammunition",
    "winchester": "Winchester",
    "barnes": "Barnes",
    "nosler": "Nosler",
    "berger": "Berger",
    "sierra": "Sierra",
    "remington": "Remington",
    "lapua": "Lapua",
    "speer": "Speer",
    "norma": "Norma Precision",
    "norma precision": "Norma Precision",
    "aguila": "Aguila",
    "american eagle": "American Eagle",
    "barnaul": "Barnaul Ammunition",
    "bellot": "Sellier & Bellot",
    "blazer brass": "Blazer Brass",
    "blazer": "Blazer Brass",
    "brownell": "Brownells",
    "brownells": "Brownells",
    "cbc global ammunition": "CBC Global Ammunition",
    "cbc global": "CBC Global Ammunition",
    "cbc": "CBC Global Ammunition",
    "cci": "CCI",
    "cascade cartridge": "CCI",
    "duke defense": "Duke Defense",
    "duke defence": "Duke Defense",
    "fiocchi": "Fiocchi",
    "freedom munitions": "Freedom Munitions",
    "geco": "Geco",
    "magtech": "Magtech",
    "mkek": "MKEK",
    "mechanical and chemical industry": "MKEK",
    "pmc": "PMC Ammunition",
    "prvi partizan": "Prvi Partizan",
    "prvi": "Prvi Partizan",
    "ppu": "Prvi Partizan",
    "rws": "RWS",
    "rottweil": "RWS",
    "sako": "Sako",
    "sellier & bellot": "Sellier & Bellot",
    "sellier and bellot": "Sellier & Bellot",
    "sellier": "Sellier & Bellot",
    "tula": "Tula Ammunition",
    "wolf performance ammunition": "Wolf Performance Ammunition",
    "wolf performance": "Wolf Performance Ammunition",
    "wolf": "Wolf Performance Ammunition",
}

CARTRIDGE_DB = {
    ".308 Winchester": {
        "patterns": [".308", "308 winchester", "308 win", "7.62x51", "7.62×51", "7.62 nato"],
        "wiki_title": ".308 Winchester",
        "bullet_diameter_in": 0.308,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    "6.5mm Creedmoor": {
        "patterns": ["6.5 creedmoor", "65 creedmoor", "6.5mm creedmoor"],
        "wiki_title": "6.5mm Creedmoor",
        "bullet_diameter_in": 0.264,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    "6.5 PRC": {
        "patterns": ["6.5 prc", "65 prc"],
        "wiki_title": "6.5 PRC",
        "bullet_diameter_in": 0.264,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 22.0,
    },
    "6mm Creedmoor": {
        "patterns": ["6 creedmoor", "6mm creedmoor"],
        "wiki_title": "6mm Creedmoor",
        "bullet_diameter_in": 0.243,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 18.0,
    },
    "5.56×45mm NATO": {
        "patterns": ["5.56", "5.56x45", "5.56×45", "223 rem", ".223", "223 remington", "5.56 nato"],
        "wiki_title": "5.56×45mm NATO",
        "bullet_diameter_in": 0.224,
        "reference_barrel_in": 20.0,
        "fps_per_inch": 25.0,
    },
    ".223 Wylde": {
        "patterns": ["223 wylde"],
        "wiki_title": "5.56×45mm NATO",
        "bullet_diameter_in": 0.224,
        "reference_barrel_in": 20.0,
        "fps_per_inch": 25.0,
    },
    ".300 AAC Blackout": {
        "patterns": ["300 blackout", "300 blk", "300 aac", ".300 blackout"],
        "wiki_title": ".300 AAC Blackout",
        "bullet_diameter_in": 0.308,
        "reference_barrel_in": 16.0,
        "fps_per_inch": 15.0,
    },
    "6mm ARC": {
        "patterns": ["6mm arc", "6 arc"],
        "wiki_title": "6 mm Advanced Rifle Cartridge",
        "bullet_diameter_in": 0.243,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 18.0,
    },
    ".30-06 Springfield": {
        "patterns": ["30-06", "30 06", ".30-06", "3006", "30-06 springfield"],
        "wiki_title": ".30-06 Springfield",
        "bullet_diameter_in": 0.308,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    ".300 Winchester Magnum": {
        "patterns": ["300 win mag", ".300 win mag", "300wm", "300 winchester magnum"],
        "wiki_title": ".300 Winchester Magnum",
        "bullet_diameter_in": 0.308,
        "reference_barrel_in": 26.0,
        "fps_per_inch": 22.0,
    },
    "7mm Remington Magnum": {
        "patterns": ["7mm rem mag", "7 mm remington magnum"],
        "wiki_title": "7mm Remington Magnum",
        "bullet_diameter_in": 0.284,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 22.0,
    },
    ".270 Winchester": {
        "patterns": ["270 winchester", ".270 win", "270 win"],
        "wiki_title": ".270 Winchester",
        "bullet_diameter_in": 0.277,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    ".243 Winchester": {
        "patterns": ["243 win", ".243 winchester"],
        "wiki_title": ".243 Winchester",
        "bullet_diameter_in": 0.243,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 18.0,
    },
    ".30-30 Winchester": {
        "patterns": ["30-30", ".30-30", "30 30 winchester"],
        "wiki_title": ".30-30 Winchester",
        "bullet_diameter_in": 0.308,
        "reference_barrel_in": 20.0,
        "fps_per_inch": 15.0,
    },
    ".338 Lapua Magnum": {
        "patterns": ["338 lapua", ".338 lapua", "338 lm"],
        "wiki_title": ".338 Lapua Magnum",
        "bullet_diameter_in": 0.338,
        "reference_barrel_in": 27.0,
        "fps_per_inch": 18.0,
    },
    ".450 Bushmaster": {
        "patterns": ["450 bushmaster"],
        "wiki_title": ".450 Bushmaster",
        "bullet_diameter_in": 0.452,
        "reference_barrel_in": 20.0,
        "fps_per_inch": 12.0,
    },
    "6.8 Western": {
        "patterns": ["6.8 western", "68 western"],
        "wiki_title": "6.8 Western",
        "bullet_diameter_in": 0.277,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    ".224 Valkyrie": {
        "patterns": ["224 valkyrie"],
        "wiki_title": ".224 Valkyrie",
        "bullet_diameter_in": 0.224,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    "7.62×39mm": {
        "patterns": ["7.62x39", "7.62×39", "762x39", "ak round"],
        "wiki_title": "7.62×39mm",
        "bullet_diameter_in": 0.311,
        "reference_barrel_in": 20.5,
        "fps_per_inch": 12.0,
    },
    "6.5 Grendel": {
        "patterns": ["6.5 grendel", "65 grendel"],
        "wiki_title": "6.5mm Grendel",
        "bullet_diameter_in": 0.264,
        "reference_barrel_in": 24.0,
        "fps_per_inch": 20.0,
    },
    "5.45×39mm": {
        "patterns": ["5.45x39", "5.45×39", "545x39"],
        "wiki_title": "5.45×39mm",
        "bullet_diameter_in": 0.221,
        "reference_barrel_in": 16.0,
        "fps_per_inch": 22.0,
    },
    "9mm Luger": {
        "patterns": ["9mm", "9x19", "9mm luger", "9mm parabellum", "9×19"],
        "wiki_title": "9×19mm Parabellum",
        "bullet_diameter_in": 0.355,
        "reference_barrel_in": 4.0,
        "fps_per_inch": 35.0,
    },
    ".45 ACP": {
        "patterns": ["45 acp", ".45 acp", "45 auto"],
        "wiki_title": ".45 ACP",
        "bullet_diameter_in": 0.451,
        "reference_barrel_in": 5.0,
        "fps_per_inch": 30.0,
    },
    ".40 S&W": {
        "patterns": [".40 s&w", "40 s&w", "40 sw"],
        "wiki_title": ".40 S&W",
        "bullet_diameter_in": 0.4,
        "reference_barrel_in": 4.0,
        "fps_per_inch": 35.0,
    },
    ".380 ACP": {
        "patterns": ["380 acp", ".380 acp", "380 auto"],
        "wiki_title": ".380 ACP",
        "bullet_diameter_in": 0.355,
        "reference_barrel_in": 3.7,
        "fps_per_inch": 45.0,
    },
    ".357 Magnum": {
        "patterns": [".357 mag", "357 magnum", "357 mag"],
        "wiki_title": ".357 Magnum",
        "bullet_diameter_in": 0.357,
        "reference_barrel_in": 6.0,
        "fps_per_inch": 30.0,
    },
    ".44 Remington Magnum": {
        "patterns": [".44 mag", "44 magnum", "44 rem mag"],
        "wiki_title": ".44 Remington Magnum",
        "bullet_diameter_in": 0.429,
        "reference_barrel_in": 6.0,
        "fps_per_inch": 25.0,
    },
    "10mm Auto": {
        "patterns": ["10mm auto", "10 mm auto", "10mm"],
        "wiki_title": "10mm Auto",
        "bullet_diameter_in": 0.4,
        "reference_barrel_in": 5.0,
        "fps_per_inch": 30.0,
    },
    ".38 Special": {
        "patterns": [".38 special", "38 spl", "38 special"],
        "wiki_title": ".38 Special",
        "bullet_diameter_in": 0.357,
        "reference_barrel_in": 6.0,
        "fps_per_inch": 22.0,
    },
    ".357 SIG": {
        "patterns": ["357 sig", ".357 sig"],
        "wiki_title": ".357 SIG",
        "bullet_diameter_in": 0.355,
        "reference_barrel_in": 4.0,
        "fps_per_inch": 35.0,
    },
    ".22 Long Rifle": {
        "patterns": [".22 lr", "22 lr", "22 long rifle", "22lr"],
        "wiki_title": ".22 Long Rifle",
        "bullet_diameter_in": 0.223,
        "reference_barrel_in": 16.0,
        "fps_per_inch": 18.0,
    },
}

CARTRIDGE_DEFAULT_VELOCITIES = {
    ".308 Winchester": 2820.0,
    "6.5mm Creedmoor": 2710.0,
    "6.5 PRC": 2960.0,
    "6mm Creedmoor": 2960.0,
    "5.56×45mm NATO": 3240.0,
    ".223 Wylde": 3215.0,
    ".300 AAC Blackout": 2350.0,
    "6mm ARC": 2750.0,
    ".30-06 Springfield": 2850.0,
    ".300 Winchester Magnum": 2960.0,
    "7mm Remington Magnum": 3100.0,
    ".270 Winchester": 3060.0,
    ".243 Winchester": 2960.0,
    ".30-30 Winchester": 2390.0,
    ".338 Lapua Magnum": 2950.0,
    ".450 Bushmaster": 2200.0,
    "6.8 Western": 2970.0,
    ".224 Valkyrie": 2750.0,
    "7.62×39mm": 2350.0,
    "6.5 Grendel": 2650.0,
    "5.45×39mm": 2900.0,
    "9mm Luger": 1150.0,
    ".45 ACP": 850.0,
    ".40 S&W": 1000.0,
    ".380 ACP": 950.0,
    ".357 Magnum": 1250.0,
    ".44 Remington Magnum": 1350.0,
    "10mm Auto": 1250.0,
    ".38 Special": 900.0,
    ".357 SIG": 1350.0,
    ".22 Long Rifle": 1200.0,
}

MANUAL_AMMO_CATALOG: dict[str, list[dict[str, Any]]] = {
    "Federal Ammunition": [
        {
            "name": "Federal Gold Medal Match .308 175gr SMK",
            "cartridge": ".308 Winchester",
            "weight_gr": 175.0,
            "bc_g1": 0.505,
            "velocity_fps": 2600.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.308,
            "keywords": ["gold medal", "gmm", "smk"],
        },
        {
            "name": "Federal HST 9mm 124gr +P",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1150.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
            "keywords": ["hst", "9mm"],
        },
    ],
    "Hornady": [
        {
            "name": "Hornady Precision Hunter 6.5 Creedmoor 143gr ELD-X",
            "cartridge": "6.5mm Creedmoor",
            "weight_gr": 143.0,
            "bc_g1": 0.625,
            "velocity_fps": 2700.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.264,
            "keywords": ["precision hunter", "eld-x"],
        },
        {
            "name": "Hornady Critical Duty .45 ACP 220gr FlexLock",
            "cartridge": ".45 ACP",
            "weight_gr": 220.0,
            "bc_g1": 0.2,
            "velocity_fps": 975.0,
            "reference_barrel_in": 5.0,
            "bullet_diameter_in": 0.451,
            "keywords": ["critical duty"],
        },
    ],
    "Remington": [
        {
            "name": "Remington Premier Match .223 77gr",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 77.0,
            "bc_g1": 0.372,
            "velocity_fps": 2790.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.224,
            "keywords": ["premier match"],
        },
        {
            "name": "Remington Golden Saber .40 S&W 180gr",
            "cartridge": ".40 S&W",
            "weight_gr": 180.0,
            "bc_g1": 0.165,
            "velocity_fps": 1015.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.4,
            "keywords": ["golden saber"],
        },
    ],
    "Winchester": [
        {
            "name": "Winchester Deer Season XP .300 Win Mag 180gr",
            "cartridge": ".300 Winchester Magnum",
            "weight_gr": 180.0,
            "bc_g1": 0.5,
            "velocity_fps": 2960.0,
            "reference_barrel_in": 26.0,
            "bullet_diameter_in": 0.308,
            "keywords": ["deer season"],
        },
        {
            "name": "Winchester Ranger T-Series 9mm 147gr",
            "cartridge": "9mm Luger",
            "weight_gr": 147.0,
            "bc_g1": 0.19,
            "velocity_fps": 990.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
            "keywords": ["ranger", "t-series"],
        },
    ],
    "CBC Global Ammunition": [
        {
            "name": "CBC 7.62 NATO 147gr FMJ",
            "cartridge": ".308 Winchester",
            "weight_gr": 147.0,
            "bc_g1": 0.398,
            "velocity_fps": 2750.0,
            "reference_barrel_in": 22.0,
            "bullet_diameter_in": 0.308,
            "keywords": ["cbc"],
        },
        {
            "name": "CBC .380 ACP 95gr FMJ",
            "cartridge": ".380 ACP",
            "weight_gr": 95.0,
            "bc_g1": 0.12,
            "velocity_fps": 950.0,
            "reference_barrel_in": 3.7,
            "bullet_diameter_in": 0.355,
            "keywords": ["cbc"],
        },
    ],
    "Lapua": [
        {
            "name": "Lapua Scenar-L 6.5 Creedmoor 136gr",
            "cartridge": "6.5mm Creedmoor",
            "weight_gr": 136.0,
            "bc_g1": 0.545,
            "velocity_fps": 2750.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.264,
            "keywords": ["scenar"],
        },
        {
            "name": "Lapua 9mm 123gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 123.0,
            "bc_g1": 0.15,
            "velocity_fps": 1180.0,
            "reference_barrel_in": 4.5,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Norma Precision": [
        {
            "name": "Norma BondStrike .308 180gr",
            "cartridge": ".308 Winchester",
            "weight_gr": 180.0,
            "bc_g1": 0.615,
            "velocity_fps": 2625.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.308,
            "keywords": ["bondstrike"],
        },
        {
            "name": "Norma MHP 9mm 108gr",
            "cartridge": "9mm Luger",
            "weight_gr": 108.0,
            "bc_g1": 0.13,
            "velocity_fps": 1310.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
            "keywords": ["mhp"],
        },
    ],
    "Blazer Brass": [
        {
            "name": "Blazer Brass .223 55gr FMJ",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 55.0,
            "bc_g1": 0.269,
            "velocity_fps": 3240.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
        },
        {
            "name": "Blazer Brass 9mm 115gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 115.0,
            "bc_g1": 0.145,
            "velocity_fps": 1145.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Speer": [
        {
            "name": "Speer Gold Dot .308 168gr",
            "cartridge": ".308 Winchester",
            "weight_gr": 168.0,
            "bc_g1": 0.508,
            "velocity_fps": 2650.0,
            "reference_barrel_in": 22.0,
            "bullet_diameter_in": 0.308,
            "keywords": ["gold dot"],
        },
        {
            "name": "Speer Gold Dot .357 SIG 125gr",
            "cartridge": ".357 SIG",
            "weight_gr": 125.0,
            "bc_g1": 0.167,
            "velocity_fps": 1350.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
            "keywords": ["gold dot"],
        },
    ],
    "Tula Ammunition": [
        {
            "name": "Tula 7.62x39 122gr FMJ",
            "cartridge": "7.62×39mm",
            "weight_gr": 122.0,
            "bc_g1": 0.295,
            "velocity_fps": 2330.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.311,
        },
        {
            "name": "Tula 9mm 115gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 115.0,
            "bc_g1": 0.14,
            "velocity_fps": 1180.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "PMC Ammunition": [
        {
            "name": "PMC X-Tac 5.56 62gr M855",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 62.0,
            "bc_g1": 0.307,
            "velocity_fps": 3100.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
            "keywords": ["x-tac", "m855"],
        },
        {
            "name": "PMC Bronze .45 ACP 230gr FMJ",
            "cartridge": ".45 ACP",
            "weight_gr": 230.0,
            "bc_g1": 0.195,
            "velocity_fps": 830.0,
            "reference_barrel_in": 5.0,
            "bullet_diameter_in": 0.451,
        },
    ],
    "Sellier & Bellot": [
        {
            "name": "Sellier & Bellot .300 BLK 124gr FMJ",
            "cartridge": ".300 AAC Blackout",
            "weight_gr": 124.0,
            "bc_g1": 0.275,
            "velocity_fps": 2230.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "Sellier & Bellot 9mm 124gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1180.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Brownells": [
        {
            "name": "Brownells 5.56 55gr FMJ",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 55.0,
            "bc_g1": 0.269,
            "velocity_fps": 3240.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
        },
        {
            "name": "Brownells .357 Magnum 158gr SJHP",
            "cartridge": ".357 Magnum",
            "weight_gr": 158.0,
            "bc_g1": 0.205,
            "velocity_fps": 1235.0,
            "reference_barrel_in": 6.0,
            "bullet_diameter_in": 0.357,
        },
    ],
    "Aguila": [
        {
            "name": "Aguila 5.56 62gr FMJ",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 62.0,
            "bc_g1": 0.304,
            "velocity_fps": 3150.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
        },
        {
            "name": "Aguila Super Extra .22 LR 40gr",
            "cartridge": ".22 Long Rifle",
            "weight_gr": 40.0,
            "bc_g1": 0.12,
            "velocity_fps": 1255.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.223,
        },
    ],
    "Freedom Munitions": [
        {
            "name": "Freedom Munitions 6.5 Creedmoor 140gr BTHP",
            "cartridge": "6.5mm Creedmoor",
            "weight_gr": 140.0,
            "bc_g1": 0.545,
            "velocity_fps": 2690.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.264,
        },
        {
            "name": "Freedom Munitions 10mm Auto 180gr RNFP",
            "cartridge": "10mm Auto",
            "weight_gr": 180.0,
            "bc_g1": 0.2,
            "velocity_fps": 1250.0,
            "reference_barrel_in": 5.0,
            "bullet_diameter_in": 0.4,
        },
    ],
    "Fiocchi": [
        {
            "name": "Fiocchi Exacta .223 69gr",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 69.0,
            "bc_g1": 0.355,
            "velocity_fps": 2850.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
            "keywords": ["exacta"],
        },
        {
            "name": "Fiocchi .380 ACP 95gr FMJ",
            "cartridge": ".380 ACP",
            "weight_gr": 95.0,
            "bc_g1": 0.12,
            "velocity_fps": 960.0,
            "reference_barrel_in": 3.7,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Prvi Partizan": [
        {
            "name": "PPU Match .308 168gr HPBT",
            "cartridge": ".308 Winchester",
            "weight_gr": 168.0,
            "bc_g1": 0.462,
            "velocity_fps": 2650.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "PPU 9mm 124gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1145.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "CCI": [
        {
            "name": "CCI AR Tactical .22 LR 40gr",
            "cartridge": ".22 Long Rifle",
            "weight_gr": 40.0,
            "bc_g1": 0.125,
            "velocity_fps": 1200.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.223,
        },
        {
            "name": "CCI Standard Velocity .22 LR 40gr",
            "cartridge": ".22 Long Rifle",
            "weight_gr": 40.0,
            "bc_g1": 0.12,
            "velocity_fps": 1070.0,
            "reference_barrel_in": 6.0,
            "bullet_diameter_in": 0.223,
            "keywords": ["standard velocity"],
        },
    ],
    "Magtech": [
        {
            "name": "Magtech .308 150gr FMJ",
            "cartridge": ".308 Winchester",
            "weight_gr": 150.0,
            "bc_g1": 0.398,
            "velocity_fps": 2820.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "Magtech .40 S&W 180gr FMJ",
            "cartridge": ".40 S&W",
            "weight_gr": 180.0,
            "bc_g1": 0.16,
            "velocity_fps": 990.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.4,
        },
    ],
    "American Eagle": [
        {
            "name": "American Eagle 5.56 55gr FMJ",
            "cartridge": "5.56×45mm NATO",
            "weight_gr": 55.0,
            "bc_g1": 0.269,
            "velocity_fps": 3240.0,
            "reference_barrel_in": 20.0,
            "bullet_diameter_in": 0.224,
        },
        {
            "name": "American Eagle 9mm 124gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1140.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Wolf Performance Ammunition": [
        {
            "name": "Wolf Polyformance 6.5 Grendel 123gr FMJ",
            "cartridge": "6.5 Grendel",
            "weight_gr": 123.0,
            "bc_g1": 0.51,
            "velocity_fps": 2580.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.264,
        },
        {
            "name": "Wolf 9mm 115gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 115.0,
            "bc_g1": 0.145,
            "velocity_fps": 1150.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "RWS": [
        {
            "name": "RWS R50 .22 LR 40gr",
            "cartridge": ".22 Long Rifle",
            "weight_gr": 40.0,
            "bc_g1": 0.125,
            "velocity_fps": 1080.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.223,
        },
        {
            "name": "RWS 9mm 124gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1145.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Sako": [
        {
            "name": "Sako Gamehead Pro .243 100gr",
            "cartridge": ".243 Winchester",
            "weight_gr": 100.0,
            "bc_g1": 0.355,
            "velocity_fps": 2960.0,
            "reference_barrel_in": 24.0,
            "bullet_diameter_in": 0.243,
        },
        {
            "name": "Sako 9mm 124gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1150.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Geco": [
        {
            "name": "Geco .308 170gr Teilmantel",
            "cartridge": ".308 Winchester",
            "weight_gr": 170.0,
            "bc_g1": 0.435,
            "velocity_fps": 2625.0,
            "reference_barrel_in": 22.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "Geco 9mm 115gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 115.0,
            "bc_g1": 0.145,
            "velocity_fps": 1180.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Barnaul Ammunition": [
        {
            "name": "Barnaul 5.45x39 60gr FMJ",
            "cartridge": "5.45×39mm",
            "weight_gr": 60.0,
            "bc_g1": 0.285,
            "velocity_fps": 2890.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.221,
        },
        {
            "name": "Barnaul 9mm 115gr FMJ",
            "cartridge": "9mm Luger",
            "weight_gr": 115.0,
            "bc_g1": 0.14,
            "velocity_fps": 1180.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "Duke Defense": [
        {
            "name": "Duke Defense .300 BLK 110gr TAC-TX",
            "cartridge": ".300 AAC Blackout",
            "weight_gr": 110.0,
            "bc_g1": 0.29,
            "velocity_fps": 2350.0,
            "reference_barrel_in": 16.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "Duke Defense 9mm 124gr +P",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1200.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
        },
    ],
    "MKEK": [
        {
            "name": "MKEK 7.62 NATO 147gr FMJ",
            "cartridge": ".308 Winchester",
            "weight_gr": 147.0,
            "bc_g1": 0.398,
            "velocity_fps": 2750.0,
            "reference_barrel_in": 22.0,
            "bullet_diameter_in": 0.308,
        },
        {
            "name": "MKEK 9mm 124gr NATO",
            "cartridge": "9mm Luger",
            "weight_gr": 124.0,
            "bc_g1": 0.15,
            "velocity_fps": 1250.0,
            "reference_barrel_in": 4.0,
            "bullet_diameter_in": 0.355,
            "keywords": ["nato"],
        },
    ],
}

_dynamic_cartridge_cache: dict[str, dict[str, Any]] = {}


@dataclass
class AmmoWebData:
    cartridge_title: Optional[str]
    muzzle_velocity_fps: Optional[float]
    velocity_source: Optional[str]
    reference_barrel_in: Optional[float]
    fps_per_inch: float
    bc_g1: Optional[float]
    bc_source: Optional[str]
    bullet_weight_gr: Optional[float]
    bullet_diameter_in: Optional[float]
    bullet_description: Optional[str]


@dataclass
class RifleWebData:
    barrel_length_in: Optional[float]
    twist_rate_in: Optional[float]
    source: Optional[str]


@dataclass
class TwistReport:
    required_twist: Optional[float]
    actual_twist: Optional[float]
    bullet_length_in: Optional[float]
    stability_ok: Optional[bool]
    note: Optional[str]


def _download_projectiles() -> None:
    with urllib.request.urlopen(
        urllib.request.Request(PROJECTILES_TAR, headers={"User-Agent": HTTP_USER_AGENT})
    ) as resp:
        data = resp.read()
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            member = tar.getmember("package/data/projectiles.json")
            tar.extract(member, HOME_CACHE)
        extracted = HOME_CACHE / "package" / "data" / "projectiles.json"
        PROJECTILES_JSON.write_bytes(extracted.read_bytes())
    finally:
        tmp_path.unlink(missing_ok=True)
        pkg_dir = HOME_CACHE / "package"
        if pkg_dir.exists():
            import shutil

            shutil.rmtree(pkg_dir, ignore_errors=True)


def _ensure_projectiles_loaded() -> list[dict[str, Any]]:
    global PROJECTILES_CACHE
    if PROJECTILES_CACHE is not None:
        return PROJECTILES_CACHE
    if not PROJECTILES_JSON.exists():
        _download_projectiles()
    PROJECTILES_CACHE = json.loads(PROJECTILES_JSON.read_text(encoding="utf-8"))
    return PROJECTILES_CACHE


def _detect_cartridge(ammo_text: str) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    lowered = ammo_text.lower()
    for title, meta in CARTRIDGE_DB.items():
        if any(pat in lowered for pat in meta["patterns"]):
            return title, meta
    return None, None


def _wiki_search_title(query: str) -> Optional[str]:
    params = urllib.parse.urlencode(
        {"action": "opensearch", "search": query, "limit": 1, "namespace": 0, "format": "json"}
    )
    req = urllib.request.Request(
        f"https://en.wikipedia.org/w/api.php?{params}", headers={"User-Agent": HTTP_USER_AGENT}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    if isinstance(data, list) and len(data) >= 2 and data[1]:
        return data[1][0]
    return None


def _parse_measurement_in(text: str) -> Optional[float]:
    if not text:
        return None
    text = text.replace("\u00a0", " ").lower()
    match = re.search(r"(\d+(?:\.\d+)?)\s*(?:in|inch|inches|\"|′′)", text)
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)\s*mm", text)
    if match:
        return float(match.group(1)) / 25.4
    match = re.search(r"(\d+(?:\.\d+)?)\s*cm", text)
    if match:
        return float(match.group(1)) / 2.54
    return None


def _extract_infobox_value(soup: BeautifulSoup, label_fragment: str) -> Optional[str]:
    infobox = soup.find("table", class_="infobox")
    if not infobox:
        return None
    for row in infobox.find_all("tr"):
        header = row.find("th")
        if not header:
            continue
        if label_fragment.lower() in header.get_text(" ", strip=True).lower():
            data = row.find("td")
            if data:
                return data.get_text(" ", strip=True)
    return None


def _build_meta_from_wiki(title: str) -> Optional[dict[str, Any]]:
    try:
        html = _fetch_wiki_html(title)
    except Exception:
        return None
    soup = BeautifulSoup(html, "lxml")
    bullet_value = _extract_infobox_value(soup, "Bullet diameter")
    barrel_value = _extract_infobox_value(soup, "Test barrel")
    bullet_diameter = _parse_measurement_in(bullet_value or "")
    reference_barrel = _parse_measurement_in(barrel_value or "")
    meta = {
        "patterns": [],
        "wiki_title": title,
        "bullet_diameter_in": bullet_diameter,
        "reference_barrel_in": reference_barrel or 24.0,
        "fps_per_inch": 20.0,
    }
    return meta


def _resolve_cartridge_meta(ammo_text: str) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    title, meta = _detect_cartridge(ammo_text)
    if meta:
        return title, meta
    lowered = ammo_text.lower()
    for cached_title, cached_meta in _dynamic_cartridge_cache.items():
        if cached_title.lower() in lowered:
            return cached_title, cached_meta
    guess_title = _wiki_search_title(ammo_text)
    if not guess_title:
        return None, None
    if guess_title in _dynamic_cartridge_cache:
        return guess_title, _dynamic_cartridge_cache[guess_title]
    meta = _build_meta_from_wiki(guess_title)
    if not meta:
        return None, None
    _dynamic_cartridge_cache[guess_title] = meta
    return guess_title, meta


def _parse_weight(ammo_text: str) -> Optional[float]:
    match = re.search(r"(\d+(?:\.\d+)?)\s*(?:gr|grain)", ammo_text, flags=re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def _detect_brand(ammo_text: str) -> Optional[str]:
    lowered = ammo_text.lower()
    for token, brand in BRAND_KEYWORDS.items():
        if token in lowered:
            return brand
    return None


def _tokenize_keywords(ammo_text: str) -> list[str]:
    tokens = re.split(r"[^A-Za-z0-9\-\+]+", ammo_text.lower())
    keywords = []
    for token in tokens:
        if not token or token.isdigit():
            continue
        if len(token) <= 2:
            continue
        keywords.append(token)
    return keywords


def _match_projectile(
    cartridge_meta: dict[str, Any], weight_gr: Optional[float], brand: Optional[str], keywords: list[str]
) -> Optional[dict[str, Any]]:
    candidates: list[tuple[float, dict[str, Any]]] = []
    projectiles = _ensure_projectiles_loaded()
    target_diameter = cartridge_meta.get("bullet_diameter_in")
    for entry in projectiles:
        try:
            diameter = float(entry.get("diameter_in") or 0.0)
            weight = float(entry.get("weight_gr") or 0.0)
        except ValueError:
            continue
        if target_diameter and abs(diameter - target_diameter) > 0.001:
            continue
        if weight_gr and abs(weight - weight_gr) > 3:
            continue
        score = 0.0
        if brand and entry.get("company", "").lower() == brand.lower():
            score += 3.0
        name_blob = " ".join(
            str(entry.get(field) or "").lower() for field in ("product_name", "description", "name")
        )
        for kw in keywords:
            if kw and kw in name_blob:
                score += 1.5
        if weight_gr and weight:
            score += max(0.0, 1.0 - abs(weight - weight_gr) / max(weight_gr, 1.0))
        if score > 0:
            candidates.append((score, entry))
    if not candidates and projectiles:
        # fallback: closest weight match even if keywords missing
        best_entry = None
        best_delta = float("inf")
        for entry in projectiles:
            try:
                diameter = float(entry.get("diameter_in") or 0.0)
                weight = float(entry.get("weight_gr") or 0.0)
            except ValueError:
                continue
            if target_diameter and abs(diameter - target_diameter) > 0.001:
                continue
            if weight_gr:
                delta = abs(weight - weight_gr)
            else:
                delta = 0.0
            if delta < best_delta:
                best_delta = delta
                best_entry = entry
        if best_entry:
            return best_entry
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _lookup_manual_ammo_entry(
    brand: Optional[str], ammo_text: str, cartridge_title: Optional[str], weight_gr: Optional[float]
) -> Optional[dict[str, Any]]:
    if not brand:
        return None
    entries = MANUAL_AMMO_CATALOG.get(brand)
    if not entries:
        return None
    lowered = ammo_text.lower()

    def _keywords_ok(entry: dict[str, Any]) -> bool:
        keywords = entry.get("keywords")
        if not keywords:
            return True
        return any(keyword in lowered for keyword in keywords)

    def _weight_ok(entry: dict[str, Any]) -> bool:
        target = entry.get("weight_gr")
        if weight_gr is None or target is None:
            return True
        return abs(weight_gr - target) <= 5.0

    normalized_cart = (cartridge_title or "").lower()
    for entry in entries:
        entry_cart = (entry.get("cartridge") or "").lower()
        if normalized_cart and entry_cart == normalized_cart and _keywords_ok(entry) and _weight_ok(entry):
            return entry
    for entry in entries:
        if _keywords_ok(entry) and _weight_ok(entry):
            return entry
    return None


def _fetch_wiki_html(title: str) -> str:
    params = urllib.parse.urlencode(
        {"action": "parse", "page": title, "prop": "text", "format": "json", "formatversion": 2}
    )
    req = urllib.request.Request(
        f"https://en.wikipedia.org/w/api.php?{params}", headers={"User-Agent": HTTP_USER_AGENT}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    if "parse" not in data:
        raise ValueError(f"Wikipedia page not found for {title}")
    return data["parse"]["text"]


def _fetch_cartridge_velocity(title: str, desired_weight: Optional[float]) -> Optional[float]:
    html = _fetch_wiki_html(title)
    soup = BeautifulSoup(html, "lxml")
    infobox = soup.find("table", class_="infobox")
    if infobox is None:
        return None
    ballistic_table = None
    for th in infobox.find_all("th"):
        if "Ballistic performance" in th.get_text(" ", strip=True):
            ballistic_table = th.find_next("table")
            break
    if ballistic_table is None:
        return None
    rows = []
    for tr in ballistic_table.find_all("tr")[1:]:
        cells = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
        if len(cells) < 2:
            continue
        rows.append(cells)
    if not rows:
        return None
    best_row = rows[0]
    if desired_weight:
        target = desired_weight
        best_delta = float("inf")
        for row in rows:
            weight_str = row[0]
            match = re.search(r"(\d+(?:\.\d+)?)\s*gr", weight_str)
            if not match:
                continue
            weight = float(match.group(1))
            delta = abs(weight - target)
            if delta < best_delta:
                best_delta = delta
                best_row = row
    velocity_str = best_row[1]
    match = re.search(r"(\d+(?:,\d+)?(?:\.\d+)?)\s*ft/s", velocity_str)
    if not match:
        return None
    value = float(match.group(1).replace(",", ""))
    return value


def _estimate_bullet_length(weight_gr: float, diameter_in: float) -> Optional[float]:
    if not weight_gr or not diameter_in:
        return None
    weight_g = weight_gr * 0.06479891
    density = 10.2  # g/cm^3 for jacketed lead
    volume_cm3 = weight_g / density
    radius_cm = (diameter_in * 2.54) / 2.0
    area_cm2 = math.pi * radius_cm * radius_cm
    if area_cm2 == 0:
        return None
    length_cm = volume_cm3 / area_cm2
    return length_cm / 2.54


def _parse_barrel_length(text: str) -> Optional[float]:
    match = re.search(r"(\d+(?:\.\d+)?)\s*(?:in|\"|inch)", text)
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)\s*mm", text)
    if match:
        return float(match.group(1)) / 25.4
    return None


def _parse_twist(text: str) -> Optional[float]:
    match = re.search(r"1\s*[:/]\s*(\d+(?:\.\d+)?)", text)
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)\s*(?:in|\"|inch)\s*twist", text)
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)\s*mm\s*twist", text)
    if match:
        return float(match.group(1)) / 25.4
    return None


def _fetch_rifle_infobox(title: str) -> Optional[BeautifulSoup]:
    html = _fetch_wiki_html(title)
    soup = BeautifulSoup(html, "lxml")
    return soup.find("table", class_="infobox")


def _duckduckgo_first_result(query: str) -> Optional[str]:
    try:
        params = urllib.parse.urlencode({"q": query})
        url = f"https://duckduckgo.com/html/?{params}"
        req = urllib.request.Request(url, headers=SEARCH_HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        soup = BeautifulSoup(html, "lxml")
        for link in soup.find_all("a", attrs={"class": "result__a"}, href=True):
            href = link["href"]
            if href.startswith("/l/"):
                parsed = urllib.parse.urlparse(href)
                qs = urllib.parse.parse_qs(parsed.query)
                if "uddg" in qs:
                    href = urllib.parse.unquote(qs["uddg"][0])
            if href.startswith("//"):
                href = "https:" + href
            if href.startswith("http"):
                return href
    except Exception:
        return None
    return None


def _scrape_rifle_specs_from_url(url: str) -> tuple[Optional[float], Optional[float], Optional[str]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None, None, None
    soup = BeautifulSoup(html, "lxml")
    sections: list[str] = []
    for selector in ("table", "section", "article", "div"):
        for node in soup.select(f"{selector}[class*='spec'], {selector}[id*='spec']"):
            sections.append(node.get_text(" ", strip=True))
    if not sections:
        sections.append(soup.get_text(" ", strip=True))
    barrel = None
    twist = None
    for text in sections:
        if barrel is None:
            barrel = _parse_barrel_length(text)
        if twist is None:
            twist = _parse_twist(text)
        if barrel is not None and twist is not None:
            break
    if barrel is None and twist is None:
        return None, None, None
    return barrel, twist, url


def _find_manufacturer_spec_url(rifle_name: str) -> Optional[str]:
    queries = [
        f"{rifle_name} manufacturer specifications",
        f"{rifle_name} barrel length twist rate",
    ]
    for query in queries:
        url = _duckduckgo_first_result(query)
        if url:
            return url
    return None


def fetch_rifle_data(rifle_name: str) -> RifleWebData:
    if not rifle_name.strip():
        raise ValueError("Rifle name is required.")
    search_params = urllib.parse.urlencode(
        {"action": "opensearch", "search": rifle_name, "limit": 1, "namespace": 0, "format": "json"}
    )
    barrel = None
    twist = None
    source_url = None
    try:
        search_req = urllib.request.Request(
            f"https://en.wikipedia.org/w/api.php?{search_params}", headers={"User-Agent": HTTP_USER_AGENT}
        )
        with urllib.request.urlopen(search_req) as resp:
            search_data = json.load(resp)
        title = rifle_name
        if search_data and len(search_data) >= 2 and search_data[1]:
            title = search_data[1][0]
        infobox = _fetch_rifle_infobox(title)
        if infobox is not None:
            for row in infobox.find_all("tr"):
                header = row.find("th")
                if not header:
                    continue
                header_text = header.get_text(" ", strip=True)
                data = row.find("td")
                if not data:
                    continue
                text = data.get_text(" ", strip=True)
                if "Barrel" in header_text:
                    barrel = barrel or _parse_barrel_length(text)
                if "Rifling" in header_text or "Twist" in header_text:
                    twist = twist or _parse_twist(text)
            source_url = f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}"
    except Exception:
        pass

    if barrel is None or twist is None:
        manu_url = _find_manufacturer_spec_url(rifle_name)
        if manu_url:
            manu_barrel, manu_twist, manu_source = _scrape_rifle_specs_from_url(manu_url)
            if manu_barrel is not None:
                barrel = barrel or manu_barrel
            if manu_twist is not None:
                twist = twist or manu_twist
            if manu_source and (manu_barrel is not None or manu_twist is not None):
                source_url = manu_source

    if barrel is None or twist is None:
        lowered = rifle_name.lower()
        for spec in KNOWN_RIFLE_SPECS:
            if all(keyword in lowered for keyword in spec.get("keywords", [])):
                barrel = barrel or spec.get("barrel_length_in")
                twist = twist or spec.get("twist_rate_in")
                if spec.get("source"):
                    source_url = spec["source"]
                break

    return RifleWebData(barrel, twist, source_url)


def fetch_ammo_data(ammo_text: str) -> AmmoWebData:
    if not ammo_text.strip():
        raise ValueError("Ammunition description is required.")
    cartridge_title, meta = _resolve_cartridge_meta(ammo_text)
    weight_gr = _parse_weight(ammo_text)
    brand = _detect_brand(ammo_text)
    keywords = _tokenize_keywords(ammo_text)
    bc_source = "Projectiles dataset"
    bc_value = None
    bullet_desc = None
    bullet_diameter = None
    if meta:
        projectile_entry = _match_projectile(meta, weight_gr, brand, keywords)
        if projectile_entry:
            try:
                bc_value = float(projectile_entry.get("bc_g1") or 0.0) or None
            except ValueError:
                bc_value = None
            bullet_desc = projectile_entry.get("description") or projectile_entry.get("product_name")
            try:
                bullet_diameter = float(projectile_entry.get("diameter_in") or 0.0) or None
            except ValueError:
                bullet_diameter = None
            if weight_gr is None:
                try:
                    weight_gr = float(projectile_entry.get("weight_gr") or 0.0) or None
                except ValueError:
                    weight_gr = None
    manual_entry = _lookup_manual_ammo_entry(brand, ammo_text, cartridge_title, weight_gr)
    if manual_entry:
        entry_cart = manual_entry.get("cartridge")
        if entry_cart and not cartridge_title:
            cartridge_title = entry_cart
            meta = CARTRIDGE_DB.get(entry_cart, meta)
        weight_val = manual_entry.get("weight_gr")
        if weight_val is not None:
            try:
                weight_gr = float(weight_val)
            except (TypeError, ValueError):
                pass
        bc_val = manual_entry.get("bc_g1")
        if bc_val is not None:
            try:
                bc_value = float(bc_val)
                bc_source = f"{brand} preset" if brand else "Preset catalog"
            except (TypeError, ValueError):
                pass
        diameter_val = manual_entry.get("bullet_diameter_in")
        if diameter_val is not None:
            try:
                bullet_diameter = float(diameter_val)
            except (TypeError, ValueError):
                pass
        if manual_entry.get("name"):
            bullet_desc = manual_entry["name"]
    velocity_source = None
    velocity_fps = None
    reference_barrel = None
    fps_per_inch = None
    if meta and meta.get("wiki_title"):
        velocity_source = f"Wikipedia: {meta['wiki_title']}"
        velocity_fps = _fetch_cartridge_velocity(meta["wiki_title"], weight_gr)
        if velocity_fps is None and cartridge_title in CARTRIDGE_DEFAULT_VELOCITIES:
            velocity_fps = CARTRIDGE_DEFAULT_VELOCITIES[cartridge_title]
            velocity_source = f"Preset fallback: {cartridge_title}"
        reference_barrel = meta.get("reference_barrel_in")
        fps_per_inch = meta.get("fps_per_inch") or fps_per_inch
        if bullet_diameter is None:
            bullet_diameter = meta.get("bullet_diameter_in")
    if manual_entry:
        barrel_val = manual_entry.get("reference_barrel_in")
        if barrel_val is not None:
            try:
                reference_barrel = float(barrel_val)
            except (TypeError, ValueError):
                pass
        fps_per_inch_val = manual_entry.get("fps_per_inch")
        if fps_per_inch_val is not None:
            try:
                fps_per_inch = float(fps_per_inch_val)
            except (TypeError, ValueError):
                pass
        velocity_val = manual_entry.get("velocity_fps")
        if velocity_val is not None:
            try:
                velocity_fps = float(velocity_val)
                velocity_source = f"Preset: {manual_entry['name']}"
            except (TypeError, ValueError):
                pass
        diameter_val = manual_entry.get("bullet_diameter_in")
        if diameter_val is not None:
            try:
                bullet_diameter = float(diameter_val)
            except (TypeError, ValueError):
                pass
    if bullet_diameter is None and meta:
        bullet_diameter = meta.get("bullet_diameter_in")
    if fps_per_inch is None:
        fps_per_inch = _estimate_fps_per_inch(bullet_diameter)
    return AmmoWebData(
        cartridge_title,
        velocity_fps,
        velocity_source,
        reference_barrel,
        fps_per_inch,
        bc_value,
        bc_source if bc_value is not None else None,
        weight_gr,
        bullet_diameter,
        bullet_desc,
    )


def _estimate_fps_per_inch(diameter_in: Optional[float]) -> float:
    if not diameter_in:
        return 20.0
    if diameter_in <= 0.225:
        return 25.0
    if diameter_in <= 0.264:
        return 22.0
    if diameter_in <= 0.308:
        return 20.0
    if diameter_in <= 0.338:
        return 18.0
    return 15.0


def build_twist_report(ammo: AmmoWebData, rifle: RifleWebData, muzzle_velocity_fps: Optional[float]) -> TwistReport:
    if ammo.bullet_weight_gr is None or ammo.bullet_diameter_in is None or rifle.twist_rate_in is None:
        return TwistReport(None, rifle.twist_rate_in, None, None, None)
    bullet_length = _estimate_bullet_length(ammo.bullet_weight_gr, ammo.bullet_diameter_in)
    if not bullet_length or bullet_length <= 0:
        return TwistReport(None, rifle.twist_rate_in, None, None, None)
    velocity = muzzle_velocity_fps or ammo.muzzle_velocity_fps or 0.0
    greenhill_c = 150.0 if velocity >= 2800 else 180.0
    required_twist = (greenhill_c * (ammo.bullet_diameter_in ** 2)) / bullet_length
    stability_ok = rifle.twist_rate_in <= required_twist if required_twist else None
    note = None
    if required_twist:
        if stability_ok:
            note = (
                f"Twist check: needs ≤ {required_twist:.1f}\" per turn for this bullet. "
                f"Your rifle is 1:{rifle.twist_rate_in:.1f}\" so stability margin is good."
            )
        else:
            note = (
                f"Twist check: bullet needs ≤ {required_twist:.1f}\" per turn but your rifle is "
                f"1:{rifle.twist_rate_in:.1f}\". Consider lighter bullets."
            )
    return TwistReport(required_twist, rifle.twist_rate_in, bullet_length, stability_ok, note)
KNOWN_RIFLE_SPECS: list[dict[str, Any]] = [
    {
        "keywords": ["palmetto", "pa-10"],
        "barrel_length_in": 18.0,
        "twist_rate_in": 10.0,
        "source": "Palmetto State Armory PA-10 factory specs",
    },
]
