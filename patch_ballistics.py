import re, math
from pathlib import Path

p = Path(r"G:\BallisticTarget\src\BallisticTargetGUI.py")
code = p.read_text(encoding="utf-8", errors="replace")

# Find the existing calculate_ballistics() block (from "def calculate_ballistics(" to the next blank line after return)
pat = r"(?s)^def\s+calculate_ballistics\([^\n]*\n.*?\n\s*return[^\n]*\n"
m = re.search(pat, code, flags=re.M)
if not m:
    raise SystemExit("Could not find calculate_ballistics() block to replace.")

new_func = """def calculate_ballistics(range_yd, velocity_fps, bc, sight_height_in, zero_range_yd, temp_F, altitude_ft):
    \"\"\"Simple, stable ballistics approximation.

    Not a full G1 drag model. This is a practical approximation that:
      - stays stable (never negative velocity)
      - gives reasonable velocity decay
      - uses consistent units
    \"\"\"
    G_FTPS2 = 32.174

    range_ft = float(range_yd) * 3.0  # yards -> feet

    rho_ratio = calculate_air_density(altitude_ft, temp_F)

    bc = float(bc)
    if bc <= 0:
        bc = 0.05

    v0 = float(velocity_fps)
    if v0 <= 0:
        v0 = 1.0

    # exponential velocity decay (tuned for "reasonable" rifle results)
    k = 0.00035 * rho_ratio / bc  # per-yard
    vel_r = v0 * math.exp(-k * float(range_yd))
    vel_r = max(vel_r, 1.0)

    # TOF using average velocity (trapezoid approx)
    v_avg = (v0 + vel_r) / 2.0
    tof = range_ft / v_avg

    # gravity drop (inches)
    drop_in = 0.5 * G_FTPS2 * (tof ** 2) * 12.0

    # compute a simple "sight angle" using zero range
    zero_ft = float(zero_range_yd) * 3.0
    if zero_ft <= 0:
        zero_ft = 1.0
    sight_height_ft = float(sight_height_in) / 12.0

    vel_zero = v0 * math.exp(-k * float(zero_range_yd))
    vel_zero = max(vel_zero, 1.0)
    vavg_zero = (v0 + vel_zero) / 2.0
    tof_zero = zero_ft / vavg_zero
    drop_zero_ft = 0.5 * G_FTPS2 * (tof_zero ** 2)

    tan_theta = (sight_height_ft + drop_zero_ft) / zero_ft
    sight_angle_deg = math.degrees(math.atan(tan_theta))

    return drop_in, vel_r, tof, sight_angle_deg
"""

code2 = re.sub(pat, new_func + "\n", code, count=1, flags=re.M)
p.write_text(code2, encoding="utf-8")
print("OK: Replaced calculate_ballistics() with stable velocity/TOF model.")
