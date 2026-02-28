# Off Grid Power 2 - 35 kW Peak (Not Constant) with Load Management

## Calculation Basis (Managed Profile)

Assumed daily profile for a 35 kW peak system that is not constant:

1. Peak window: `35 kW x 6 h = 210 kWh/day`
2. Off-peak managed window: `10 kW x 18 h = 180 kWh/day`
3. Daily energy total: `210 + 180 = 390 kWh/day`

## Battery Sizing (Night Reliability)

Using a managed night target instead of full 35 kW:

1. Night load target (12 h at 12 kW): `12 kW x 12 h = 144 kWh usable`
2. With 20% reserve margin: `144 / 0.8 = 180 kWh usable target`
3. Practical battery range: **180-240 kWh usable**

## Conservative Practical System Size

1. Solar PV: **110-140 kW DC** (target **~125 kW DC**)
2. Inverter capacity: **40-50 kW AC continuous** (to support 35 kW peak + headroom)
3. Battery storage: **180-240 kWh usable**

## Suggested Build Point

- PV array: **126.0 kW DC** (280 x 450 W modules)
- Inverter stack: **45 kW AC continuous** total
- Battery bank: **240 kWh nominal** at 90% usable depth (~216 kWh usable)

## One-Line Architecture

`PV Array (~125 kW DC)` -> `Hybrid Inverter Plant (45 kW AC)` <-> `Battery Bank (~216 kWh usable)` -> `Main Service / Managed 35 kW Peak Bus`

## Load Management Controls (Required)

1. Hard-cap output bus at **35 kW peak**.
2. Keep base-load target near **10-12 kW** outside peak windows.
3. Use SOC-based shed tiers for noncritical loads.
4. Pre-charge battery before forecast low-solar periods.

## Site/Build Reality Check

- This remains a large custom system, but smaller than a 25 kW constant 24/7 design.
- Ground-mount PV is still likely for many sites.
- Utility interconnection, stamped engineering, and AHJ approvals are still required.
