# Constant Output Design - 25 kW Continuous (ZIP 75762)

## Requirement

- Deliver constant electrical output: **25 kW, 24 hours/day**
- Daily energy target: **600 kWh/day**

## Core Math

1. Daily energy = `25 kW x 24 h = 600 kWh/day`
2. Night-only battery need (12 h) = `25 kW x 12 h = 300 kWh usable`
3. If keeping 20% reserve margin: `300 / 0.8 = 375 kWh usable target`

## Conservative System Size (Practical)

1. Solar PV: **160-190 kW DC** (target **~175 kW DC**)
2. Inverter capacity: **40-50 kW AC continuous** (N+1 redundancy recommended)
3. Battery storage: **375-450 kWh usable**

## Suggested Build Point

- PV array: **175.5 kW DC** (390 x 450 W modules)
- Inverter stack: **50 kW AC continuous** total
- Battery bank: **420 kWh nominal** at 90% usable depth (~378 kWh usable)

## Why the PV is so large

To cover 600 kWh/day plus charging losses and cloudy-day variability in 75762, the system needs utility-scale rooftop/ground area. Constant 25 kW 24/7 is far above typical residential energy profiles.

## One-Line Architecture

`PV Array (~175 kW DC)` -> `Hybrid Inverter Plant (50 kW AC)` <-> `Battery Bank (~380 kWh usable)` -> `Main Service / Dedicated 25 kW Output Bus`

## Operational Controls

1. Maintain fixed output bus target at 25 kW.
2. Use battery SOC windows and dispatch logic.
3. Auto-curtail noncritical loads when SOC drops.
4. Use weather forecast charging strategy to protect overnight reliability.

## Site/Build Reality Check

- This is typically a **large estate / small commercial-class** system, not normal home scale.
- Ground-mount solar is likely required.
- Utility interconnection, engineering stamp, and AHJ approvals are mandatory.

## If you want lower cost/size

1. Lower constant output target (for example 10-15 kW constant), or
2. Keep 25 kW peak but not constant, with load management.
