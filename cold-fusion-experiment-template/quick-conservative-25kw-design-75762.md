# Quick Conservative Home Power Design (ZIP 75762)

## Target

- Peak capability: 25 kW
- Night stability target: full-night operation with managed loads
- Design style: conservative, non-fuel, non-nuclear

## System Size (Conservative)

- Solar PV: 36 kW DC
- Inverter capacity: 30 kW AC continuous (hybrid)
- Battery storage: 160 kWh usable

## One-Line Architecture

`PV Array (36 kW DC)` -> `Hybrid Inverter Stack (30 kW AC)` <-> `Battery Bank (160 kWh usable)` -> `Main Service + Critical Loads Subpanel`

## Equipment Count Estimate

## 1) PV Array

- Panel assumption: 450 W modules
- Quantity: 80 panels (80 x 450 W = 36,000 W)
- Mounting: roof/ground mixed as needed
- Stringing: split across multiple MPPT inputs per inverter stack

## 2) Inverters

- Hybrid inverter stack: 30 kW total continuous
- Practical build: 3 x 10 kW hybrid inverters in parallel
- Output: 120/240 V split-phase service integration (US residential)

## 3) Battery

- Usable target: 160 kWh
- If battery modules are 10 kWh nominal with 90% usable depth:
1. Required nominal = 160 / 0.90 = 177.8 kWh
2. Practical module count = 18 modules (18 x 10 = 180 kWh nominal, ~162 kWh usable)

## 4) Balance of System (Major)

- DC combiners and string fusing
- DC/AC disconnects per code
- Battery disconnect and overcurrent protection
- Interconnection breaker at main panel
- Critical loads subpanel + transfer logic
- Surge protection devices (DC and AC)
- Grounding/bonding hardware

## Control Strategy for Stable Night Operation

- Priority 1 (always on): refrigeration, internet/network, lighting, essential outlets
- Priority 2 (managed): HVAC compressor, water heating, large appliances
- Priority 3 (shed first): EV charging, pool pumps, nonessential loads

Use automatic load shedding based on:
- battery state of charge,
- inverter loading,
- time-of-use window.

## Design Math Snapshot

- Battery runtime formula: `Runtime (h) = usable_kWh / average_night_kW`
- With 162 kWh usable:
1. At 8 kW average: ~20.3 h
2. At 10 kW average: ~16.2 h
3. At 12 kW average: ~13.5 h
4. At 15 kW average: ~10.8 h

## Implementation Notes

- Final electrical design must be stamped/approved by a licensed electrician/engineer and AHJ utility requirements.
- Confirm roof area, shading, and structural load before final panel layout.
- Verify utility interconnection and export/import rules before procurement.

## Next Data Needed to Finalize

1. 12 months of utility kWh usage
2. Actual nighttime average kW target
3. Roof/ground available area and azimuth/tilt constraints
4. Critical-load list (must-run circuits)
