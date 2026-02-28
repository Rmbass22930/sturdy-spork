# Revised Home Power Design (ZIP 75762) - 6 Ton Heat Pump 24/7

## Updated Constraint

- HVAC: 6-ton heat pump assumed to run 24 hours/day
- Target: stable home power with 25 kW-capable service

## Key Assumptions (Conservative)

1. 6-ton heat pump average draw assumption: 6.5-8.5 kW (continuous operation equivalent)
2. Non-HVAC average load: 2-4 kW
3. Total average load planning range: 9-12.5 kW
4. East Texas solar yield used as planning basis (final production depends on exact site/shading/tilt)

## Energy Implication

- Daily energy at 9 kW avg: 216 kWh/day
- Daily energy at 12.5 kW avg: 300 kWh/day

This is significantly above the prior quick design and requires larger PV and storage.

## Revised Conservative System Size

1. Solar PV: 55-70 kW DC (target ~60 kW DC)
2. Inverter capacity: 35-40 kW AC continuous hybrid
3. Battery storage (usable): 200-280 kWh (target ~220 kWh usable)

## Suggested Build Point

- PV: 60.3 kW DC (134 x 450 W modules)
- Inverter stack: 40 kW continuous total (for headroom and compressor cycling)
- Battery bank: 250 kWh nominal (~225 kWh usable at 90% usable depth)

## Runtime Check (225 kWh usable)

- At 9 kW average: 25.0 h
- At 10 kW average: 22.5 h
- At 12.5 kW average: 18.0 h

## One-Line Architecture

`PV Array (~60 kW DC)` -> `Hybrid Inverter Stack (40 kW AC)` <-> `Battery Bank (~225 kWh usable)` -> `Main Panel + Critical Loads + Automated Load Management`

## Required Controls

1. HVAC staging/lockout logic tied to battery SOC and inverter load
2. Priority load tiers with automatic shedding for nonessential loads
3. Reserve SOC floor for overnight reliability
4. Optional pre-cooling strategy in solar-rich afternoon hours

## Practical Notes

1. If true 24/7 compressor operation occurs during severe weather, occasional curtailment of nonessential loads is still recommended.
2. Roof area for ~60 kW may be limiting; ground-mount may be required.
3. Final interconnection and electrical design must be completed by licensed professionals to code/AHJ requirements.

## Next Inputs to Finalize

1. Nameplate and measured draw profile for actual 6-ton heat pump
2. 12-month utility kWh usage
3. Roof + ground mounting area constraints
4. Critical-load circuit list
