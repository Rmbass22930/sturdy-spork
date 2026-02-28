# Revised Home Power Design (ZIP 75762) - 5 Ton Heat Pump 24/7

## Updated Constraint

- HVAC: 5-ton heat pump assumed to run 24 hours/day
- Target: stable home power with 25 kW-capable service

## Key Assumptions (Conservative)

1. 5-ton heat pump average draw assumption: 5.0-7.0 kW (continuous operation equivalent)
2. Non-HVAC average load: 2-4 kW
3. Total average load planning range: 7-11 kW
4. East Texas solar yield used as planning basis (final production depends on exact site/shading/tilt)

## Energy Implication

- Daily energy at 7 kW avg: 168 kWh/day
- Daily energy at 11 kW avg: 264 kWh/day

## Revised Conservative System Size

1. Solar PV: 45-60 kW DC (target ~50 kW DC)
2. Inverter capacity: 30-35 kW AC continuous hybrid
3. Battery storage (usable): 160-240 kWh (target ~200 kWh usable)

## Suggested Build Point

- PV: 50.4 kW DC (112 x 450 W modules)
- Inverter stack: 35 kW continuous total
- Battery bank: 225 kWh nominal (~202 kWh usable at 90% usable depth)

## Runtime Check (~202 kWh usable)

- At 7 kW average: 28.9 h
- At 9 kW average: 22.4 h
- At 11 kW average: 18.4 h

## One-Line Architecture

`PV Array (~50 kW DC)` -> `Hybrid Inverter Stack (35 kW AC)` <-> `Battery Bank (~200 kWh usable)` -> `Main Panel + Critical Loads + Automated Load Management`

## Required Controls

1. HVAC staging/lockout logic tied to battery SOC and inverter load
2. Priority load tiers with automatic shedding for nonessential loads
3. Reserve SOC floor for overnight reliability
4. Optional pre-cooling strategy in solar-rich afternoon hours

## Next Inputs to Finalize

1. Nameplate and measured draw profile for actual 5-ton heat pump
2. 12-month utility kWh usage
3. Roof + ground mounting area constraints
4. Critical-load circuit list
