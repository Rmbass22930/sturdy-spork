# Security Gateway SOC Roadmap

## Positioning
Security Gateway is not a drop-in replacement for Security Onion Pro. The practical path is to grow it into a focused SOC-style control plane around the workflows this repo already supports: policy decisions, endpoint telemetry, malware detection, tracker intelligence, reporting, and operator response.

## Current Baseline
- Zero-trust policy evaluation
- Endpoint telemetry and malware scanning
- Tracker and DNS intelligence
- Operator auth, PAM-backed secrets, and audit logging
- Reports, proxy tooling, and a local desktop launcher

## Phase 1
- Persisted SOC events
- Automatic alert promotion for high and critical events
- Analyst case objects with ownership, notes, and lifecycle state
- Operator APIs for event, alert, case, and overview queries

## Phase 2
- Correlation rules across access denials, endpoint posture drift, malware detections, and tracker blocks
- Triage queues and saved filters
- Case enrichment from existing reports and audit data
- Exportable incident summaries

### Current Phase 2 Implementation
- Correlation alerts for repeated tracker-block activity
- Correlation alerts for endpoints that combine posture problems with risky access outcomes
- Dashboard API summarizing queue state, severity/status counts, active cases, unassigned alerts, and recent correlations
- Desktop analyst queue presets for tier-1 triage, tier-2 investigation, containment, and review views

## Phase 3
- Durable background jobs for event ingestion and alert routing
- Additional host and network telemetry sources
- External integrations for notification delivery and analyst workflow tools
- Broader dashboards and role-based analyst views

## Scope Rule
Each phase should leave the service usable and testable. Avoid pretending the platform has SIEM-scale ingestion or enterprise SOC features before the persistence, analyst workflow, and operational model actually exist.
