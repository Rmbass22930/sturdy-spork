# Security Onion Pro Gap Matrix

## Baseline
This comparison uses the local Security Onion ISO mounted from:
- [securityonion-2.4.211-20260312.iso](E:/FileHistory/murra/MAC1/Data/C/Users/murra/Downloads/securityonion-2.4.211-20260312/securityonion-2.4.211-20260312.iso)

Mounted media observed at:
- [H:\SecurityOnion](H:/SecurityOnion)
- [H:\docker](H:/docker)
- [H:\fleet](H:/fleet)
- [H:\BaseOS](H:/BaseOS)

Concrete shipped components visible on the ISO include:
- Suricata content and configuration: [H:\SecurityOnion\salt\suricata](H:/SecurityOnion/salt/suricata)
- Zeek content and configuration: [H:\SecurityOnion\salt\zeek](H:/SecurityOnion/salt/zeek)
- Strelka file analysis stack: [H:\SecurityOnion\salt\strelka](H:/SecurityOnion/salt/strelka)
- Elastic/ElastAlert/Fleet stack: [H:\SecurityOnion\salt\elasticsearch](H:/SecurityOnion/salt/elasticsearch), [H:\SecurityOnion\salt\elastalert](H:/SecurityOnion/salt/elastalert), [H:\SecurityOnion\salt\elasticfleet](H:/SecurityOnion/salt/elasticfleet), [H:\fleet](H:/fleet)
- PCAP and sensor orchestration: [H:\SecurityOnion\salt\pcap](H:/SecurityOnion/salt/pcap), [H:\SecurityOnion\salt\sensor](H:/SecurityOnion/salt/sensor), [H:\SecurityOnion\salt\sensoroni](H:/SecurityOnion/salt/sensoroni)
- SOC orchestration and Salt state model: [H:\SecurityOnion\salt\soc](H:/SecurityOnion/salt/soc), [H:\SecurityOnion\pillar\soc](H:/SecurityOnion/pillar/soc)
- Container registry payloads: [H:\docker\registry.tar](H:/docker/registry.tar), [H:\docker\registry_image.tar](H:/docker/registry_image.tar)

This document does not remove or redefine existing Security Gateway add-on features. It treats them as preserved local capabilities and focuses only on the missing platform layers needed for parity.

## Current Security Gateway Baseline
Current Security Gateway has:
- desktop launcher and installer/uninstaller
- SOC events, alerts, cases, queues, and dashboard
- host, network, stream, and limited packet monitoring
- alert/case workflow actions
- tracker, DNS, malware, proxy, and reporting features
- operator APIs and local audit logging

Current Security Gateway does not have:
- a real distributed sensor architecture
- a SIEM-grade search and storage layer
- mature IDS/NDR depth
- full packet capture workflow
- fleet/agent management
- production containerized platform orchestration
- enterprise auth/compliance coverage at Security Onion Pro scope

## Gap Matrix
Status meanings:
- `Present`: materially exists now
- `Partial`: some local capability exists, but not at Security Onion Pro depth
- `Missing`: no credible equivalent exists yet

| Capability Area | Security Onion ISO Evidence | Security Gateway Status | Gap |
| --- | --- | --- | --- |
| Installable platform stack | ISO ships OS, Salt states, containers, setup flows | Partial | Security Gateway packages a local app, not a platform stack |
| Sensor architecture | `salt/sensor`, `salt/sensoroni`, `salt/zeek`, `salt/suricata` | Missing | No distributed sensor role model |
| Full packet capture | `salt/pcap`, Suricata PCAP states | Partial | Limited local packet monitor only; no retained PCAP workflow |
| Network IDS/NDR | Suricata and Zeek stacks on media | Missing | No equivalent protocol analysis or IDS rule engine depth |
| File analysis | `salt/strelka` | Partial | Malware scan exists, but not a distributed file detonation/analysis stack |
| Search and analytics | Elasticsearch/Kibana/Logstash/Fleet media and states | Missing | No central search cluster or SIEM query layer |
| Alerting engine | ElastAlert stack on media | Partial | Local alerting exists, but not large-scale rule execution/routing |
| Case management | SOC stack and Pro workflow surface | Partial | Local cases exist, but not enterprise workflow depth |
| Dashboards | Elastic/Kibana and SOC dashboard layers | Partial | Local dashboard exists, but not search-driven analytics dashboards |
| Host visibility | Fleet/Elastic Agent media and config | Partial | Host monitor exists, but no fleet-managed endpoint telemetry platform |
| Multi-node orchestration | Salt/pillar orchestration throughout ISO | Missing | No node roles, orchestration, or distributed state model |
| Manager of Managers | Pro feature | Missing | No multi-grid management layer |
| Connect API | Pro feature | Partial | Local APIs exist, but not Security Onion Connect-equivalent scope |
| MCP server | Pro feature | Partial | Security Gateway has local tooling, but not a platform MCP surface |
| Reports | Pro feature | Partial | Local reports exist, but not platform-wide SOC reporting |
| Notifications | Pro feature | Partial | Popup/alert plumbing exists, but not durable enterprise notification delivery |
| Guaranteed message delivery | Pro feature | Missing | No queue/delivery guarantee layer |
| OIDC/enterprise auth | Pro feature | Missing | Local operator auth exists, not enterprise SSO/OIDC |
| Hypervisor node support | `pillar/hypervisor`, `salt/hypervisor`, `salt/libvirt` | Missing | No hypervisor orchestration layer |
| Splunk app | Pro feature | Missing | No packaged external SIEM integration equivalent |
| AI assistant | Pro Onion AI | Partial | Local assistant-style features exist only in fragments |
| Compliance hardening | `salt/stig`, Pro STIG/FIPS/LUKS scope | Missing | No equivalent compliance/hardening program |

## Preserve Rule
The following existing Security Gateway features stay in place and are not to be removed during parity work:
- tracker blocking
- proxy tooling
- DNS tooling
- malware feeds and local scanning
- local reports
- desktop launcher and local operator workflows
- current SOC dashboard, alerts, and cases

Parity work should absorb these into a larger platform, not replace them with less capable equivalents.

## Required Platform Layers
To reach credible Security Onion Pro parity, Security Gateway needs these layers added in order.

### 1. Platform Foundation
- define node roles: manager, search, sensor, standalone
- define deployment model: local single-node first, then multi-node
- move from app packaging mindset to platform packaging mindset
- establish durable service/process supervision beyond the desktop launcher

### 2. Data Plane
- central event ingestion pipeline
- normalized event schema
- durable search/index storage
- retention, rollover, and export model
- queueing between collection, parsing, and alerting

### 3. Sensor Plane
- real network sensor service
- full packet capture service
- Zeek-like metadata extraction
- Suricata-like IDS alert path
- file extraction and downstream analysis hooks

### 4. Endpoint Plane
- managed endpoint telemetry collection
- host inventory and health state
- agent enrollment/rotation/update model
- broader process, service, and artifact telemetry

### 5. Detection and Response
- scalable detection rules
- correlation engine over event history
- durable notification routing
- analyst response actions tied to alerts/cases
- evidence preservation for suspicious network/file activity

### 6. SOC Workflow
- search-driven investigation views
- alert-to-case lifecycle at analyst scale
- assignment, SLA, and time-tracking
- report generation across incidents, detections, and node health

### 7. Enterprise Features
- OIDC
- API surface expansion
- message delivery guarantees
- manager-of-managers control plane
- compliance modes and hardening profiles
- AI/MCP assistant integration

## Implementation Backlog
This is the minimum coherent backlog to pursue full parity without destabilizing existing add-on features.

### Phase A: Single-Node SOC Platform
- add a persistent event store abstraction separate from flat JSON logs
- add a query layer over events, alerts, cases, and host findings
- split current monitors into managed services with health reporting
- add a service supervisor and node health model
- add ingest pipelines for packet, host, and stream evidence

### Phase B: Real Network and Detection Stack
- replace limited packet monitor with bounded capture service plus metadata extraction
- add network session summaries, flow storage, and evidence retention policy
- add rule execution over captured network and host events
- add alert routing with retries and durable queues

### Phase C: Endpoint and Fleet
- add agent enrollment and agent status tracking
- add host telemetry beyond current health checks
- add package/update/heartbeat handling for agents
- add per-node dashboards and fleet views

### Phase D: Search, Investigation, and Reporting
- add indexed search over events and evidence
- add analyst query UI instead of only queue-centric views
- add exportable incident and system reports
- add case time-tracking and ownership pressure metrics tied to searches

### Phase E: Enterprise and Pro Scope
- add OIDC
- add external integration APIs
- add notification backends with delivery guarantees
- add manager-of-managers
- add compliance/hardening profiles
- add AI/MCP assistant layer

## Immediate Build Order
If the target is truly "all of them," the next five implementation steps should be:
1. Formalize node roles and deployment model in architecture docs.
2. Introduce a real event store and query layer.
3. Replace the current packet monitor with a bounded capture and session-analysis service.
4. Add a first-class network detection/rule engine.
5. Add a managed endpoint telemetry/agent model.

Until those exist, Security Gateway can borrow workflow ideas from Security Onion Pro, but it cannot honestly be described as feature-equivalent.
