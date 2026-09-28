# Standard Operating Procedure (SOP)
## Code Harvesting & Master Build Integration for SIH 26160

> **Author:** Antigravity Engineering Pair  
> **Source Workspace:** `dummy2` (`repos/SIH26160-Alchemist`, `repos/TunnelScope`, `repos/vaultscope`)  
> **Target Production Workspace:** `payodhi2BlockChain`  
> **Target Repository:** `https://github.com/Ujjwalsaivanga/payodhi2BlockChain`

---

## 1. Objectives & Guiding Principles

This SOP defines the exact, reproducible process to extract high-value modules from the reference repositories (`TunnelScope` and `SIH26160-Alchemist`) and integrate them into the master codebase (`payodhi2BlockChain`, which is built on the `vaultscope` foundational architecture).

### Core Integration Principles:
1. **Preserve What Works:** Do not break the existing byte-level RFC 7296 binary parser (`core/ike_parser/`), FastAPI router, D3 Peer Graph, or instant SQLite seeding (`scripts/seed_demo_db.py`).
2. **Never Claim Impossible Capabilities:** Follow `TunnelScope`'s rigor: mark passive wire analysis as `OBSERVED`, `INFERRED`, or `NOT_OBSERVABLE`. Never claim raw packet payload decryption without credentials.
3. **Defense-Grade Compliance:** Adopt `TunnelScope`'s DISA SRG v2r6, CNSA 2.0, and India CERT-In / DST-NQM rule definitions.
4. **Instant Demonstration Assurance:** All newly integrated features must support pre-computed mock/demo states so live presentations never crash if internet or network interfaces fail.

---

## 2. Component Harvesting Roadmap

```
+-----------------------------------------------------------------------------------+
|                           payodhi2BlockChain (Master)                             |
|                                                                                   |
|  [Existing Base - vaultscope]                                                     |
|  ├── core/ike_parser/ (RFC 7296 binary deserializer)                              |
|  ├── core/flow/ (ESP side-channel extractor)                                      |
|  ├── core/classifiers/ (Pre-trained traffic & protocol ML models)                 |
|  ├── api/ (FastAPI + WebSocket engine)                                            |
|  └── frontend/ (Next.js 16 + D3 Peer Graph + Capture Spectrum)                    |
|                                                                                   |
|  [Harvested from TunnelScope]                                                     |
|  ├── core/pq/cbom.py              <-- CycloneDX 1.6 Cryptographic Bill of Materials|
|  ├── core/intel/lookup.py         <-- CISA KEV, NVD & strongSwan EUVD Threat Intel|
|  ├── core/config/reconcile.py     <-- Config-to-Wire Drift & Downgrade Reconciler |
|  ├── core/rules/definitions/      <-- DISA SRG, CNSA 2.0 & India DST-NQM Rules   |
|  └── frontend/components/tunnel/  <-- 3D Interactive Tunnel Canvas               |
|                                                                                   |
|  [Harvested from SIH26160-Alchemist]                                              |
|  ├── data/pcaps/                  <-- Real PCAP Suite (AES-GCM, NAT-T, Certs, DH) |
|  ├── data/wireshark_keys/         <-- Wireshark Decryption Tables (MR !3444)     |
|  ├── frontend/api/report-chat/    <-- AI Analyst Assistant (Gemini/Groq)        |
|  └── testbed/lab_topologies/      <-- 8 Dockerized VPN Profiles (P01-P08)         |
+-----------------------------------------------------------------------------------+
```

---

## 3. Step-by-Step Harvesting Procedures

### Procedure 1: Harvesting Post-Quantum Cryptography & CycloneDX 1.6 CBOM
**Source:** `repos/TunnelScope/tunnelscope/pq/cbom.py`  
**Destination:** `payodhi2BlockChain/core/pq/cbom.py`

#### Purpose:
Satisfies NTRO Problem Statement Section E: Generates standardized CycloneDX 1.6 JSON Cryptographic Bills of Materials (CBOM), catalogues classical vs quantum-safe algorithms, flags Shor-vulnerable DH/ECDH groups, and recognizes NIST FIPS 203 ML-KEM algorithms.

#### Execution Steps:
1. Create directory: `mkdir -p core/pq`
2. Copy `repos/TunnelScope/tunnelscope/pq/cbom.py` to `core/pq/cbom.py`.
3. Adapt import paths: Replace `from ..evidence.record import EvidenceRecord, Status` with `from core.models import SessionRecord, FindingStatus`.
4. Add endpoint to `api/main.py`:
   ```python
   @app.get("/sessions/{session_id}/cbom")
   async def export_session_cbom(session_id: str):
       session = store.get(session_id)
       if not session:
           raise HTTPException(status_code=404, detail="Session not found")
       cbom = generate_cbom(session)
       return Response(content=json.dumps(cbom, indent=2), media_type="application/vnd.cyclonedx+json")
   ```
5. Add UI button in `frontend/src/components/Toolbar.tsx` to download `session_cbom.json`.

---

### Procedure 2: Harvesting Live Threat Intelligence (CISA KEV & NVD)
**Source:** `repos/TunnelScope/tunnelscope/intel/lookup.py` & `sources.py`  
**Destination:** `payodhi2BlockChain/core/intel/`

#### Purpose:
Dynamically cross-references fingerprinted VPN vendors (Cisco ASA, strongSwan, Fortinet, Juniper, LibreSwan) against CISA's Known Exploited Vulnerabilities (KEV) catalog and NIST NVD.

#### Execution Steps:
1. Create directory: `mkdir -p core/intel`
2. Copy `repos/TunnelScope/tunnelscope/intel/lookup.py` and `sources.py` to `core/intel/`.
3. Copy offline fixture data:
   `cp -r repos/TunnelScope/tests/fixtures/intel/ core/intel/cached_fixtures/`
4. Hook into the rule engine: When vendor IDs are extracted from IKE payloads (`_vendor_ids.py`), invoke `intel.lookup(vendor_name)` and attach CVE entries directly to the session report.

---

### Procedure 3: Harvesting Config-to-Wire Reconciler
**Source:** `repos/TunnelScope/tunnelscope/config/reconcile.py` & `parse.py`  
**Destination:** `payodhi2BlockChain/core/config/`

#### Purpose:
Solves "Shadow VPN" detection. Allows an auditor to upload a gateway configuration file (`swanctl.conf` or `ipsec.conf`) alongside a pcap. The engine compares configured proposals against actual wire negotiation and alerts on drift, unauthorized cipher downgrade, or unapproved lifetime values.

#### Execution Steps:
1. Create directory: `mkdir -p core/config`
2. Copy `parse.py` and `reconcile.py` from `repos/TunnelScope/tunnelscope/config/` to `core/config/`.
3. Add API endpoint `/sessions/{session_id}/reconcile`:
   - Accepts uploaded config file (`.conf`)
   - Returns a structured diff: `[{"field": "encr", "outcome": "mismatch", "config": "AES-256-GCM", "wire": "3DES-CBC"}]`
4. Display reconciliation diffs in `frontend/src/components/SessionDrilldown.tsx`.

---

### Procedure 4: Harvesting Advanced Compliance Rules (DISA SRG & India DST-NQM)
**Source:** `repos/TunnelScope/tunnelscope/rules/`  
**Destination:** `payodhi2BlockChain/core/rules/definitions/`

#### Purpose:
Upgrades compliance checks from basic checks to official Defense and Indian National standards:
- `disa-vpn-srg-v2r6.yaml`: US DoD DISA VPN Security Requirements Guide.
- `dst-nqm-pq.yaml`: India DST National Quantum Mission post-quantum guidance.
- `rules/context/india.yaml`: India CERT-In guidelines on mandatory encryption standards.
- `cnsa2-ipsec.yaml`: Commercial National Security Algorithm Suite 2.0.

#### Execution Steps:
1. Create directory: `mkdir -p core/rules/definitions`
2. Copy YAML rule files into `core/rules/definitions/`.
3. Update `core/rules/engine.py` to load and evaluate multiple selectable regulatory profiles (`Profile: DISA-SRG | DST-NQM | RFC-8247 | CERT-In`).

---

### Procedure 5: Harvesting Real-World Public PCAPs & Wireshark Decryption Tables
**Source:** `repos/SIH26160-Alchemist/testdata/public-pcaps/`  
**Destination:** `payodhi2BlockChain/data/pcaps/` and `data/wireshark/`

#### Purpose:
Gives the team immediate, verified, authentic pcap captures for demonstration and testing without needing to capture packets on the fly during the presentation:
- `ikev2_aes256gcm16.pcap`
- `ikev2_natt_gcm_ctr_cbc_esp_icmp.pcapng`
- `ikev2_s2s_aes256gcm_dh19_esp_icmp.pcapng`
- `ikev1_certificates.pcap`
- Official Wireshark decryption tables: `esp_sa` and `ikev2_decryption_table`

#### Execution Steps:
1. Copy all pcap files from `repos/SIH26160-Alchemist/testdata/public-pcaps/` to `data/pcaps/`.
2. Add a sample dropdown in the frontend UI (`UploadDrop.tsx`):
   - Option 1: "Demo Capture: Cisco ASA to strongSwan (CVE-2015-4000 Weak DH)"
   - Option 2: "Real Capture: IKEv2 NAT-T Multi-Cipher (GCM/CTR/CBC)"
   - Option 3: "Real Capture: Site-to-Site AES-256-GCM + DH-19"
   - Option 4: "Real Capture: IKEv1 Certificate Authentication"
   - Option 5: "Custom Upload (.pcap / .pcapng)"

---

### Procedure 6: Harvesting AI Analyst Report Chat Assistant
**Source:** `repos/SIH26160-Alchemist/frontend/app/api/report-chat/route.ts` & `lib/report-chat-context.ts`  
**Destination:** `payodhi2BlockChain/frontend/src/app/api/report-chat/`

#### Purpose:
Provides an interactive LLM chat pane directly in the dashboard where an evaluator can ask questions:
- *"Explain why this session received a 42/100 score."*
- *"What is the exact remediation command for Cisco ASA to fix Sweet32?"*
- *"Which packets violated the DST National Quantum Mission guidelines?"*

#### Execution Steps:
1. Copy `report-chat/route.ts` to `frontend/src/app/api/report-chat/route.ts`.
2. Configure environment variable `GEMINI_API_KEY` (or fallback to an offline simulated AI response if no key is provided, ensuring zero demo failure).
3. Embed the chat assistant drawer in `frontend/src/app/page.tsx`.

---

### Procedure 7: Harvesting 3D Tunnel Visualizer & Threat Matrix
**Source:** `repos/TunnelScope/fleet-dashboard/src/components/tunnel/` & `ThreatMatrix.tsx`  
**Destination:** `payodhi2BlockChain/frontend/src/components/`

#### Purpose:
Adds breathtaking visual impact:
- A real-time 3D rendered tunnel canvas using HTML5 Canvas / Three.js that dynamically shifts color (green for compliant, red/amber for vulnerable or leaking tunnels).
- A 12-threat MITRE ATT&CK risk matrix showing likelihood vs impact.

#### Execution Steps:
1. Copy `repos/TunnelScope/fleet-dashboard/src/components/tunnel/` into `frontend/src/components/tunnel/`.
2. Copy `ThreatMatrix.tsx` into `frontend/src/components/`.
3. Integrate into the main dashboard tab bar:
   - Tab 1: **Topology & Peer Graph** (D3 Force Directed)
   - Tab 2: **3D Tunnel Inspection** (Interactive Canvas)
   - Tab 3: **Threat Matrix & Mitre Mapping** (12-Threat Grid)
   - Tab 4: **Quantum Readiness & CBOM** (CycloneDX 1.6 Explorer)

---

## 4. Automation: The Master Harvest Script

To eliminate manual copying errors, run the automated harvester:
```bash
python3 scripts/harvest_to_master.py --target /Users/vangaujjwalsai/payodhi2BlockChain
```
This script validates file checksums, patches relative imports, updates configuration dictionaries, and runs smoke tests.
