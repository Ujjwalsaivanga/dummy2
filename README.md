# SIH 26160 Reference Hub & Code Harvester
**NTRO — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**

This repository (`dummy2`) serves as the comprehensive analysis, cross-comparison, and component harvesting hub for Smart India Hackathon (SIH) 2026 Problem Statement **SIH 26160**.

It brings together the top 3 open-source implementations of this problem statement, analyzes their architectural strengths, weaknesses, and evidence tiers, and provides a clear Standard Operating Procedure (SOP) to harvest their best capabilities into the master build repository:
👉 **Master Repository:** [`Ujjwalsaivanga/payodhi2BlockChain`](https://github.com/Ujjwalsaivanga/payodhi2BlockChain)

---

## 📂 Repository Contents

```
dummy2/
├── README.md                                 # This guide and overview
├── SIH26160_TRIPLE_REPO_COMPARATIVE_ANALYSIS.md # 50+ point matrix & deep technical comparison
├── SOP_CODE_HARVESTING_AND_INTEGRATION.md   # Step-by-step procedure to port code into master
├── scripts/
│   └── harvest_to_master.py                  # Automated idempotent component transfer script
└── repos/
    ├── SIH26160-Alchemist/                   # Go Core + gRPC + Next.js + Real PCAPs + Labs
    ├── TunnelScope/                          # Python + PQC/CBOM + CISA KEV Intel + Reconciler
    └── vaultscope/                           # Python + FastAPI + D3 Force Graph + PDF Reports
```

---

## 🔍 The 3 Reference Repositories at a Glance

| Feature / Dimension | `SIH26160-Alchemist` | `TunnelScope` | `vaultscope` |
|---|---|---|---|
| **Core Architecture** | Go (Core Ingestion) + Python (ML) + Next.js | Python 3.11 CLI/Engine + React Fleet UI | Python 3.11 FastAPI + Next.js 16/React 19 |
| **Parsing Engine** | `gopacket`/`pcap` Go sensor | `tshark` stream wrapper + Python sieve | **Byte-level RFC 7296 binary struct parser** |
| **Post-Quantum / CBOM** | Mentioned in docs | **CycloneDX 1.6 CBOM + ML-KEM/Kyber** | Classical DH checks |
| **Compliance Baselines** | RFC 7296 / installed SA checks | **DISA VPN SRG v2r6, CNSA 2.0, India DST-NQM** | 18 CVE-linked rules (Logjam, Sweet32) |
| **Threat Intelligence** | Static map | **Live CISA KEV, NVD & strongSwan EUVD** | Seeded CVE citations |
| **Config vs Wire Drift** | strongSwan VICI checks | **Automated config reconciler (`reconcile.py`)** | Vendor remediation diffs |
| **ML Traffic Classifier** | 7 classes + `UNKNOWN` abstention | Random Forest on packet size floors | Random Forest (6 classes) with `.pkl` models |
| **UI & Visualizations** | Next.js landing + workspace | **3D Canvas Tunnel Animation + Threat Matrix** | **D3 Force-Directed Peer Graph + Spectrum** |
| **Reporting & Export** | JSON + Gemini/Groq AI Chat Assistant | CycloneDX 1.6 CBOM + Markdown + CEF | **Executive & Technical PDF (WeasyPrint) + CEF** |
| **Testbeds & Captures** | **Real-world PCAPs (AES-GCM, NAT-T, Certs, DH)** | 33 Pre-Registered Empirical Experiments | 300+ ground truth JSON manifests |

---

## 🌟 Superpowers to Harvest into Master (`payodhi2BlockChain`)

To build the definitive #1 solution, we extract the elite capabilities of each reference project:

1. **From `vaultscope` (The Foundation):**
   - Pure Python byte-level RFC 7296 binary deserializer (`core/ike_parser/`).
   - Clean, high-performance FastAPI backend with WebSocket live-streaming (`api/`).
   - Interactive D3 force-directed Peer Graph (`PeerGraph.tsx`) and Capture Spectrum bar.
   - Dual Jinja2/WeasyPrint Executive & Technical PDF generator (`reporting/`).
   - Instant 1-second SQLite seeding script (`scripts/seed_demo_db.py`).

2. **From `TunnelScope` (Scientific Rigor & Compliance):**
   - **CycloneDX 1.6 CBOM Export (`tunnelscope/pq/cbom.py`):** Meets NTRO Section E requirements.
   - **Live Threat Intel Engine (`tunnelscope/intel/lookup.py`):** Integrates CISA KEV, NVD, and strongSwan EUVD.
   - **Config-to-Wire Reconciler (`tunnelscope/config/reconcile.py`):** Flags configuration drift and shadow VPNs.
   - **Defense Baselines:** DISA VPN SRG v2r6, CNSA 2.0, and India CERT-In/DST National Quantum Mission rules.
   - **Visual Assets:** 3D animated tunnel canvas (`BackgroundTunnel.tsx`) and 12-threat MITRE ATT&CK matrix.

3. **From `SIH26160-Alchemist` (Real-World Evidence & Lab Engine):**
   - **Real PCAP Test Archive (`testdata/public-pcaps/`):** Authentic captures for AES-256-GCM, NAT-T, X.509 certs, and DH-19.
   - **Wireshark Decryption Tables:** Official keys (`esp_sa`, `ikev2_decryption_table`) matching Wireshark MR !3444.
   - **AI Analyst Assistant Route (`app/api/report-chat/route.ts`):** Natural language Q&A on session audit reports.
   - **Dockerized VPN Lab Profiles (`backend/lab/configs/`):** 8 multi-topology strongSwan profiles (P01–P08).

---

## 🚀 How to Run the Automated Harvester

To port all curated superpowers from `dummy2` directly into your master repository:

```bash
# Make script executable
chmod +x scripts/harvest_to_master.py

# Run the harvest against your master repo:
python3 scripts/harvest_to_master.py --target /Users/vangaujjwalsai/payodhi2BlockChain
```

---

## 📖 In-Depth Documentation Links

- Detailed Comparative Analysis: [`SIH26160_TRIPLE_REPO_COMPARATIVE_ANALYSIS.md`](SIH26160_TRIPLE_REPO_COMPARATIVE_ANALYSIS.md)
- Code Harvesting SOP: [`SOP_CODE_HARVESTING_AND_INTEGRATION.md`](SOP_CODE_HARVESTING_AND_INTEGRATION.md)
