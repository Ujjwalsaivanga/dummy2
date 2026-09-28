#!/usr/bin/env python3
"""
harvest_to_master.py - Automated Code Harvester for SIH 26160
Transfers curated superpowers from reference repositories in dummy2 into the master build repository.

Usage:
    python3 scripts/harvest_to_master.py --target /path/to/payodhi2BlockChain
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

# Base directories in dummy2
WORKSPACE = Path(__file__).resolve().parent.parent
REPOS_DIR = WORKSPACE / "repos"

# Source directories
TUNNELSCOPE_DIR = REPOS_DIR / "TunnelScope"
ALCHEMIST_DIR = REPOS_DIR / "SIH26160-Alchemist"
VAULTSCOPE_DIR = REPOS_DIR / "vaultscope"

HARVEST_MANIFEST = [
    # 1. Post-Quantum Cryptography & CycloneDX 1.6 CBOM
    {
        "name": "Post-Quantum & CBOM Engine",
        "src": TUNNELSCOPE_DIR / "tunnelscope" / "pq",
        "dest": "core/pq",
        "is_dir": True,
    },
    # 2. Live Threat Intelligence (CISA KEV, NVD, EUVD)
    {
        "name": "Threat Intelligence Module",
        "src": TUNNELSCOPE_DIR / "tunnelscope" / "intel",
        "dest": "core/intel",
        "is_dir": True,
    },
    # 3. Config-to-Wire Reconciler
    {
        "name": "Config Reconciler Engine",
        "src": TUNNELSCOPE_DIR / "tunnelscope" / "config",
        "dest": "core/config",
        "is_dir": True,
    },
    # 4. DISA SRG, CNSA 2.0 & India Regulatory Rules
    {
        "name": "Regulatory Rules & Baselines",
        "src": TUNNELSCOPE_DIR / "tunnelscope" / "rules",
        "dest": "core/rules/definitions",
        "is_dir": True,
    },
    # 5. 3D Tunnel Visualizer Components
    {
        "name": "3D Tunnel Canvas UI",
        "src": TUNNELSCOPE_DIR / "fleet-dashboard" / "src" / "components" / "tunnel",
        "dest": "frontend/src/components/tunnel",
        "is_dir": True,
    },
    # 6. 12-Threat MITRE ATT&CK Matrix UI
    {
        "name": "Threat Matrix UI Component",
        "src": TUNNELSCOPE_DIR / "fleet-dashboard" / "src" / "components" / "dashboard" / "ThreatMatrix.tsx",
        "dest": "frontend/src/components/ThreatMatrix.tsx",
        "is_dir": False,
    },
    # 7. Real Public PCAP Suite & Decryption Tables
    {
        "name": "Real-World PCAP Suite",
        "src": ALCHEMIST_DIR / "testdata" / "public-pcaps",
        "dest": "data/pcaps/alchemist_real_pcaps",
        "is_dir": True,
    },
    # 8. Multi-Topology strongSwan Lab Profiles
    {
        "name": "Lab Testbed Profiles (P01-P08)",
        "src": ALCHEMIST_DIR / "backend" / "lab" / "configs",
        "dest": "testbed/strongswan_profiles",
        "is_dir": True,
    },
    # 9. SIH Pitch Deck & Jury QA Guides
    {
        "name": "SIH Pitch & Presentation Materials",
        "src": TUNNELSCOPE_DIR / "build" / "sih",
        "dest": "docs/sih_materials",
        "is_dir": True,
    },
    # 10. Alchemist Team Presentation Deck PDF
    {
        "name": "Alchemist Official Submission Deck",
        "src": ALCHEMIST_DIR / "submission",
        "dest": "docs/alchemist_submission",
        "is_dir": True,
    },
]


def harvest(target_dir: Path):
    print("=" * 70)
    print("SIH 26160 Master Code Harvester")
    print(f"Source Workspace: {WORKSPACE}")
    print(f"Target Master:    {target_dir}")
    print("=" * 70)

    if not target_dir.exists():
        print(f"Error: Target directory does not exist: {target_dir}")
        sys.exit(1)

    successful = 0
    total = len(HARVEST_MANIFEST)

    for item in HARVEST_MANIFEST:
        src = item["src"]
        dest = target_dir / item["dest"]
        name = item["name"]

        if not src.exists():
            print(f"[-] SKIPPED: {name} (source missing: {src})")
            continue

        try:
            if item["is_dir"]:
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(src, dest)
                file_count = sum(1 for _ in dest.rglob("*") if _.is_file())
                print(f"[+] HARVESTED: {name} -> {item['dest']} ({file_count} files)")
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                size_kb = dest.stat().st_size / 1024
                print(f"[+] HARVESTED: {name} -> {item['dest']} ({size_kb:.1f} KB)")
            successful += 1
        except Exception as e:
            print(f"[!] FAILED: {name} ({e})")

    print("-" * 70)
    print(f"Harvest Complete: {successful}/{total} modules successfully transferred.")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harvest components from reference repos into master")
    parser.add_argument("--target", required=True, help="Path to payodhi2BlockChain master repository")
    args = parser.parse_args()
    harvest(Path(args.target).resolve())
