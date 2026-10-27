```
     _         _        ____  ______   __
    / \  _   _| |_ ___ |  _ \/ ___\ \ / /
   / _ \| | | | __/ _ \| |_) \___ \\ V /
  / ___ \ |_| | || (_) |  __/ ___) || |
 /_/   \_\__,_|\__\___/|_|   |____/ |_|
```

# AutoPSY — Anti-Forensic Detection & Evidence Integrity Framework for Software-Defined Vehicles

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()

**AutoPSY** is the first unified offensive + forensic framework that addresses the complete vehicle anti-forensic problem. It combines vehicle network reconnaissance, attack simulation, forensic evidence acquisition, and anti-forensic tamper detection in a single tool.

## The Problem

Modern software-defined vehicles present a forensic nightmare:

| Anti-Forensic Technique | Impact | Detection Difficulty |
|---|---|---|
| OTA firmware updates | Overwrites ECU state, destroys evidence | High — no pre-update baseline exists |
| DTC clearing (`UDS 0x14`) | Erases all diagnostic trouble codes | Medium — clear timestamp survives |
| ECU reflashing | Replaces firmware, resets all counters | High — hash comparison needed |
| CAN bus injection | No source authentication on CAN | Medium — timing jitter detectable |
| Clock manipulation | Alters event timestamps | Medium — drift analysis possible |
| Cloud telemetry wipe | OEM-controlled, inaccessible to investigators | Very High — no local evidence |

**Result:** Vehicle forensic evidence is the easiest to destroy and the hardest to verify in all of digital forensics.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AutoPSY CLI                        │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│  RECON   │  ATTACK  │ FORENSICS│ANTI-FORNS│  REPORTING  │
│          │          │          │          │             │
│ DoIP     │ CAN Inj  │ CAN Cap  │ FW Tamper│ JSON Report │
│ SOME/IP  │ Bus-Off  │ DID Read │ DTC Clear│ MD Report   │
│ CAN Scan │ DoIP Hjk │ DTC Ext  │ CAN Inj  │ Court-Ready │
│ ECU FP   │ UDS Brute│ SOME/IP  │ Diag Trc │             │
│          │ DTC Clear│ Hash Chn │ Clock    │             │
│          │ SD Poison│          │ OTA Dest │             │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│                    PROTOCOL LAYER                       │
│  ISO 11898 CAN  │  ISO 13400 DoIP  │  AUTOSAR SOME/IP  │
│  ISO 14229 UDS  │  Forensic Container (SHA-256 chains)  │
└─────────────────────────────────────────────────────────┘
```

## Features

### RECON — Vehicle Network Discovery
- DoIP entity discovery via UDP broadcast
- SOME/IP service enumeration via SD multicast
- CAN bus traffic capture and analysis
- ECU fingerprinting — reads VIN, firmware versions, serial numbers, manufacturing dates via UDS DIDs (F186–F1A0)

### ATTACK — 9 Vehicle Attack Modules
| Attack | Protocol | Forensic Artifacts Left Behind |
|---|---|---|
| Message Injection | CAN | Timing jitter, frequency anomaly |
| Bus-Off Attack | CAN | Error frame burst, target ECU silence |
| Replay Attack | CAN | Duplicate messages, timestamp inconsistency |
| Session Hijacking | DoIP | Routing activation log, session change DTC |
| DID Dump | UDS | ReadDataByIdentifier log |
| ECU Reset | UDS | Reset counter increment, uptime discontinuity |
| Security Access Brute Force | UDS | Attempt counter, lockout NRC (0x36) |
| DTC Clearing | UDS | Clear timestamp, counter reset to zero |
| Fake Service Offer | SOME/IP-SD | Duplicate offer, TTL anomaly, IP mismatch |
| Method Call Injection | SOME/IP | Unknown client ID, session sequence break |

Every attack documents the **exact forensic artifacts** it creates — showing both offense and defense.

### FORENSICS — Chain-of-Custody Evidence Acquisition
- Multi-bus evidence capture (CAN, SOME/IP, DoIP)
- ECU state extraction (all forensic DIDs)
- DTC extraction with status flags (`testFailed`, `pending`, `confirmed`)
- SHA-256 hash-chained forensic containers
- Per-block and master hash integrity verification
- JSON serialization with full audit trail

### ANTI-FORENSICS — 6 Tamper Detection Modules
| Detector | Severity | What It Finds |
|---|---|---|
| Firmware Tampering | CRITICAL | ECU firmware hash changed since baseline |
| DTC Clearing | HIGH | Suspiciously clean ECU after incident |
| CAN Injection | HIGH | Timing jitter, frequency anomalies, unknown IDs |
| Diagnostic Traces | CRITICAL | ECU in programming/extended session |
| Clock Manipulation | HIGH | Time drift, non-monotonic timestamps |
| OTA Evidence Destruction | HIGH | Unknown firmware version, rollback detected |

Each indicator includes **severity**, **confidence score**, and **forensic significance** explanation.

### REPORTING — Court-Ready Output
- JSON structured reports
- Markdown formatted reports
- Case information (examiner, organization, vehicle, incident)
- Evidence summary with integrity verification
- Anti-forensic analysis with all indicators

## Installation

```bash
git clone https://github.com/sapnadfir-blip/AutoPSY.git
cd AutoPSY
pip install -e .
```

## Quick Start

### Full Demo (recommended first run)
```bash
python -m autopsy demo
```

### Individual Modules

**Reconnaissance:**
```bash
autopsy recon --target 192.168.1.10 --interface vcan0
```

**Attacks:**
```bash
autopsy attack all --target 192.168.1.10
autopsy attack can-inject --arb-id 0x0C0 --data 1F40000000000000 --count 50
autopsy attack security-bruteforce --target 192.168.1.10
autopsy attack dtc-clear --target 192.168.1.10
```

**Forensic Acquisition:**
```bash
autopsy forensics --target 192.168.1.10 --case-id CASE001 --vin WBA11CF090CH77832
```

**Anti-Forensic Detection:**
```bash
autopsy anti-forensics --evidence-file autopsy_evidence_CASE001.json
```

**Report Generation:**
```bash
autopsy report autopsy_evidence_CASE001.json --format markdown
autopsy report autopsy_evidence_CASE001.json --format json
```

## Hardware Testbed Setup

For a fully real demo environment using a Raspberry Pi:

```
┌──────────────┐     Ethernet/WiFi     ┌──────────────────┐
│   Laptop     │◄──────────────────────►│  Raspberry Pi    │
│   AutoPSY    │     CAN (MCP2515)      │  Vehicle Sim     │
│  (attacker)  │◄──────────────────────►│  vCAN + DoIP +   │
│              │                         │  SOME/IP ECUs    │
└──────────────┘                         └──────────────────┘
```

**Requirements:**
- Raspberry Pi 3/4/5
- MCP2515 CAN bus module (~$5)
- Ethernet cable or WiFi

## Protocol Standards

| Protocol | Standard | Usage in AutoPSY |
|---|---|---|
| CAN | ISO 11898 | Bus capture, injection, analysis |
| DoIP | ISO 13400 | Diagnostic gateway access |
| UDS | ISO 14229 | ECU diagnostics, DID/DTC operations |
| SOME/IP | AUTOSAR | Service discovery, method calls |
| SOME/IP-SD | AUTOSAR | Service enumeration, SD poisoning |

## UDS Security Access Brute Force

AutoPSY implements 11 candidate key algorithms for seed/key cracking:

| Algorithm | Method |
|---|---|
| XOR (7 variants) | `seed ⊕ 0xFF/0xAA/0x55/0xC3/0x3C/0x69/0x96` |
| Byte Reverse | `seed[::-1]` |
| Complement | `~seed & 0xFF` |
| Rotate Left | `seed[1:] + seed[:1]` |
| Rotate Right | `seed[-1:] + seed[:-1]` |
| Add (4 variants) | `seed + 0x01/0x02/0x10/0x20` |

## Project Structure

```
AutoPSY/
├── setup.py
├── autopsy/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                          # Full CLI with all subcommands
│   ├── protocols/
│   │   ├── can_bus.py                  # ISO 11898 CAN
│   │   ├── doip.py                     # ISO 13400 DoIP + ISO 14229 UDS
│   │   ├── someip.py                   # AUTOSAR SOME/IP + SD
│   │   └── forensic_container.py       # SHA-256 hash-chained evidence
│   ├── recon/
│   │   └── scanner.py                  # Multi-protocol vehicle scanner
│   ├── attack/
│   │   └── vehicle_attacks.py          # 9 attack modules
│   ├── forensics/
│   │   └── acquisition.py              # Evidence acquisition engine
│   ├── antiforensics/
│   │   └── detector.py                 # 6 tamper detection modules
│   └── reporting/
│       └── report_gen.py               # JSON + Markdown reports
```

## Example Output

```
[Phase 4] ANTI-FORENSIC DETECTION
----------------------------------------
  Risk level:      CRITICAL
  Indicators:      6
    [CRITICAL] firmware_tamper: ECU 'Gateway_ECU' firmware hash changed since baseline
    [HIGH] dtc_cleared: ECU 'Engine_ECU' had 5 DTCs at baseline, now has 0
    [MEDIUM] recent_dtc_clear: DTC clear event recorded at 2026-10-26 14:30:00
    [CRITICAL] active_diagnostic_session: ECU is in Programming diagnostic session
    [HIGH] clock_drift: ECU clock deviates from reference by 7200 seconds (2.0 hours)
    [HIGH] unknown_firmware_version: Current firmware version not in known version list
```

## Use Cases

- **Incident Response:** Acquire and preserve vehicle evidence with chain-of-custody integrity
- **Penetration Testing:** Test vehicle network security across CAN, DoIP, and SOME/IP
- **Anti-Forensic Detection:** Determine if vehicle evidence has been tampered with
- **Expert Witness:** Generate court-ready reports with hash verification and tamper indicators
- **Research:** Study vehicle attack surfaces and their forensic implications

## Authors

- **Dr. Sapna VM** — PES University
- **Prajwal Chowdary M** — PES University
- **Prasad B Honnavalli** — PES University

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Disclaimer

AutoPSY is designed for authorized security testing, forensic investigation, and educational purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. Do not use this tool against vehicles or networks without explicit authorization.
