# Purdue Model — Network Architecture

The Forge lab maps to the Purdue Enterprise Reference Architecture (IEC 62443),
the standard framework for segmenting ICS/SCADA networks.

```
┌─────────────────────────────────────────────────┐
│  Level 5 — Enterprise Network (internet, email) │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│  Level 4 — Business Planning (ERP, databases)   │
├─────────────────── DMZ ─────────────────────────┤
│  Level 3.5 — Industrial DMZ (historian mirror,  │
│              patch server, remote access jump)   │
├─────────────────────────────────────────────────┤
│  Level 3 — Site Operations                      │
│  ┌─────────────┐  ┌───────────────────┐         │
│  │  Historian   │  │  Forge Dashboard  │         │
│  │  (data log)  │  │  (alert monitor)  │         │
│  └─────────────┘  └───────────────────┘         │
├─────────────────────────────────────────────────┤
│  Level 2 — Area Supervisory Control             │
│  ┌─────────────┐                                │
│  │     HMI     │  ← reads process, sends        │
│  │  (client)   │    setpoints to PLC             │
│  └─────────────┘                                │
├─────────────────────────────────────────────────┤
│  Level 1 — Basic Control                        │
│  ┌─────────────┐                                │
│  │     PLC     │  ← Modbus TCP server            │
│  │  (unit 1)   │    runs process logic            │
│  └─────────────┘                                │
├─────────────────────────────────────────────────┤
│  Level 0 — Physical Process                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ │
│  │ Intake │ │ Dosing │ │  Tank  │ │  Outlet  │ │
│  │  Pump  │ │  Pump  │ │ (level)│ │  Valve   │ │
│  └────────┘ └────────┘ └────────┘ └──────────┘ │
└─────────────────────────────────────────────────┘
```

## How Forge maps to each level

| Level | Forge component | What it does |
|-------|----------------|--------------|
| 0 | `process.py` (PlantState) | Simulates tank, pumps, valves, chemistry |
| 1 | `plc.py` (PLCServer) | Modbus TCP server, runs the process tick |
| 2 | `hmi.py` (HMI) | Polls PLC, adjusts actuators to keep plant safe |
| 3 | `dashboard.py`, `monitor.py`, `detect.py` | Security monitoring, alerts, asset inventory |
| 3.5 | Network boundary | In production: firewall, jump host, historian mirror |
| 4-5 | Not modelled | Enterprise network, internet |

## Why segmentation matters

In a real plant, Levels 0-2 sit on an isolated OT network with no direct
path to the internet.  The DMZ (Level 3.5) is the only bridge, and it runs
unidirectional gateways or tightly firewalled proxies.

The attack scripts in `scripts/` simulate what happens when an attacker
breaches the DMZ and lands on the Level 1-2 network:

- **recon.py** — scans for PLCs (Level 1 discovery)
- **hijack.py** — sends unauthorized writes to actuators (Level 0 manipulation)
- **flood.py** — DoS against the PLC (Level 1 disruption)

Each attack is detected by the monitor at Level 3 and mapped to MITRE
ATT&CK for ICS.
