# GbemiShield — Grand Marina IoT Security System

> **Hydroficient IoT Cyber Defense Externship** · Extern.com · Top 10% of Global Learners

A complete IoT security pipeline built to protect the Grand Marina Hotel's water management system — 500 rooms, 3 device zones, streaming sensor data every few seconds. The mission: think like an attacker, then become the defender.

---

## What This Is

This isn't a tutorial project. This is a real attack-and-defense pipeline built from scratch — starting with an insecure MQTT system and hardening it step by step through encryption, authentication, replay defense, and AI-powered anomaly detection.

By the end, every attack I simulated was blocked. **100% rejection rate across all attack types.**

---

## The System

```
IoT Sensors (3 zones)
    ↓  MQTT over mTLS (port 8884)
Mosquitto Broker
    ↓  Certificate verification
Subscriber + Defense Layer
    ├── HMAC-SHA256 verification
    ├── Timestamp freshness check (30s window)
    ├── Sequence counter tracking
    └── Isolation Forest AI anomaly detection
         ↓
GbemiShield Dashboard (WebSocket + HTTP)
    ├── Live sensor readings (pressure, flow rate, gate position)
    ├── Rule-based attack alerts (red)
    └── AI anomaly flags (orange — what rules miss, the model catches)
```

**Three device zones monitored:**
- Main Building
- Pool & Spa
- Kitchen & Laundry

---

## Attack Surface & Defenses

### Phase 1 — No Security (Baseline)
Plain MQTT with no encryption. Messages intercepted in plaintext. 0% rejection rate on all attacks.

### Phase 2 — One-Way TLS
Traffic encrypted. Man-in-the-middle attacks blocked. But devices still can't prove their identity.

### Phase 3 — Mutual TLS (mTLS)
Every device needs a certificate signed by the Grand Marina CA. Rogue devices with no cert, wrong CA cert, or expired cert are all rejected at the TLS handshake.

### Phase 4 — Replay Attack Defenses
Three layers stacked in order:
1. **HMAC-SHA256** — proves message wasn't tampered with
2. **Timestamp freshness** — rejects messages older than 30 seconds
3. **Sequence counter** — detects duplicate messages regardless of timestamp

**Experiment results (60 attack trials):**

| Defense | Immediate Replay | Delayed Replay | Modified Replay |
|---|---|---|---|
| None | 0% rejected | 0% rejected | 0% rejected |
| Timestamp only | 0% rejected | **100% rejected** | 0% rejected |
| Sequence counter | **100% rejected** | **100% rejected** | 0% rejected |
| All three | **100% rejected** | **100% rejected** | **100% rejected** |

No single defense catches everything. All three together catch everything.

### Phase 5 — AI Anomaly Detection
Rule-based defenses only catch what you already know to look for. The Isolation Forest model catches behavioral anomalies that pass all rule checks — unusual pressure patterns, abnormal flow combinations, sensor readings that look valid individually but are statistically anomalous together.

> *"Red = rule caught it. Orange = AI flagged it. Green = all clear. Two layers of defense — what rules miss, the model catches."*

---

## Repo Structure

```
GbemiShield/
│
├── src/                          # Core pipeline
│   ├── publisher_mtls.py         # Device sensor publisher (mTLS)
│   ├── publisher_defended.py     # Publisher with HMAC + sequence counter
│   ├── subscriber_tls.py         # Basic TLS subscriber
│   ├── subscriber_mtls.py        # Mutual TLS subscriber
│   ├── subscriber_defended.py    # Subscriber with 3-layer replay defense
│   └── subscriber_dashboard_ai.py # Full pipeline with AI + live dashboard
│
├── dashboard/                    # GbemiShield live dashboard
│   ├── dashboard.html            # Rule-based attack dashboard
│   ├── dashboard_ai.html         # AI-enhanced dashboard
│   ├── dashboard_server.py       # WebSocket + HTTP server
│   └── dashboard_server_ai.py    # AI-extended dashboard server
│
├── attacks/                      # Attack simulation tools
│   ├── replay_attacker.py        # Replay attack (capture/replay/delayed/modified)
│   ├── attack_simulator.py       # Three-phase theatrical attack demo
│   ├── identity_tester.py        # Identity attack suite (no cert/wrong CA/expired)
│   └── key_test.py               # Rogue device connection test
│
├── experiments/                  # Research & results
│   ├── experiment_runner.py      # Automated defense comparison runner
│   ├── defense_tester.py         # Manual defense testing tool
│   ├── experiment_results.json   # Full results (60 trials)
│   ├── defense_comparison.png    # Replay attack defense chart
│   └── captured_messages.json   # Sample captured MQTT messages
│
├── certs/                        # Certificate infrastructure
│   ├── generate_certs.py         # CA + server cert generation
│   └── generate_client_certs.py  # Per-device cert generation (mTLS)
│
├── config/                       # Mosquitto broker configs
│   ├── mosquitto_insecure.conf   # Phase 1: No security
│   ├── mosquitto_tls.conf        # Phase 2: One-way TLS
│   ├── mosquitto_oneway.conf     # Phase 3: One-way TLS variant
│   └── mosquitto_mtls.conf       # Phase 4: Mutual TLS
│
├── models/                       # AI models
│   └── anomaly_model.joblib      # Trained Isolation Forest model
│
├── reports/                      # Deliverables
│   ├── grand_marina_security_report.docx
│   ├── vulnerability_analysis.docx
│   ├── Grand_Marina_Threat_Model.docx
│   └── Externship_Final_Capstone.pptx
│
└── screenshots/
    ├── gbemishield_dashboard.png  # Live dashboard screenshot
    └── defense_comparison.png     # Experiment results chart
```

---

## Quick Start

### Prerequisites
```bash
pip install paho-mqtt cryptography scikit-learn joblib websockets
```

Also install [Mosquitto](https://mosquitto.org/download/) MQTT broker.

### 1. Generate Certificates
```bash
python certs/generate_certs.py
python certs/generate_client_certs.py
```

### 2. Start the Broker
```bash
# Insecure (Phase 1)
mosquitto -c config/mosquitto_insecure.conf -v

# Mutual TLS (Phase 4 — recommended)
mosquitto -c config/mosquitto_mtls.conf -v
```

### 3. Run the Full Pipeline
```bash
# Terminal 1 — Start the AI dashboard subscriber
python src/subscriber_dashboard_ai.py

# Terminal 2 — Start a defended publisher
python src/publisher_defended.py --device 001

# Terminal 3 — Run an attack simulation
python attacks/attack_simulator.py
```

Then open `http://localhost:8000` to see GbemiShield live.

---

## Running Attacks

```bash
# Replay attack — capture then replay messages
python attacks/replay_attacker.py --mode capture --count 5
python attacks/replay_attacker.py --mode replay
python attacks/replay_attacker.py --mode replay-delayed --delay 60
python attacks/replay_attacker.py --mode replay-modified

# Identity attacks — test certificate rejection
python attacks/identity_tester.py --mode test-no-cert
python attacks/identity_tester.py --mode test-wrong-ca
python attacks/identity_tester.py --mode all

# Three-phase theatrical attack demo
python attacks/attack_simulator.py
```

---

## Benchmarks

mTLS connection overhead vs one-way TLS:
```bash
python src/mtls_benchmark.py --mode connection --trials 20
python src/mtls_benchmark.py --mode latency --count 50
```

---

## STRIDE Threat Model

Full analysis in `reports/Grand_Marina_Threat_Model.docx`.

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Rogue device impersonation | mTLS — device certificates |
| **Tampering** | Message modification in transit | HMAC-SHA256 signature |
| **Repudiation** | Denying message origin | Signed messages with device ID |
| **Information Disclosure** | Plaintext MQTT interception | TLS encryption on wire |
| **Denial of Service** | Replay flooding | Sequence counter + timestamp |
| **Elevation of Privilege** | Unauthorized broker access | Certificate-based authentication |

---

## Results

- **Top 10% of global learners** on this externship
- **100% replay attack rejection** with all three defenses combined
- **AI anomaly detection** catches behavioral threats that pass all rule checks
- **Live dashboard** (GbemiShield) streams real-time device health and attack events
- **Full STRIDE threat model** delivered as Security Improvement Report

---

## Tech Stack

`Python` `MQTT` `Mosquitto` `mTLS` `HMAC-SHA256` `Isolation Forest` `WebSocket` `scikit-learn` `paho-mqtt` `cryptography` `asyncio` `JavaScript` `HTML/CSS`

---

## Key Files to Read First

If you want to understand what was built, start here:

1. `src/subscriber_defended.py` — the core defense logic (HMAC + timestamp + sequence)
2. `attacks/replay_attacker.py` — how replay attacks work in practice
3. `experiments/experiment_results.json` — the raw data behind the chart
4. `dashboard/dashboard_server_ai.py` — how the live AI dashboard works
5. `reports/grand_marina_security_report.docx` — the full deliverable
