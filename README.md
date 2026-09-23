# GbemiShield — Grand Marina IoT Security System

> **Hydroficient IoT Cyber Defense Externship** · Extern.com · Top 10% of Global Learners

**[▶ Try the live dashboard demo](https://gbemilekeadesiyan-a11y.github.io/GbemiShield-Grand-Marina-IoT-Security-System/)** — runs in your browser with simulated sensor data, no setup needed.

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
grand-marina-iot-security/
│
├── src/                            # Core pipeline (publishers & subscribers)
│   ├── publisher_tls.py            # Phase 2: one-way TLS publisher (port 8883)
│   ├── publisher_mtls.py           # Phase 3: mutual TLS publisher (port 8884)
│   ├── publisher_defended.py       # Phase 4: HMAC + timestamp + sequence counter
│   ├── subscriber_tls.py           # Phase 2: one-way TLS subscriber
│   ├── subscriber_mtls.py          # Phase 3: mutual TLS subscriber
│   ├── subscriber_defended.py      # Phase 4: 3-layer replay defense
│   ├── subscriber_dashboard.py     # Defended subscriber + rule-based dashboard
│   ├── subscriber_dashboard_ai.py  # Defended subscriber + AI dashboard (full pipeline)
│   └── mtls_benchmark.py           # TLS vs mTLS overhead benchmark
│
├── dashboard/                      # GbemiShield live dashboard
│   ├── dashboard.html              # Rule-based attack dashboard
│   ├── dashboard_ai.html           # AI-enhanced dashboard
│   ├── dashboard_server.py         # HTTP (8000) + WebSocket (8765) server
│   └── dashboard_server_ai.py      # AI-extended dashboard server
│
├── attacks/                        # Attack simulation tools
│   ├── replay_attacker.py          # Replay attack (capture/replay/delayed/modified)
│   ├── attack_simulator.py         # Three-phase theatrical attack demo
│   ├── identity_tester.py          # Identity attacks (no cert / wrong CA / expired)
│   └── key_test.py                 # Rogue device connection test
│
├── experiments/                    # Research & results
│   ├── experiment_runner.py        # TLS experiments (baseline, expired cert, wrong CA)
│   ├── defense_tester.py           # Replay defense trials + chart generation
│   ├── anomaly_detection_lab.ipynb # Isolation Forest training notebook (Colab)
│   ├── experiment_results.json     # Full results (60 trials)
│   ├── defense_comparison.png      # Replay attack defense chart
│   └── captured_messages.json      # Sample captured MQTT messages
│
├── certs/                          # Certificate generation scripts
│   ├── generate_client_certs.py    # CA + server + per-device certs (use this one)
│   └── generate_certs.py           # Phase 2 only: CA + server cert (no CA key)
│
├── certs2/                         # Generated certificates (git-ignored, never commit)
│
├── config/                         # Mosquitto broker configs
│   ├── mosquitto_insecure.conf     # Phase 1: no security (port 18883)
│   ├── mosquitto_tls.conf          # Phase 2: TLS (port 8883)
│   ├── mosquitto_oneway.conf       # Phase 2: one-way TLS, minimal (port 8883)
│   └── mosquitto_mtls.conf         # Phase 3+: mutual TLS (port 8884)
│
├── models/
│   └── anomaly_model.joblib        # Trained Isolation Forest model
│
├── reports/                        # Written deliverables, in project order (see Reports below)
│   ├── 01_Asset_CIA_Analysis.pdf … 12_Anomaly_Detection_Results.pdf
│   └── 13_Final_Capstone.pptx
│
└── requirements.txt
```

> **Run every command from the repo root.** Scripts find `certs2/`, `models/` and the
> dashboard by their own location, but Mosquitto resolves the `certs2/...` paths in
> `config/*.conf` relative to the folder you start it from.

---

## Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

Also install the [Mosquitto](https://mosquitto.org/download/) MQTT broker.

### 1. Generate Certificates (first time only)
```bash
python certs/generate_client_certs.py
```
This creates the CA, the broker certificate and device certificates `001`–`003` in `certs2/`.
(If you already have a `certs2/` folder from before, just copy it into the repo root instead.)

### 2. Start the Broker
```bash
# Mutual TLS (recommended — what the full pipeline uses)
mosquitto -c config/mosquitto_mtls.conf -v

# Insecure baseline (Phase 1)
mosquitto -c config/mosquitto_insecure.conf -v
```

### 3. Run the Full Pipeline
```bash
# Terminal 1 — AI dashboard subscriber (opens http://localhost:8000 automatically)
python src/subscriber_dashboard_ai.py

# Terminal 2 — defended publishers, one per device zone
python src/publisher_defended.py --device 001
python src/publisher_defended.py --device 002
python src/publisher_defended.py --device 003

# Terminal 3 — run an attack simulation
python attacks/attack_simulator.py
```

Then open **http://localhost:8000** to see GbemiShield live.

### Just want to see the dashboard?
Open the **[online demo](https://gbemilekeadesiyan-a11y.github.io/GbemiShield-Grand-Marina-IoT-Security-System/)**, or just double-click `dashboard/dashboard_ai.html`.

The AI dashboard has a built-in **demo mode**: whenever it isn't served from `localhost` (or you add
`?demo` to the URL) it generates realistic sensor readings, blocked replay/tampering attacks and AI
anomalies right in the browser, and the header badge reads **DEMO** instead of **LIVE**. No broker,
certificates or Python needed.

When you run the real pipeline (`python src/subscriber_dashboard_ai.py`) the page is served from
`localhost:8000` and switches to live data from the WebSocket on port 8765 automatically.

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

Full analysis in [`reports/02_Threat_Model_STRIDE.pdf`](reports/02_Threat_Model_STRIDE.pdf).

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Rogue device impersonation | mTLS — device certificates |
| **Tampering** | Message modification in transit | HMAC-SHA256 signature |
| **Repudiation** | Denying message origin | Signed messages with device ID |
| **Information Disclosure** | Plaintext MQTT interception | TLS encryption on wire |
| **Denial of Service** | Replay flooding | Sequence counter + timestamp |
| **Elevation of Privilege** | Unauthorized broker access | Certificate-based authentication |

---

## Reports

Every written deliverable from the externship, in the order the work was done:

| # | Report | What it covers |
|---|---|---|
| 01 | [Asset CIA Analysis](reports/01_Asset_CIA_Analysis.pdf) | Confidentiality / integrity / availability scores (1–5) for each Grand Marina asset |
| 02 | [Threat Model (STRIDE)](reports/02_Threat_Model_STRIDE.pdf) | Full STRIDE threat analysis of the water-management system |
| 03 | [Vulnerability Analysis](reports/03_Vulnerability_Analysis.docx) | Weaknesses found in the unencrypted MQTT pipeline, with recommendations |
| 04 | [TLS Experiment Results](reports/04_TLS_Experiment_Results.pdf) | Eavesdropping, expired-cert and wrong-CA experiments with TLS |
| 05 | [Security Report](reports/05_Security_Report.docx) | Security assessment for the hotel's GM, recommending encryption |
| 06 | [Identify the Gap](reports/06_Identify_the_Gap.pdf) | Why the one-way TLS setup can't verify which device is talking |
| 07 | [mTLS Deliverable](reports/07_mTLS_Deliverable.pdf) | Screenshots: certificate generation, mTLS broker/publisher/subscriber, rogue-device rejection |
| 08 | [mTLS Benchmark Report](reports/08_mTLS_Benchmark_Report.pdf) | TLS vs mTLS connection time and latency (+2.5 ms / +11.5% to connect) |
| 09 | [Device Provisioning Policy](reports/09_Device_Provisioning_Policy.docx) | How device certificates are issued, stored and revoked |
| 10 | [Replay Attack Report](reports/10_Replay_Attack_Report.docx) | Replay attack defense report for the hotel's GM (HMAC + timestamp + sequence) |
| 11 | [Defense Experiment Results](reports/11_Defense_Experiment_Results.pdf) | Hypotheses vs results for the replay defense experiments |
| 12 | [Anomaly Detection Results](reports/12_Anomaly_Detection_Results.pdf) | Isolation Forest results: precision 0.74, recall 0.78, F1 0.76 |
| 13 | [Final Capstone](reports/13_Final_Capstone.pptx) | Final presentation of the full GbemiShield pipeline |

The model training notebook is in [`experiments/anomaly_detection_lab.ipynb`](experiments/anomaly_detection_lab.ipynb).

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
5. [`reports/05_Security_Report.docx`](reports/05_Security_Report.docx) — the Security Improvement Report
6. [`reports/13_Final_Capstone.pptx`](reports/13_Final_Capstone.pptx) — the final capstone presentation
