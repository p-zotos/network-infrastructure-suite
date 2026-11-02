# Network Infrastructure QA & Telemetry Suite

[![Network QA Suite](https://github.com/p-zotos/network-infrastructure-suite/actions/workflows/tests.yml/badge.svg)](https://github.com/p-zotos/network-infrastructure-suite/actions/workflows/tests.yml)

An automated Quality Assurance framework that captures, analyzes and monitors TCP traffic on Debian-based environments.
It runs deterministic baselines, high-load stress profiles, seeded fuzzing and live wire captures, and streams the resulting telemetry into a Prometheus + Grafana stack.

---

## 🛠 Project Architecture

The suite operates as a decoupled data-acquisition and test-assertion pipeline:

1. **Traffic Generation / Capture:** Scapy builds realistic TCP sessions (3-way handshake, data segments, delayed ACKs, FIN teardown) into `.pcap` files, or sniffs live traffic from a network interface.
2. **Analysis Engine (`analyzer.py`):** Streams the capture and tracks **per-flow TCP state** to measure retransmissions, out-of-order segments, arrival jitter and connection teardown.
3. **Automated Verification:** Two PyTest layers. Unit tests prove the analyzer is correct, and profile tests assert each traffic profile against thresholds in `config.json`.
4. **Telemetry Hub:** Every profile run pushes its metrics to a Prometheus Pushgateway, which feeds a provisioned Grafana dashboard.

```text
 generators / live sniffer ──► .pcap ──► NetworkAnalyzer ──► PyTest assertions
                                               │                    │
                                               ▼                    ▼
                                    JSON report (test_results/)  Pushgateway ──► Prometheus ──► Grafana
```

---

## 🔬 What the Analyzer Measures

| Metric | How it is computed |
|---|---|
| **Retransmissions** | A data segment whose sequence number was already seen *in the same flow* (src/dst IP **and** port). Pure ACKs carry no sequence space and are never counted. |
| **Out-of-order segments** | New data that starts below the highest sequence number already observed for the flow. |
| **Capture duplicates** | Identical segments seen again within 5 ms (e.g. the same frame captured twice on loopback). Reported but excluded from retransmissions. |
| **Arrival jitter** | Mean / max variation between consecutive inter-arrival times of data segments (IPDV, RFC 3393). |
| **Clean close / reset** | Presence of FIN and RST flags. |

Rates are calculated against **data segments** (segments with payload, SYN or FIN), the same way Wireshark's `tcp.analysis` does. Sequence comparisons handle 32-bit wraparound (RFC 1982). Payload length comes from the IP header, so Ethernet padding is never mistaken for data.

---

## 🧪 Test Strategy

| Layer | File | Purpose |
|---|---|---|
| **Analyzer unit tests** | `test_analyzer.py` | Hand-crafted captures with exact expected results: pure-ACK immunity, flow separation by port, retransmission vs. out-of-order, capture-duplicate filter, sequence wraparound, jitter. |
| **Profile tests** | `test_network.py` | Runs each profile from `config.json` through the analyzer and asserts its thresholds. Exploratory captures are checked against the generator's **ground truth**. |

---

## 📂 Project Structure

```text
.
├── analyzer.py                     # Per-flow TCP analysis engine & Pushgateway exporter
├── config.json                     # Profile matrix & threshold limits
├── test_analyzer.py                # Analyzer unit tests (known ground truth)
├── test_network.py                 # Profile assertion suite
├── capture_traffic.py              # Live sniffer for real-mode execution (Scapy)
├── generate_real_pcap.sh           # Alternative live capture using tshark
├── run_tests.sh                    # Automated shell controller wrapper
├── mock_generation_scripts/
│   ├── tcp_session.py              # Realistic TCP session builder shared by generators
│   ├── generate_normal_mock_pcap.py
│   ├── generate_stress_mock_pcap.py
│   └── generate_exploratory_mock_pcap.py  # Seeded fuzzer + ground-truth manifest
├── docker-compose.yml              # Prometheus, Pushgateway, Grafana
├── prometheus.yml
├── grafana/                        # Provisioned datasource & dashboard
└── .github/workflows/tests.yml     # CI: generate captures, run the full suite
```

Generated artifacts (`mock_data/`, `pcaps/`, `test_results/`) are rebuilt on every run and are not version controlled.

---

## ⚙️ Configuration Management (`config.json`)

System behavior and validation thresholds are managed entirely within `config.json`:

```json
{
  "modes": {
    "normal": {
      "pcap_path": "mock_data/mock_normal_data.pcap",
      "retrans_threshold": 2.0,
      "condition": "less_than"
    },
    "stress": {
      "pcap_path": "mock_data/mock_stress_data.pcap",
      "retrans_threshold": 5.0,
      "condition": "greater_than_or_equal"
    },
    "real": {
      "pcap_path": "pcaps/real_traffic.pcap",
      "retrans_threshold": 1.0,
      "condition": "less_than",
      "require_clean_close": false
    },
    "exploratory": {
      "pcap_path": "mock_data/mock_exploratory_data.pcap",
      "ground_truth_path": "mock_data/mock_exploratory_data.truth.json",
      "condition": "matches_ground_truth"
    }
  }
}
```

| Key | Meaning |
|---|---|
| `condition` | `less_than`, `greater_than_or_equal` (compared with `retrans_threshold`) or `matches_ground_truth`. Unknown values fail the test. |
| `require_clean_close` | Assert a FIN was observed (default `true`). Disabled for live captures, where a capture window rarely contains a full session. |

---

## 🚀 Execution Profiles

`./run_tests.sh` creates the virtual environment if needed, installs `requirements.txt` and regenerates the mock captures. With no argument it runs the full suite (unit tests plus all profiles).

```bash
./run_tests.sh          # everything
./run_tests.sh unit     # analyzer unit tests only
```

### 1. Normal Mode

A clean session with a stable 10 ms cadence, zero retransmissions and zero jitter. Asserts a retransmission rate **below 2%**.

```bash
./run_tests.sh normal
```

### 2. Stress Mode

A degraded link where 1 in 10 segments is retransmitted after a 50 ms timeout. Verifies the suite **flags** the degradation (rate **≥ 5%**).

```bash
./run_tests.sh stress
```

### 3. Real Mode (Live Capture)

Sniffs live TCP traffic from the default interface for 15 seconds, then analyzes it. The real profile is skipped automatically when no capture exists.

> ⚠️ Note: Requires root privileges to access the network interface.

```bash
./run_tests.sh real
CAPTURE_INTERFACE=ens33 CAPTURE_DURATION=30 ./run_tests.sh real
```

### 4. Exploratory Mode (Seeded Network Fuzzing)

Generates a random session (50–200 data segments, random socket identities and segment sizes) with three organic anomalies:

- **Fast retransmissions (6%):** re-sends the segment from three positions back, as after three duplicate ACKs.
- **Out-of-order delivery (3%):** a segment is overtaken on the wire by the next one.
- **Jitter spikes (4%):** sudden 200–500 ms routing delays.

The generator writes a **ground-truth manifest** of the anomalies it injected, and the test asserts that the analyzer detects exactly those counts. Every run prints its seed, so a failure can be replayed exactly:

```bash
./run_tests.sh exploratory
SEED=42 ./run_tests.sh exploratory
```

---

## 📊 Grafana & Prometheus Telemetry Integration

```bash
docker compose up -d     # Grafana: http://localhost:3000 (admin / admin)
./run_tests.sh
```

All three services are bound to `127.0.0.1`, so they are not reachable from the local network (the Pushgateway accepts unauthenticated writes). If the stack runs inside a VM, reach Grafana from the host via an SSH tunnel (`ssh -L 3000:localhost:3000 user@vm`) or VS Code Remote-SSH port forwarding.

Each profile run pushes its latest metrics to the Pushgateway (grouped by `mode`), which Prometheus scrapes every second. The provisioned **QA Network Infrastructure Suite** dashboard (folder *QA Infrastructure*) shows:

- Retransmission rate per mode (green < 2%, yellow < 5%, red ≥ 5%)
- PASS / FAIL status per mode
- Out-of-order rate and mean jitter
- Test runner host CPU / RAM footprint
- Time since the last run

| Environment variable | Default | Purpose |
|---|---|---|
| `PUSHGATEWAY_URL` | `localhost:9091` | Pushgateway target. Set to an empty string to disable pushing (as CI does). |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | Grafana admin password (can be set in a `.env` file). |
| `SEED` | random | Replay a specific exploratory fuzzing run. |
| `CAPTURE_INTERFACE` / `CAPTURE_DURATION` | default route / `15` | Live capture settings for real mode. |

Grafana uses file-based provisioning to register both the datasource and the dashboard when the container boots, so there are no manual UI imports:

```text
grafana/
├── provisioning/
│   ├── datasources/datasource.yml    # Prometheus datasource with fixed uid "Prometheus"
│   └── dashboards/dashboards.yml     # Dashboard file provider
└── dashboards/
    └── network_dashboard.json        # The dashboard layout
```

---

# 🔧 Troubleshooting

Below are the issues encountered, and how they were resolved, while building the telemetry dashboard.

---

## 🔍 Issue 1: Dashboard Missing / "Dashboard Not Found" Error

### Symptom

Grafana boots up cleanly but visiting the dashboard routing path results in a **"Dashboard Not Found"** error page.

Container logs show:

```text
failed to walk provisioned dashboards:
stat /var/lib/grafana/dashboards: no such file or directory
```

### Root Cause

Docker applies volume mounts only when a container is created. If you change `docker-compose.yml` or the mounted paths after creation, a plain `docker compose restart` keeps the old mounts.

### Resolution

Tear the containers down and recreate them so the new mounts are applied:

```bash
docker compose down
docker compose up -d --force-recreate
```

---

## 🔏 Issue 2: Linux Host Permissions Restrictions

### Symptom

The container paths are validated but dashboards remain unrendered.

### Root Cause

Inside the container, Grafana drops root privileges and runs as a non-root user (UID `472`). If the project files were modified by another host user or with `sudo`, their permissions may block that user from reading them.

### Resolution

Grant read access to the dashboard directory recursively:

```bash
chmod -R 755 grafana/dashboards/
```

---

## 🧩 Issue 3: Dashboard JSON Schema Incompatibility (Grafana Scenes)

### Symptom

Copying the JSON from Grafana's newer JSON Model screen into the provisioned file makes the dashboard disappear (**"Dashboard Not Found"**) after a restart.

### Root Cause

Newer Grafana UIs export dashboards in a nested layout format called **Scenes** (`"elements": {}`, `"kind": "Panel"`).

Grafana's file provisioning loader, however, expects the classic flat array model (`"panels": []`).

If the file contains unrecognized top-level keys and lacks the standard fields (`id: null`, `uid`, `schemaVersion`), Grafana silently skips it.

### Resolution

Keep the provisioned file in the classic format, with each panel's queries listed in its `targets`:

```json
{
  "id": null,
  "uid": "qa-network-infrastructure-suite",
  "title": "QA Network Infrastructure Suite",
  "schemaVersion": 38,
  "panels": [ ... ]
}
```

---

## 🔀 Issue 4: "Datasource Prometheus Not Found" Inside Visualizations

### Symptom

The dashboard page loads correctly and panels display their borders and titles, but charts show an error indicating the Prometheus data source cannot be found.

### Root Cause

Dashboards copied between Grafana instances often reference the datasource through:

- A randomly generated UID
  (e.g. `"PBFA97CFB590B2093"`)

**or**

- A template variable such as:

```text
${DS_PROMETHEUS}
```

Neither resolves to the datasource in the local Grafana instance.

### Resolution

Provision the datasource with a **fixed UID** (`uid: Prometheus` in `datasource.yml`) and reference that UID from every panel target in `network_dashboard.json`:

```json
"targets": [
  {
    "datasource": {
      "type": "prometheus",
      "uid": "Prometheus"
    },
    "expr": "qa_retransmission_rate",
    "refId": "A"
  }
]
```
