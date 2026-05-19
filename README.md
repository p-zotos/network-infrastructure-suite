# Network Infrastructure QA & Telemetry Suite

A robust, automated Quality Assurance framework designed to capture, analyze, and monitor network traffic patterns on Debian-based virtual environments.
This suite supports multi-mode execution—spanning pristine deterministic baselines, high-load stress profiles, real-world live wire captures, and randomized fuzzing vectors—and pipes the resulting telemetry directly into a Prometheus and Grafana visualization stack.

---

## 🛠 Project Architecture

The suite operates as a decoupled data-acquisition and test-assertion pipeline:

1. **Traffic Generation / Capture:** Scripts compile raw packet data into industry-standard `.pcap` binaries using Scapy.
2. **Analysis Engine:** Processes packet frames to evaluate metrics like duplicate sequence numbers (retransmissions), arrival jitter, and out-of-order execution flags.
3. **Automated Verification:** A PyTest harness correlates data metrics against profile thresholds configured via a central JSON matrix.
4. **Telemetry Hub:** The test cycle exposes or pushes metrics to Prometheus, populating a dynamic Grafana dashboard tracking infrastructure reliability.

---

## 📂 Project Structure

```text
.
├── config.json                     # Global orchestration matrix & threshold limits
├── test_network.py                 # PyTest assertion suite & Prometheus metric exporter
├── capture_traffic.py              # Raw socket sniffing utility for live-wire execution
├── run_tests.sh                    # Automated shell controller wrapper
├── mock_generation_scripts/        # Synthetic PCAP generation utilities
│   └── generate_exploratory_mock_pcap.py  # Fuzzing engine simulating organic network anomalies
└── mock_data/                      # Binary target directories for generated packet captures
    └── mock_exploratory_data.pcap
```

---

## ⚙️ Configuration Management (`config.json`)

System behavior and validation thresholds are managed entirely within `config.json`.

The framework maps metrics dynamically using the following structure:

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
      "condition": "less_than"
    },
    "exploratory": {
      "pcap_path": "mock_data/mock_exploratory_data.pcap",
      "retrans_threshold": 3.0,
      "condition": "less_than"
    }
  }
}
```

---

## 🚀 Execution Profiles

The wrapper controller `./run_tests.sh` accepts a target execution profile as an argument or execute them all if none provided.

### 1. Normal Mode

Validates standard network expectations against a clean, zero-jitter scenario with predictable sequence counts.

```bash
./run_tests.sh normal
```

### 2. Stress Mode

Evaluates systemic behavior under sustained, highly dense traffic streams to determine resilience boundaries.

```bash
./run_tests.sh stress
```

### 3. Real Mode (Live Capture)

Bypasses faked environments by spinning up a raw network sniffer directly on the local machine interface for 15 seconds. (WorkInProgress)

> ⚠️ Note: Requires elevated privileges to interface with network hardware.

```bash
./run_tests.sh real
```

### 4. Exploratory Mode (Network Fuzzing)

Runs a synthetic generation pass that injects random packet counts (between 50 and 200), randomizes socket identities, and exposes the framework to three organic network anomalies:

- **Packet Drops / Retransmissions:** Injects random duplicate frame weights.
- **Out-of-Order Delivery:** Swaps timeline stamps to simulate misrouted packets.
- **Jitter Spikes:** Artificially introduces random 200ms–500ms server processing lags.

```bash
./run_tests.sh exploratory
```

---

## 📊 Grafana & Prometheus Telemetry Integration

The Network Infrastructure QA & Telemetry Suite leverages a fully automated containerized stack to capture, parse, and visualize traffic and host behavior patterns during automated test executions. When `rn_tests.sh` runs, telemetry hooks emit data streams directly into Prometheus, which are instantly mirrored to a persistent, provisioned Grafana dashboard.

---

## 🚀 Architecture Overview

1. **Traffic & Host Scrapers:**  
   Active processes monitor retransmission rates, CPU footprint, and test outcome states, exposing them as Prometheus-compliant metrics.

2. **Prometheus Data Layer:**  
   Collects and stores time-series data scraped from the suite's execution endpoints.

3. **Automated Provisioning:**  
   Grafana uses file-based configuration layout providers to register the telemetry dashboard automatically upon container boot (`docker compose up`), completely eliminating manual UI import procedures.

---

## 📂 Directory & Deployment Structure

To ensure configuration persistence across `docker compose down` cycles, assets are arranged locally inside the project workspace as follows:

```text
.
├── docker-compose.yml
├── run_tests.sh
└── grafana/
    ├── provisioning/
    │   └── dashboards/
    │       └── dashboards.yaml       # Defines dashboard file providers for Grafana
    └── dashboards/
        └── network_dashboard.json    # The core dashboard layout configuration
```

---

## ⚙️ Provisioning Configurations

### 1. The Provider Manifest  
`grafana/provisioning/dashboards/dashboards.yaml`

This file instructs Grafana's core initialization engine to poll local disk storage inside the container path for dashboard objects:

```yaml
apiVersion: 1

providers:
  - name: 'My QA Dashboards'
    orgId: 1
    folder: 'QA Infrastructure'
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
```

---

### 2. The Compose Mapping Layer  
`docker-compose.yml`

To mirror your host files directly into the sandbox namespace, the Grafana service definition mounts the workspace directories using the following relative paths:

```yaml
grafana:
  image: grafana/grafana:latest
  container_name: qa_grafana
  ports:
    - "3000:3000"
  volumes:
    - ./grafana/provisioning:/etc/grafana/provisioning
    - ./grafana/dashboards:/var/lib/grafana/dashboards
```

---

# 🔧 Troubleshooting

Below are the engineering blocks and configuration rules established during the implementation of the telemetry dashboard system.

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

Docker volume states are evaluated strictly at container initialization. Modifying `docker-compose.yml` or the file-tree pathing after the container has been built and applying a standard `docker compose restart` does not apply updated mount instructions.

### Resolution

Destroy the active namespace cache and rebuild the structural layers with explicit recreation flags:

```bash
docker compose down
docker compose up -d --force-recreate
```

---

## 🔏 Issue 2: Linux Host Permissions Restrictions

### Symptom

The container paths are validated but dashboards remain unrendered.

### Root Cause

Inside the container architecture, Grafana drops root privileges and operates under a generic non-root UID (`472`). If project files are manipulated locally by the host user or via `sudo`, read authorization flags can become restricted, locking out the internal parser.

### Resolution

Open recursive read access to the shared dashboard volume path:

```bash
chmod -R 755 grafana/dashboards/
```

---

## 🧩 Issue 3: Architectural Layout Schema Incompatibilities (Grafana Scenes Engine)

### Symptom

Saving or copy-pasting the raw text from Grafana's newer JSON Model screen back to your host file causes the dashboard to immediately disappear with a **"Dashboard Not Found"** state upon restart.

### Root Cause

Modern Grafana user interfaces use a nested dictionary-backed layout engine called **Scenes** (`"elements": {}`, `"kind": "Panel"`).

However, Grafana’s file provisioning loader expects a legacy flat array model (`"panels": []`) to boot resources.

When it encounters unmapped top-level keys without standard boot metadata flags (`id: null`, `uid`, `schemaVersion`), it silently drops the file from memory.

### Resolution

Standardize the local tracking file to use backward-compatible schema models mapping metrics directly to explicit targets:

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

High-level dashboard layouts copied across instances often include:

- Randomized hardcoded UID strings  
  (e.g. `"PBFA97CFB590B2093"`)

**or**

- Variable bindings like:

```text
${DS_PROMETHEUS}
```

These fail to bind against the localized Grafana data connection.

### Resolution

Hardcode the connection definition block inside every panel target array within `network_dashboard.json` so it explicitly references the literal Prometheus datasource name exactly as registered in Grafana:

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
