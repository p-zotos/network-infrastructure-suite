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

> TODOO

---

## 🔧 Troubleshooting 

> TODO
