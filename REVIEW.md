# Codebase Review — Network Infrastructure QA & Telemetry Suite

_Review date: 2026-10-21 · Reviewed commit: `885b41f`_

> **Status (2026-11-02):** All bugs in section 1 are fixed. Section 2 is addressed by `test_analyzer.py` (unit layer) and ground-truth checks for exploratory runs. From section 3, 3.4 (CI) and 3.5 (seeded fuzzing) are done, and 3.3 is partly done (per-flow state, out-of-order, jitter). Section 4 is done. Still open: 3.1 (`tc netem`), 3.2 (Wireshark cross-check), and RTT / duplicate-ACK metrics from 3.3.

## Summary

The architecture is solid for a portfolio project: generator → analyzer → pytest → Pushgateway → Grafana, with config-driven thresholds and provisioned dashboards. The main problems are in correctness, and someone who knows networking would find several of them within minutes. Fix those before adding new features.

---

## 1. Confirmed bugs

### 1.1 Exploratory retransmissions are never detected
- **Where:** [generate_exploratory_mock_pcap.py:53](mock_generation_scripts/generate_exploratory_mock_pcap.py#L53) vs [analyzer.py:70](analyzer.py#L70)
- **Problem:** The injected duplicate arrives **4 ms** after the original, but the analyzer ignores anything under **5 ms**.
- **Evidence:** 11 of the 12 committed exploratory reports show `total_retransmissions: 0`, even though about 6% of packets are injected as retransmissions. The exploratory test passes because of this bug, not because the analyzer works.
- **Fix:** Model a realistic retransmission timeout: re-send the segment ≥ 200 ms later, after a few more packets.

### 1.2 Missing `import socket` in the normal and stress generators
- **Where:** [generate_normal_mock_pcap.py:9](mock_generation_scripts/generate_normal_mock_pcap.py#L9), [generate_stress_mock_pcap.py:9](mock_generation_scripts/generate_stress_mock_pcap.py#L9)
- **Problem:** `socket` is never imported. The resulting `NameError` is swallowed by `except Exception`, so the code always falls back to the hardcoded IP.
- **Evidence:** Every stress report has destination `172.217.16.142`.
- **Fix:** Remove the DNS lookup entirely and use fixed documentation IPs (`192.0.2.x` / `198.51.100.x`). The tests shouldn't depend on the internet.

### 1.3 Retransmission detection false positives on real traffic
- **Where:** [analyzer.py:56](analyzer.py#L56)
- **Problem:** Retransmissions are keyed on `(src, dst, seq)` and the payload is ignored:
  - Pure ACKs (no payload) keep repeating the same sequence number, so **every ACK more than 5 ms apart counts as a retransmission**.
  - Ports are left out, so separate flows between the same two hosts get mixed together.
  - The denominator counts every TCP packet. Wireshark-style rates count data segments only.
- **Fix:** Track state per flow using the full address-and-port tuple. Consider only segments with a payload (or SYN/FIN), and compare `seq + len` against the highest sequence number seen so far.

### 1.4 Out-of-order step does not reorder anything
- **Where:** [generate_exploratory_mock_pcap.py:62-65](mock_generation_scripts/generate_exploratory_mock_pcap.py#L62-L65)
- **Problem:** The step swaps timestamps but not the order of packets in the list. The analyzer reads packets in file order, so `delay_ms` can come out negative. Nothing in the analyzer measures out-of-order packets.
- **Fix:** Swap the list positions (keeping the timestamps monotonic), and add out-of-order detection to the analyzer.

### 1.5 Fallback "dummy packet" is not a valid pcap
- **Where:** [generate_real_pcap.sh:29](generate_real_pcap.sh#L29)
- **Problem:** `xxd -r -p` writes a raw Ethernet frame with no pcap header, so `rdpcap` will reject it. Faking data so the test doesn't crash also hides real failures.
- **Fix:** Exit with a non-zero code and have the test `pytest.skip()` or fail when the capture is empty.

### 1.6 Test assertion logic
- **Where:** [test_network.py:42-45](test_network.py#L42-L45)
- **Problems:**
  - An unknown `condition` passes silently because there is no `else` branch.
  - The assertions have no failure messages.
  - `pcap_file`, `threshold` and `condition` are assigned (lines 23–25) and then never used.
  - `config.json` is opened with a cwd-relative path, so pytest fails when run from another directory.
- **Fix:** Use a mapping of condition name → `operator` function and `pytest.fail` on unknown conditions. Add assertion messages, and resolve paths with `Path(__file__).parent`.

### 1.7 Incomplete `requirements.txt`
- **Where:** [requirements.txt](requirements.txt)
- **Problem:** `psutil` and `pytest` are missing. `run_tests.sh` runs `pip install pytest` on every run to make up for it.
- **Fix:** Pin all dependencies and run `pip install -r requirements.txt` once.

### 1.8 Grafana datasource has no fixed UID
- **Where:** [datasource.yml](grafana/provisioning/datasources/datasource.yml)
- **Problem:** The dashboard refers to `uid: "Prometheus"`, but the provisioned datasource has no `uid`. It currently works only because Grafana falls back to matching by name. That is the fragile setup behind README "Issue 4".
- **Fix:** Add `uid: Prometheus` to the datasource definition.

---

## 2. Design issue: you're testing the generator, not the network

The `normal`, `stress` and `exploratory` modes all run on synthetic data produced by your own scripts. Each one passes or fails depending on whether the generator did what you expected. Stress mode makes this obvious: it passes when retransmissions are **at least 5%**, so the "network test" passes when the network is bad.

Split the suite into two layers:

| Layer | Purpose | Input | Assertions |
|---|---|---|---|
| **Analyzer unit tests** | Prove the tool is correct | Packets built in memory with Scapy | *Exact* counts, e.g. "10 retransmissions, 2 out-of-order, 0 false positives on pure ACKs" |
| **Network tests** | Prove the network meets its SLA | Real traffic under controlled impairment | Thresholds (loss %, RTT, jitter, throughput) |

---

## 3. Additions for a networking portfolio

Highest value first.

### 3.1 Controlled impairment with `tc netem`
Create two network namespaces (or Docker containers) joined by a veth pair, then apply impairment:

```bash
tc qdisc add dev veth0 root netem loss 5% delay 50ms 10ms
```

Generate traffic with `iperf3` or `curl`, capture it with `tcpdump`, and assert that the analyzer detects about 5% loss. This makes "real" mode deterministic, CI-friendly and genuinely about networking.

### 3.2 Validate against Wireshark
Run `tshark -r capture.pcap -Y tcp.analysis.retransmission` on the same pcap and assert that your counts match. "My analyzer agrees with Wireshark" is a strong, easy-to-verify claim.

### 3.3 Full TCP analysis engine
Track state per flow and report:
- Retransmissions (based on `seq + len`), out-of-order segments, duplicate ACKs and fast retransmits
- RTT (SYN → SYN/ACK, and data → ACK)
- Jitter (RFC 3550 interarrival jitter)
- Throughput per flow
- Handshake success rate (SYN → SYN/ACK → ACK), RST rate, zero-window events

The README already promises jitter and out-of-order detection, but neither is implemented yet.

### 3.4 CI pipeline
Add a GitHub Actions workflow that runs the unit tests on every push and publishes JUnit XML or `pytest-html` reports as artifacts. Put the status badge in the README.

### 3.5 Reproducible fuzzing
Seed `random`, log the seed in every report, and accept `--seed` so any failing run can be replayed exactly.

---

## 4. Smaller fixes

**Git hygiene**
- Add `test_results/`, `pcaps/` and `mock_data/*.pcap` to `.gitignore`. The pcaps are regenerated on every run, and the exploratory one changes every time, so the working tree is always dirty.

**Metrics push**
- Rename `push_metrics_to_grafana`, because it pushes to the Pushgateway, not to Grafana.
- Use `prometheus_client.push_to_gateway` with `Gauge` objects instead of hand-building the text payload, and add `# TYPE` metadata.
- Read the Pushgateway URL from config or an environment variable instead of hardcoding `localhost:9091`.

**Host metrics**
- The CPU and RAM values come from the machine running pytest while it parses a file, not from the network infrastructure. Either rename them that way or replace them with something like interface counters.

**Dashboard**
- The retransmission panel turns red at **80**%, but the configured thresholds are 1–5%. Set per-mode thresholds.
- Add a "last run" panel based on `push_time_seconds`.

**Docker**
- Drop the obsolete `version:` key from `docker-compose.yml`.
- Pin image tags instead of using `:latest`.
- Move the Grafana admin password into a `.env` file.

**Analyzer and capture scripts**
- Use `PcapReader` (streaming) instead of `rdpcap` so large captures don't have to fit in memory.
- Use `argparse` in `capture_traffic.py` for the interface, duration and output path, instead of the hardcoded `ens33`.
- Use `logging` instead of `print`, and add type hints.

**Shell scripts**
- `run_tests.sh`: check that `venv/` exists before running `source`, and pass the pytest exit code through.
- `generate_real_pcap.sh`: translate the Greek comments to English for international reviewers.

**README**
- Fix the `rn_tests.sh` typo.
- The README refers to `dashboards.yaml`, but the file is `dashboards.yml`.
- The README shows the folder as `'QA Infrastructure'`, but the provisioning config has `''`.
- The stress generator comment mentions a "15ms TSO filter", but the analyzer uses 5 ms.
- Make sure the description matches what is actually implemented (jitter and out-of-order detection).

---

## 5. Suggested roadmap

1. Fix bugs 1.1–1.8 (small and fast).
2. Add analyzer unit tests with exact assertions against crafted packets.
3. Rebuild the analyzer with per-flow state, out-of-order detection, jitter and RTT (3.3).
4. Rebuild real mode on `tc netem` impairment (3.1), with Wireshark cross-validation (3.2).
5. Add CI (3.4) and clean up the README.
