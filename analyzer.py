import os
import json
import statistics
import psutil
from datetime import datetime
from pathlib import Path
from scapy.all import PcapReader, IP, IPv6, TCP
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "test_results"
DEFAULT_PUSHGATEWAY_URL = "localhost:9091"
SEQ_MOD = 2**32


def seq_before(a, b):
    """True if sequence number `a` precedes `b`, accounting for 32-bit wraparound (RFC 1982)."""
    return a != b and ((b - a) % SEQ_MOD) < SEQ_MOD // 2


def tcp_payload_length(pkt):
    """TCP payload size derived from the IP header, so Ethernet padding is never counted as data."""
    tcp = pkt[TCP]
    if IP in pkt:
        return pkt[IP].len - pkt[IP].ihl * 4 - tcp.dataofs * 4
    # IPv6 payload length also covers any extension headers sitting between IPv6 and TCP
    ip6 = pkt[IPv6]
    extension_headers_len = len(ip6.payload) - len(tcp)
    return ip6.plen - extension_headers_len - tcp.dataofs * 4


class FlowState:
    """Per-direction TCP state, keyed by the (src_ip, src_port, dst_ip, dst_port) tuple."""

    def __init__(self):
        self.first_seen = {}      # { seq_num: first_timestamp }
        self.highest_end = None   # Highest seq + segment length observed so far
        self.last_arrival = None
        self.last_interarrival = None


class NetworkAnalyzer:
    def __init__(self, pcap_path=None, results_dir=DEFAULT_RESULTS_DIR, capture_duplicate_ms=5.0):
        self.pcap_path = pcap_path
        self.results_dir = Path(results_dir)
        # Identical segments seen again within this window are capture artifacts
        # (e.g. the same frame on loopback + "any"), not real retransmissions
        self.capture_duplicate_ms = capture_duplicate_ms
        self.metrics = {}
        self.cpu_usage = 0.0
        self.ram_usage = 0.0

    def analyze_network_profile(self, user_mode):
        """
        Parses network traffic captures, computes raw protocol metrics,
        and extracts concurrent system infrastructure utilization footprints.

        Returns:
            dict: A comprehensive data packet containing network metrics,
                  hardware utilization, and failed packet metadata.
        """
        if not self.pcap_path:
            print("[WARN] No PCAP source path specified for metrics extraction.")
            return None

        print("\n========================================")
        print("EXECUTING NETWORK TELEMETRY EXTRACTION")
        print("========================================")
        print(f"[INFO] Target Trace: {self.pcap_path}")

        flows = {}
        failed_packets_metrics = []
        jitter_samples_ms = []

        total_tcp_packets = 0
        data_segments = 0
        retransmissions_count = 0
        out_of_order_count = 0
        capture_duplicates = 0
        clean_close = False
        connection_failed = False

        # Stream the trace packet by packet so large captures never have to fit in memory
        with PcapReader(str(self.pcap_path)) as packets:
            for pkt in packets:
                if TCP not in pkt or (IP not in pkt and IPv6 not in pkt):
                    continue
                total_tcp_packets += 1

                ip = pkt[IP] if IP in pkt else pkt[IPv6]
                tcp = pkt[TCP]
                flags = tcp.flags
                timestamp = float(pkt.time)

                if "F" in flags:
                    clean_close = True
                if "R" in flags:
                    connection_failed = True

                # Only segments that consume sequence space can be retransmitted.
                # Pure ACKs legitimately repeat the same seq number and are skipped.
                payload_len = tcp_payload_length(pkt)
                seg_len = payload_len + ("S" in flags) + ("F" in flags)
                if seg_len <= 0:
                    continue

                flow = flows.setdefault((ip.src, tcp.sport, ip.dst, tcp.dport), FlowState())
                seq_num = tcp.seq

                delay_ms = None
                if seq_num in flow.first_seen:
                    delay_ms = (timestamp - flow.first_seen[seq_num]) * 1000
                    if delay_ms < self.capture_duplicate_ms:
                        capture_duplicates += 1
                        continue
                data_segments += 1

                # Arrival jitter of the data stream: variation between consecutive
                # inter-arrival times (IPDV, RFC 3393). Handshake/teardown timing is excluded.
                if payload_len > 0:
                    if flow.last_arrival is not None:
                        interarrival = timestamp - flow.last_arrival
                        if flow.last_interarrival is not None:
                            jitter_samples_ms.append(abs(interarrival - flow.last_interarrival) * 1000)
                        flow.last_interarrival = interarrival
                    flow.last_arrival = timestamp

                # Evaluate TCP sequence numbers to detect network drops/retries
                if delay_ms is not None:
                    retransmissions_count += 1
                    failed_packets_metrics.append({
                        "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                        "source": f"{ip.src}:{tcp.sport}",
                        "destination": f"{ip.dst}:{tcp.dport}",
                        "sequence_number": seq_num,
                        "retransmit_delay_ms": round(delay_ms, 2),
                        "window_size": tcp.window
                    })
                    continue

                flow.first_seen[seq_num] = timestamp
                seg_end = (seq_num + seg_len) % SEQ_MOD
                if flow.highest_end is not None and seq_before(seq_num, flow.highest_end):
                    # New data that starts below what we've already seen arrived late
                    out_of_order_count += 1
                elif flow.highest_end is None or seq_before(flow.highest_end, seg_end):
                    flow.highest_end = seg_end

        if data_segments == 0:
            print("[WARN] Analysis completed. No TCP data segments identified.")
            return None

        # Profile host system state of the test runner (short sampling window for a valid reading)
        self.cpu_usage = psutil.cpu_percent(interval=0.1)
        self.ram_usage = psutil.virtual_memory().percent

        # Rates are relative to data segments, matching Wireshark's tcp.analysis semantics
        retrans_rate = (retransmissions_count / data_segments) * 100
        out_of_order_rate = (out_of_order_count / data_segments) * 100
        mean_jitter_ms = statistics.fmean(jitter_samples_ms) if jitter_samples_ms else 0.0
        max_jitter_ms = max(jitter_samples_ms, default=0.0)

        self.metrics = {
            "execution_time": datetime.now().isoformat(),
            "mode": user_mode,
            "total_tcp_packets": total_tcp_packets,
            "data_segments": data_segments,
            "tcp_flows": len(flows),
            "total_retransmissions": retransmissions_count,
            "retransmission_rate_percent": round(retrans_rate, 2),
            "out_of_order_segments": out_of_order_count,
            "out_of_order_rate_percent": round(out_of_order_rate, 2),
            "capture_duplicates_ignored": capture_duplicates,
            "mean_jitter_ms": round(mean_jitter_ms, 3),
            "max_jitter_ms": round(max_jitter_ms, 3),
            "is_clean_close": clean_close,
            "is_connection_failed": connection_failed
        }

        print(f"[*] Analysis Results -> Packets: {total_tcp_packets} | Data Segments: {data_segments} | "
              f"Retransmissions: {retransmissions_count} ({retrans_rate:.2f}%) | "
              f"Out-of-Order: {out_of_order_count} | Mean Jitter: {mean_jitter_ms:.2f}ms")

        # Compile full operational database payload
        report_data = {
            "network_metrics": self.metrics,
            "runner_host_footprint": {
                "cpu_utilization_percent": self.cpu_usage,
                "ram_utilization_percent": self.ram_usage
            },
            "failed_packets": failed_packets_metrics
        }

        # Export full structured analysis report to localized file
        now = datetime.now()
        output_path = self.results_dir / now.strftime("%Y-%m-%d") / f"{user_mode}_{now.strftime('%Y%m%d_%H%M%S')}_telemetry.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=4)
            print(f"[+] Operational analysis trace saved locally: {output_path}")

        return report_data

    def push_metrics_to_pushgateway(self, user_mode, is_passed):
        """
        Publishes the latest run's metrics to the Prometheus Pushgateway, grouped by mode.
        Set PUSHGATEWAY_URL to override the target, or to an empty string to disable pushing.
        """
        gateway = os.environ.get("PUSHGATEWAY_URL", DEFAULT_PUSHGATEWAY_URL)
        if not gateway or not self.metrics:
            return

        registry = CollectorRegistry()
        gauges = {
            "qa_retransmission_rate": ("TCP retransmission rate (percent of data segments)", self.metrics["retransmission_rate_percent"]),
            "qa_out_of_order_rate": ("Out-of-order segment rate (percent of data segments)", self.metrics["out_of_order_rate_percent"]),
            "qa_mean_jitter_ms": ("Mean arrival jitter in milliseconds", self.metrics["mean_jitter_ms"]),
            "qa_total_tcp_packets": ("Total parsed TCP packets", self.metrics["total_tcp_packets"]),
            "qa_test_status": ("Execution status outcome (1=PASS, 0=FAIL)", 1 if is_passed else 0),
            "qa_infra_cpu_utilization": ("Test runner host CPU utilization percentage", self.cpu_usage),
            "qa_infra_ram_utilization": ("Test runner host RAM utilization percentage", self.ram_usage),
        }
        for name, (description, value) in gauges.items():
            Gauge(name, description, registry=registry).set(value)

        try:
            push_to_gateway(gateway, job="network_qa_suite", grouping_key={"mode": user_mode}, registry=registry, timeout=2)
            print("[+] Telemetry metric gateway push: SUCCESS")
        except Exception as e:
            print(f"[WARN] Could not push metrics to gateway: {e}")
