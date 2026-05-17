from scapy.all import rdpcap, IP, TCP
import os
import json
import psutil
import urllib.request
from datetime import datetime

class NetworkAnalyzer:
    def __init__(self, pcap_path=None):
        self.pcap_path = pcap_path
        self.retrans_rate = 0.0
        self.total_tcp_packets = 0
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

        # Extract network metrics from the target trace file
        packets = rdpcap(self.pcap_path)
        
        seen_sequences = {}  # Format: { (src_ip, dst_ip, seq_num): first_timestamp }
        failed_packets_metrics = []
        
        total_tcp_packets = 0
        retransmissions_count = 0
        clean_close = False
        connection_failed = False

        # Profile host system state during execution window
        self.cpu_usage = psutil.cpu_percent(interval=None)
        self.ram_usage = psutil.virtual_memory().percent

        for pkt in packets:
            if IP in pkt and TCP in pkt:
                total_tcp_packets += 1
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                seq_num = pkt[TCP].seq
                packet_id = (src_ip, dst_ip, seq_num)
                timestamp = float(pkt.time)

                if "F" in pkt[TCP].flags:
                    clean_close = True
                if "R" in pkt[TCP].flags:
                    connection_failed = True

                # Evaluate TCP sequence numbers to detect network drops/retries
                if packet_id in seen_sequences:
                    first_timestamp = seen_sequences[packet_id]
                    delay_ms = (timestamp - first_timestamp) * 1000
                    
                    # RTO validation step: skip local host loopback duplications (< 5ms)
                    if delay_ms > 5.0:
                        retransmissions_count += 1
                        failed_packets_metrics.append({
                            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                            "source": src_ip,
                            "destination": dst_ip,
                            "sequence_number": seq_num,
                            "retransmit_delay_ms": round(delay_ms, 2),
                            "window_size": pkt[TCP].window
                        })
                else:
                    seen_sequences[packet_id] = timestamp

        if total_tcp_packets == 0:
            print("[WARN] Analysis completed. No active TCP sequences identified.")
            return None

        # Calculate mathematical rates
        retrans_rate = (retransmissions_count / total_tcp_packets) * 100
        self.retrans_rate = retrans_rate
        self.total_tcp_packets = total_tcp_packets

        print(f"[*] Analysis Results -> Packets: {total_tcp_packets} | Retransmissions: {retransmissions_count} | Rate: {retrans_rate:.2f}%")

        # Compile full operational database payload
        report_data = {
            "network_metrics": {
                "execution_time": datetime.now().isoformat(),
                "mode": user_mode,
                "total_tcp_packets": total_tcp_packets,
                "total_retransmissions": retransmissions_count,
                "retransmission_rate_percent": round(retrans_rate, 2),
                "is_clean_close": clean_close,
                "is_connection_failed": connection_failed
            },
            "infrastructure_visibility": {
                "cpu_utilization_percent": self.cpu_usage,
                "ram_utilization_percent": self.ram_usage
            },
            "failed_packets": failed_packets_metrics
        }

        # Export full structured analysis report to localized file
        current_date = datetime.now().strftime("%Y-%m-%d")
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"test_results/{current_date}/{user_mode}_{timestamp_str}_telemetry.json"

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=4)
            print(f"[+] Operational analysis trace saved locally: {output_path}")

        return report_data

    def push_metrics_to_grafana(self, user_mode, is_passed):
        """
        Transmits compiled line protocol payloads directly to the Prometheus Pushgateway.
        """
        status_metric = 1 if is_passed else 0
        
        metrics_payload = (
            f"# HELP qa_retransmission_rate TCP Retransmission Rate percentage\n"
            f"qa_retransmission_rate{{mode=\"{user_mode}\"}} {self.retrans_rate}\n"
            f"# HELP qa_total_tcp_packets Total parsed TCP packets\n"
            f"qa_total_tcp_packets{{mode=\"{user_mode}\"}} {self.total_tcp_packets}\n"
            f"# HELP qa_test_status Execution status outcome (1=PASS, 0=FAIL)\n"
            f"qa_test_status{{mode=\"{user_mode}\"}} {status_metric}\n"
            f"# HELP qa_infra_cpu_utilization System host CPU footprint percentage\n"
            f"qa_infra_cpu_utilization{{mode=\"{user_mode}\"}} {self.cpu_usage}\n"
            f"# HELP qa_infra_ram_utilization System host RAM footprint percentage\n"
            f"qa_infra_ram_utilization{{mode=\"{user_mode}\"}} {self.ram_usage}\n"
        )
        
        url = "http://localhost:9091/metrics/job/network_qa_suite"
        try:
            req = urllib.request.Request(
                url, 
                data=metrics_payload.encode('utf-8'), 
                method='POST',
                headers={'Content-Type': 'text/plain; version=0.0.4'}
            )
            with urllib.request.urlopen(req, timeout=2) as response:
                if response.status in [200, 202]:
                    print("[+] Telemetry metric gateway push: SUCCESS")
        except Exception as e:
            print(f"[WARN] Could not push metrics to gateway: {e}")
