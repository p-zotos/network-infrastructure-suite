from scapy.all import rdpcap, IP, TCP, UDP
import ssl
import socket
from datetime import datetime

class QANetworkTool:
    def __init__(self, pcap_path=None):
        self.pcap_path = pcap_path

    def analyze_traffic(self):
        """Analyzes PCAP files for a QA reporting."""
        if not self.pcap_path:
            return "No PCAP file provided."
        
        packets = rdpcap(self.pcap_path)
        stats = {"TCP": 0, "UDP": 0, "Total": len(packets)}
        
        for pkt in packets:
            if pkt.haslayer(TCP): stats["TCP"] += 1
            if pkt.haslayer(UDP): stats["UDP"] += 1
        
        print(f"--- Traffic Analysis Report ---")
        for proto, count in stats.items():
            print(f"{proto}: {count}")

    def verify_ssl(self, host):
        """Verifies SSL (OpenSSL/Security testing)."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    print(f"--- SSL Security Check: {host} ---")
                    print(f"Certificate valid until: {expire_date}")
        except Exception as e:
            print(f"SSL Verification Failed: {e}")

if __name__ == "__main__":
    tool = QANetworkTool(pcap_path="sample.pcap")

    tool.verify_ssl("google.com")
    tool.analyze_traffic()
