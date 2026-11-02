import argparse
import os
import sys
from scapy.all import sniff, wrpcap, conf

def live_network_capture(interface, duration_seconds, output_path):
    """
    Captures live production network traffic from a specified network interface
    for a controlled timeframe window and exports a standardized PCAP file.
    """
    print("========================================")
    print("INITIALIZING LIVE E2E NETWORK CAPTURE")
    print("========================================")
    print(f"[INFO] Monitoring Interface : {interface}")
    print(f"[INFO] Capture Timeframe    : {duration_seconds} seconds")
    print(f"[INFO] Target Export Path   : {output_path}")
    print("[*] Sniffing network sockets... Speak to the wire now.")

    # Ensure targeted output directory tree exists safely
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        # Sniff packets natively using Scapy kernel hooks
        # filter="tcp" isolates our dataset to TCP traffic to optimize processing
        captured_packets = sniff(
            iface=interface,
            timeout=duration_seconds,
            filter="tcp"
        )
    except PermissionError:
        print("[ERROR] Insufficient privileges! Packet sniffing requires root/sudo access.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during capture: {e}")
        sys.exit(1)

    packet_count = len(captured_packets)
    print(f"[+] Capture window completed. Intercepted {packet_count} TCP packets.")

    if packet_count == 0:
        # Fail loudly instead of handing the test suite an empty or fake trace
        print("[ERROR] No TCP sequences detected during this timeframe window.")
        print("[ERROR] Ensure active network traffic is flowing through the interface.")
        sys.exit(1)

    # Write memory frame buffers straight to raw PCAP storage
    wrpcap(output_path, captured_packets)
    print(f"[SUCCESS] Live network trace asset exported to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture live TCP traffic into a PCAP file.")
    parser.add_argument("--interface", default=str(conf.iface), help="Interface to sniff (default: system default route interface)")
    parser.add_argument("--duration", type=int, default=15, help="Capture window in seconds (default: 15)")
    parser.add_argument("--output", default="pcaps/real_traffic.pcap", help="Output PCAP path")
    args = parser.parse_args()

    live_network_capture(
        interface=args.interface,
        duration_seconds=args.duration,
        output_path=args.output
    )
