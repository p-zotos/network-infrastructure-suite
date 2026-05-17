import sys
import os
from scapy.all import sniff, wrpcap
from datetime import datetime

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
        
        packet_count = len(captured_packets)
        print(f"[+] Capture window completed. Intercepted {packet_count} TCP packets.")

        if packet_count == 0:
            print("[WARN] No TCP sequences detected during this timeframe window.")
            print("[WARN] Ensure active network traffic is flowing through the interface.")
        
        # Write memory frame buffers straight to raw PCAP storage
        wrpcap(output_path, captured_packets)
        print(f"[SUCCESS] Live network trace asset exported seamlessly to: {output_path}")

    except PermissionError:
        print("[ERROR] Insufficient privileges! Packet sniffing requires root/sudo access.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # --- Configuration Blocks ---
    TARGET_INTERFACE = "ens33" 
    CAPTURE_DURATION = 15  # Timeframe window in seconds
    TARGET_OUTPUT = "pcaps/real_traffic.pcap"
    # ----------------------------

    # Allow overriding timeframe via command line execution flags
    if len(sys.argv) > 1:
        try:
            CAPTURE_DURATION = int(sys.argv[1])
        except ValueError:
            print(f"[WARN] Invalid duration argument. Falling back to default: {CAPTURE_DURATION}s")

    live_network_capture(
        interface=TARGET_INTERFACE,
        duration_seconds=CAPTURE_DURATION,
        output_path=TARGET_OUTPUT
    )
