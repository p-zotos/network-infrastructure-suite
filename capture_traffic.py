import argparse
import os
import sys
import threading
import urllib.request
from scapy.all import AsyncSniffer, wrpcap, conf, get_if_list

DEFAULT_TARGET_URL = "https://example.com"

def generate_traffic(stop_event, target_url, interval=0.5):
    """Issues HTTPS requests until stopped, so every capture window contains complete TCP sessions."""
    requests_sent = 0
    while not stop_event.is_set():
        try:
            with urllib.request.urlopen(target_url, timeout=3) as response:
                response.read()
            requests_sent += 1
        except Exception as e:
            print(f"[WARN] Traffic request to {target_url} failed: {e}")
        stop_event.wait(interval)
    print(f"[INFO] Traffic generator completed {requests_sent} requests to {target_url}")

def live_network_capture(interface, duration_seconds, output_path, target_url=None):
    """
    Captures live production network traffic from a specified network interface
    for a controlled timeframe window and exports a standardized PCAP file.
    If a target URL is given, traffic is generated only once the sniffer is running.
    """
    print("========================================")
    print("INITIALIZING LIVE E2E NETWORK CAPTURE")
    print("========================================")
    print(f"[INFO] Monitoring Interface : {interface}")
    print(f"[INFO] Capture Timeframe    : {duration_seconds} seconds")
    print(f"[INFO] Target Export Path   : {output_path}")
    print(f"[INFO] Traffic Source       : {target_url or 'passive (existing traffic only)'}")

    # Ensure targeted output directory tree exists safely
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sniffer_started = threading.Event()
    stop_traffic = threading.Event()
    try:
        # filter="tcp" isolates our dataset to TCP traffic to optimize processing
        sniffer = AsyncSniffer(iface=interface, filter="tcp", started_callback=sniffer_started.set)
        sniffer.start()
        if not sniffer_started.wait(timeout=10):
            sniffer.join()  # Surfaces the sniffer thread's exception (permissions, missing libpcap...)
            raise RuntimeError("Sniffer did not start within 10 seconds")
        print("[*] Sniffer is live. Capturing network sockets...")

        traffic = None
        if target_url:
            traffic = threading.Thread(target=generate_traffic, args=(stop_traffic, target_url), daemon=True)
            traffic.start()

        stop_traffic.wait(duration_seconds)
        stop_traffic.set()
        if traffic:
            traffic.join(timeout=5)
        captured_packets = sniffer.stop()
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
        print(f"[ERROR] Available interfaces: {', '.join(get_if_list())}")
        print("[ERROR] Retry with the interface that carries your traffic, e.g. CAPTURE_INTERFACE=ens33 ./run_tests.sh real")
        sys.exit(1)

    # Write memory frame buffers straight to raw PCAP storage
    wrpcap(output_path, captured_packets)
    print(f"[SUCCESS] Live network trace asset exported to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture live TCP traffic into a PCAP file.")
    parser.add_argument("--interface", default=str(conf.iface), help="Interface to sniff (default: system default route interface)")
    parser.add_argument("--duration", type=int, default=15, help="Capture window in seconds (default: 15)")
    parser.add_argument("--output", default="pcaps/real_traffic.pcap", help="Output PCAP path")
    parser.add_argument("--target-url", default=DEFAULT_TARGET_URL, help=f"URL to request during the capture (default: {DEFAULT_TARGET_URL})")
    parser.add_argument("--passive", action="store_true", help="Do not generate traffic; capture only what is already flowing")
    args = parser.parse_args()

    live_network_capture(
        interface=args.interface,
        duration_seconds=args.duration,
        output_path=args.output,
        target_url=None if args.passive else args.target_url
    )
