import time
from scapy.all import IP, TCP, wrpcap

def create_normal_mock_pcap(filename="mock_data/mock_normal_data.pcap", total_packets=50):
    print(f"[*] Generating deterministic NORMAL mode PCAP: {filename}")
    
    # Dynamic IP Resolution to match the Analyzer's Traffic Isolation Filter
    try:
        TARGET_IP = socket.gethostbyname("google.com")
        print(f"[ * ] Resolved google.com to {TARGET_IP} for mock data.")
    except Exception:
        TARGET_IP = "172.217.16.142" # Fallback if offline
    
    SRC_IP = "192.168.1.50"
    
    packets = []
    base_time = time.time()
    current_seq = 1000
    
    # 1. Stream pristine TCP packets with sequential sequence numbers
    for i in range(1, total_packets + 1):
        pkt = IP(src=SRC_IP, dst=TARGET_IP) / TCP(sport=54321, dport=443, seq=current_seq, flags="A")
        # Incremental, stable timestamps (10ms gaps) simulating zero jitter/delay spikes
        pkt.time = base_time + (i * 0.01) 
        packets.append(pkt)
        
        current_seq += 100

    # 2. Append a realistic FIN/ACK handshake to satisfy Assertion B (Clean Close)
    fin_pkt = IP(src=TARGET_IP, dst=SRC_IP) / TCP(sport=443, dport=54321, seq=99999, flags="FA")
    fin_pkt.time = base_time + (total_packets * 0.01) + 0.1
    packets.append(fin_pkt)

    # Write the clean packet sequence to a binary PCAP file
    wrpcap(filename, packets)
    
    print(f"[+] Success! Generated {len(packets)} total packets.")
    print(f"[+] Retransmissions Injected: 0 (0.00% Retransmit Rate)")

if __name__ == "__main__":
    # Generates a flawless capture profile with 50 sequential packets and a clean teardown
    create_normal_mock_pcap()
