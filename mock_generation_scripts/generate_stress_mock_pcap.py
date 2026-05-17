import time
from scapy.all import IP, TCP, wrpcap

def create_large_mock_pcap(filename="mock_data/mock_stress_data.pcap", total_normal_packets=100, retrans_rate_target=10.0):
    print(f"[*] Generating large deterministic mock PCAP: {filename}")
    
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
    
    # Calculate the packet interval to hit the target retransmission rate
    # e.g., For 10%, we inject 1 retransmission every 10 normal packets
    retransmit_interval = int(100 / retrans_rate_target)
    
    retrans_generated = 0
    
    for i in range(1, total_normal_packets + 1):
        # 1. Create a normal TCP packet
        pkt = IP(src=SRC_IP, dst=TARGET_IP) / TCP(sport=54321, dport=443, seq=current_seq, flags="A")
        pkt.time = base_time + (i * 0.01) # Stable 10ms intervals
        packets.append(pkt)
        
        # 2. Inject an intentional Retransmission based on the calculated interval
        if i % retransmit_interval == 0:
            retransmit_pkt = IP(src=SRC_IP, dst=TARGET_IP) / TCP(sport=54321, dport=443, seq=current_seq, flags="A")
            # +50ms delay to bypass the 15ms TSO mitigation filter in analyzer.py
            retransmit_pkt.time = pkt.time + 0.050 
            packets.append(retransmit_pkt)
            retrans_generated += 1
            
        current_seq += 100 # Increment Sequence Number

    # 3. Append a FIN packet at the end to satisfy the Connection Integrity Assertion (Assertion B)
    fin_pkt = IP(src=TARGET_IP, dst=SRC_IP) / TCP(sport=443, dport=54321, seq=99999, flags="FA")
    fin_pkt.time = base_time + (total_normal_packets * 0.01) + 0.1
    packets.append(fin_pkt)

    # Write the forged packet list to a real binary PCAP file
    wrpcap(filename, packets)
    
    # Total Captured TCP Packets = Normal + Retransmissions + FIN
    total_captured = len(packets)
    actual_rate = (retrans_generated / total_captured) * 100
    
    print(f"[+] Done! Generated {total_captured} total packets.")
    print(f"[+] Normal Packets: {total_normal_packets}")
    # Note: actual_rate is calculated against the total packet count in the capture file
    print(f"[+] Retransmissions Injected: {retrans_generated} ({actual_rate:.2f}% of total capture)")

if __name__ == "__main__":
    # Generate a mock pcap with 100 normal packets and ~10% retransmission rate
    create_large_mock_pcap(total_normal_packets=100, retrans_rate_target=10.0)
