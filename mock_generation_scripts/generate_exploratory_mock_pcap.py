import time
import socket
import random
from scapy.all import IP, TCP, wrpcap

def create_random_exploratory_pcap(filename="mock_data/mock_exploratory_data.pcap", total_packets=50):
    print(f"[*] Simulating live organic network conditions into: {filename}")

    # 1. Target & Source IP Resolution
    target_domains = ["google.com", "github.com", "aws.amazon.com", "cloudflare.com"]
    selected_domain = random.choice(target_domains)
    try:
        TARGET_IP = socket.gethostbyname(selected_domain)
    except Exception:
        TARGET_IP = f"142.250.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    SRC_IP = f"192.168.1.{random.randint(2, 254)}"
    SRC_PORT = random.randint(49152, 65535)
    DST_PORT = random.choice([443, 80])
    
    packets = []
    base_time = time.time()
    current_seq = random.randint(100000, 900000)
    current_timestamp = base_time
    
    retrans_count = 0
    ooo_count = 0
    jitter_spikes = 0

    # 2. Process Packet Stream with Random Volatility Rates
    for i in range(1, total_packets + 1):
        # Generate the standard packet
        pkt = IP(src=SRC_IP, dst=TARGET_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, seq=current_seq, flags="A")
        
        # Calculate base timeline progress (Standard 10ms–30ms wire latency)
        arrival_delay = random.uniform(0.010, 0.030)
        
        # --- ANOMALY 1: ORGANIC JITTER SPIKE (4% chance) ---
        if random.random() < 0.04:
            arrival_delay += random.uniform(0.200, 0.500)  # Sudden 200-500ms lag spike
            jitter_spikes += 1
            
        current_timestamp += arrival_delay
        pkt.time = current_timestamp
        
        # --- ANOMALY 2: PACKET RETRANSMISSION DROP (6% chance) ---
        if random.random() < 0.06 and len(packets) > 0:
            # The current packet goes through, but we inject a duplicate of the *previous* one
            # to simulate a retransmission request from a dropped ACK
            packets.append(pkt)
            
            duplicate_pkt = pkt.copy()
            current_timestamp += 0.004  # Arrives slightly later
            duplicate_pkt.time = current_timestamp
            packets.append(duplicate_pkt)
            
            retrans_count += 1
            current_seq += random.choice([64, 128, 512, 1024])
            continue

        # --- ANOMALY 3: OUT-OF-ORDER ARRIVAL (3% chance) ---
        if random.random() < 0.03 and len(packets) > 1:
            # Swap the time stamps of this packet and the previous one so they arrive inverted
            prev_pkt = packets[-1]
            pkt.time, prev_pkt.time = prev_pkt.time, pkt.time
            ooo_count += 1

        # Append standard packet to array
        packets.append(pkt)
        current_seq += random.choice([64, 128, 512, 1024])

    # 3. Append matching FIN/ACK handshake for clean close
    fin_pkt = IP(src=TARGET_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, seq=current_seq + 1, flags="FA")
    fin_pkt.time = current_timestamp + 0.05
    packets.append(fin_pkt)

    # Write out the final binary PCAP
    wrpcap(filename, packets)
    
    # Calculate exact metric telemetry percentages
    actual_retrans_rate = (retrans_count / len(packets)) * 100
    
    print("--------------------------------------------------")
    print(f"[+] Success! Generated {len(packets)} total packets.")
    print(f"[+] Anomaly Metrics Intercepted:")
    print(f"    - Retransmissions : {retrans_count} ({actual_retrans_rate:.2f}%)")
    print(f"    - Out-of-Order    : {ooo_count} occurrences")
    print(f"    - Jitter Spikes   : {jitter_spikes} routing delays")
    print(f"[+] Final Trace Asset Exported: {filename}")
    print("--------------------------------------------------")

if __name__ == "__main__":
    # Randomize total volume between 50 and 200 packets
    random_packet_count = random.randint(50, 200)
    
    create_random_exploratory_pcap(
        filename="mock_data/mock_exploratory_data.pcap", 
        total_packets=random_packet_count
    )
