from tcp_session import TcpSession

def create_large_mock_pcap(filename="mock_data/mock_stress_data.pcap", total_segments=100, retrans_rate_target=10.0):
    print(f"[*] Generating large deterministic STRESS mode PCAP: {filename}")

    session = TcpSession()
    session.handshake()

    # Calculate the segment interval to hit the target retransmission rate
    # e.g., For 10%, we retransmit 1 out of every 10 data segments
    retransmit_interval = int(100 / retrans_rate_target)
    retrans_generated = 0

    for i in range(1, total_segments + 1):
        # 1. Send the next data segment at a stable 10ms cadence
        segment = session.segment(100)
        session.send(segment, gap=0.01)

        # 2. Resend the same segment after a 50ms simulated retransmission timeout.
        #    Well above the analyzer's 5ms capture-duplicate filter.
        if i % retransmit_interval == 0:
            session.send(segment, gap=0.05)
            retrans_generated += 1

        if i % 2 == 0:
            session.server_ack()

    # 3. Graceful teardown to satisfy the clean-close assertion
    session.close()

    path = session.write(filename)
    print(f"[+] Done! Generated {len(session.packets)} total packets -> {path}")
    print(f"[+] Data Segments: {total_segments} originals + {retrans_generated} retransmissions")

if __name__ == "__main__":
    # Generate a mock pcap with 100 data segments and a ~10% retransmission rate
    create_large_mock_pcap(total_segments=100, retrans_rate_target=10.0)
