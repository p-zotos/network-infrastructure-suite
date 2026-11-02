from tcp_session import TcpSession

def create_normal_mock_pcap(filename="mock_data/mock_normal_data.pcap", total_segments=50):
    print(f"[*] Generating deterministic NORMAL mode PCAP: {filename}")

    session = TcpSession()
    session.handshake()

    # 1. Stream pristine 100-byte data segments at a stable 10ms cadence (zero jitter)
    for i in range(1, total_segments + 1):
        session.send(session.segment(100), gap=0.01)
        # Delayed ACK: the server acknowledges every second segment with a pure ACK
        if i % 2 == 0:
            session.server_ack()

    # 2. Graceful FIN/ACK teardown to satisfy the clean-close assertion
    session.close()

    path = session.write(filename)
    print(f"[+] Success! Generated {len(session.packets)} total packets -> {path}")
    print(f"[+] Retransmissions Injected: 0 (0.00% Retransmit Rate)")

if __name__ == "__main__":
    # Generates a flawless capture profile with 50 sequential data segments and a clean teardown
    create_normal_mock_pcap()
