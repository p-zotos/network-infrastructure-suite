import argparse
import json
import random
from tcp_session import TcpSession, PROJECT_ROOT

def create_random_exploratory_pcap(filename="mock_data/mock_exploratory_data.pcap", total_segments=50, seed=None):
    """
    Fuzzes a TCP session with randomized anomalies and writes a ground-truth manifest
    next to the PCAP, so the analyzer's findings can be verified exactly.
    """
    seed = seed if seed is not None else random.randrange(2**32)
    rng = random.Random(seed)
    print(f"[*] Simulating organic network conditions into: {filename} (seed={seed})")

    # 1. Randomized socket identities (RFC 1918 client, RFC 5737 server: no DNS needed)
    session = TcpSession(
        client=(f"10.0.0.{rng.randint(2, 254)}", rng.randint(49152, 65535)),
        server=(f"198.51.100.{rng.randint(2, 254)}", rng.choice([443, 80])),
        client_isn=rng.randint(100000, 900000),
    )
    session.handshake()

    segments = [session.segment(rng.choice([64, 128, 512, 1024])) for _ in range(total_segments)]
    emitted = []
    retrans_count = 0
    ooo_count = 0
    jitter_spikes = 0

    def wire_gap():
        """Standard 10ms–30ms wire latency, with a 4% chance of a 200–500ms jitter spike."""
        nonlocal jitter_spikes
        gap = rng.uniform(0.010, 0.030)
        if rng.random() < 0.04:
            gap += rng.uniform(0.200, 0.500)
            jitter_spikes += 1
        return gap

    # 2. Process segment stream with random volatility rates
    i = 0
    while i < len(segments):
        # --- ANOMALY 1: OUT-OF-ORDER ARRIVAL (3% chance) ---
        # The next segment overtakes the current one on the wire
        if rng.random() < 0.03 and i + 1 < len(segments):
            batch = [segments[i + 1], segments[i]]
            ooo_count += 1
            i += 2
        else:
            batch = [segments[i]]
            i += 1

        for segment in batch:
            emitted.append(session.send(segment, gap=wire_gap()))

        # --- ANOMALY 2: FAST RETRANSMISSION (6% chance) ---
        # Resend the segment sent three positions back, as after three duplicate ACKs
        if rng.random() < 0.06 and len(emitted) >= 3:
            session.send(emitted[-3], gap=wire_gap())
            retrans_count += 1

        if rng.random() < 0.5:
            session.server_ack()

    # 3. Graceful FIN/ACK teardown for clean close
    session.close()
    path = session.write(filename)

    ground_truth = {
        "seed": seed,
        "data_segments": total_segments,
        "retransmissions": retrans_count,
        "out_of_order": ooo_count,
        "jitter_spikes": jitter_spikes,
    }
    truth_path = path.with_suffix(".truth.json")
    truth_path.write_text(json.dumps(ground_truth, indent=4))

    print("--------------------------------------------------")
    print(f"[+] Success! Generated {len(session.packets)} total packets.")
    print(f"[+] Anomalies Injected (seed={seed}):")
    print(f"    - Retransmissions : {retrans_count}")
    print(f"    - Out-of-Order    : {ooo_count} occurrences")
    print(f"    - Jitter Spikes   : {jitter_spikes} routing delays")
    print(f"[+] Final Trace Asset Exported: {path}")
    print(f"[+] Ground Truth Manifest     : {truth_path.relative_to(PROJECT_ROOT)}")
    print("--------------------------------------------------")
    return ground_truth

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a randomized (fuzzed) TCP capture.")
    parser.add_argument("--seed", type=int, help="Replay a previous run by reusing its seed")
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(2**32)
    create_random_exploratory_pcap(
        filename="mock_data/mock_exploratory_data.pcap",
        # Randomize total volume between 50 and 200 data segments
        total_segments=random.Random(seed).randint(50, 200),
        seed=seed,
    )
