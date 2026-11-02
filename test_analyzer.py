"""Unit tests for the analyzer engine against hand-crafted captures with known ground truth."""
import pytest
from scapy.all import IP, IPv6, IPv6ExtHdrDestOpt, TCP, Raw, wrpcap
from analyzer import NetworkAnalyzer

CLIENT, SERVER = "10.0.0.50", "203.0.113.10"


def segment(t, seq, size=100, sport=54321, src=CLIENT, dst=SERVER, flags="PA"):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=443, seq=seq, flags=flags)
    if size:
        pkt = pkt / Raw(load=bytes(size))
    pkt.time = t
    return pkt


def pure_ack(t, seq=5000):
    return segment(t, seq, size=0, src=SERVER, dst=CLIENT, flags="A")


@pytest.fixture
def analyze(tmp_path):
    def _analyze(packets):
        pcap = tmp_path / "trace.pcap"
        wrpcap(str(pcap), packets)
        report = NetworkAnalyzer(pcap_path=pcap, results_dir=tmp_path).analyze_network_profile("unit")
        return report["network_metrics"] if report else None
    return _analyze


def test_pure_acks_repeating_seq_are_not_retransmissions(analyze):
    packets = [segment(0.00, 1000), pure_ack(0.10), pure_ack(0.20), pure_ack(0.30)]
    metrics = analyze(packets)
    assert metrics["total_retransmissions"] == 0
    assert metrics["data_segments"] == 1


def test_same_seq_on_different_ports_are_separate_flows(analyze):
    packets = [segment(0.00, 1000, sport=50000), segment(0.05, 1000, sport=50001)]
    metrics = analyze(packets)
    assert metrics["tcp_flows"] == 2
    assert metrics["total_retransmissions"] == 0


def test_resent_segment_is_a_retransmission(analyze):
    packets = [segment(0.00, 1000), segment(0.01, 1100), segment(0.21, 1000)]
    metrics = analyze(packets)
    assert metrics["total_retransmissions"] == 1
    assert metrics["retransmission_rate_percent"] == pytest.approx(33.33)
    assert metrics["out_of_order_segments"] == 0


def test_capture_duplicate_within_window_is_ignored(analyze):
    packets = [segment(0.000, 1000), segment(0.002, 1000)]
    metrics = analyze(packets)
    assert metrics["total_retransmissions"] == 0
    assert metrics["capture_duplicates_ignored"] == 1


def test_late_segment_is_out_of_order_not_retransmission(analyze):
    packets = [segment(0.00, 1000), segment(0.01, 1200), segment(0.02, 1100)]
    metrics = analyze(packets)
    assert metrics["out_of_order_segments"] == 1
    assert metrics["total_retransmissions"] == 0


def test_sequence_wraparound_is_in_order(analyze):
    packets = [segment(0.00, 2**32 - 100), segment(0.01, 0), segment(0.02, 100)]
    metrics = analyze(packets)
    assert metrics["out_of_order_segments"] == 0
    assert metrics["total_retransmissions"] == 0


def test_stable_cadence_has_zero_jitter_and_spike_is_measured(analyze):
    steady = analyze([segment(i * 0.01, 1000 + i * 100) for i in range(10)])
    assert steady["mean_jitter_ms"] == pytest.approx(0.0, abs=0.01)

    spiky = analyze([segment(0.00, 1000), segment(0.01, 1100), segment(0.32, 1200)])
    assert spiky["max_jitter_ms"] == pytest.approx(300.0, abs=0.01)


def test_ipv6_flows_with_extension_headers_are_analyzed(analyze):
    def v6(t, seq, size, flags="PA"):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrDestOpt() / TCP(sport=54321, dport=443, seq=seq, flags=flags)
        pkt = pkt / Raw(load=bytes(size)) if size else pkt
        pkt.time = t
        return pkt

    packets = [v6(0.00, 1000, 100), v6(0.05, 1100, 0, flags="A"), v6(0.10, 1100, 0, flags="A"), v6(0.30, 1000, 100)]
    metrics = analyze(packets)
    assert metrics["data_segments"] == 2
    assert metrics["total_retransmissions"] == 1


def test_capture_without_tcp_data_returns_none(analyze):
    assert analyze([pure_ack(0.0), pure_ack(0.1)]) is None
