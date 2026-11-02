import time
from pathlib import Path
from scapy.all import IP, TCP, Raw, wrpcap

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# RFC 1918 client and RFC 5737 (TEST-NET-3) server: deterministic, offline, never routable
CLIENT = ("10.0.0.50", 54321)
SERVER = ("203.0.113.10", 443)


class TcpSession:
    """
    Builds a realistic single-flow TCP conversation (handshake, client data with
    payloads, server pure ACKs, FIN teardown) on a controllable capture clock.
    """

    def __init__(self, client=CLIENT, server=SERVER, client_isn=1000, server_isn=5000, start_time=None):
        self.client_ip, self.client_port = client
        self.server_ip, self.server_port = server
        self.client_seq = client_isn
        self.server_seq = server_isn
        self.clock = start_time if start_time is not None else time.time()
        self.packets = []

    def _client_pkt(self, flags, seq, payload=b""):
        pkt = IP(src=self.client_ip, dst=self.server_ip) / TCP(
            sport=self.client_port, dport=self.server_port, seq=seq, ack=self.server_seq, flags=flags
        )
        return pkt / Raw(load=payload) if payload else pkt

    def _server_pkt(self, flags):
        return IP(src=self.server_ip, dst=self.client_ip) / TCP(
            sport=self.server_port, dport=self.client_port, seq=self.server_seq, ack=self.client_seq, flags=flags
        )

    def _emit(self, pkt, gap, advance=True):
        """Stamps a copy of the packet `gap` seconds after the clock and appends it to the capture."""
        pkt = pkt.copy()
        pkt.time = self.clock + gap
        if advance:
            self.clock += gap
        self.packets.append(pkt)
        return pkt

    def handshake(self, gap=0.01):
        self._emit(self._client_pkt("S", self.client_seq), gap)
        self.client_seq += 1  # SYN consumes one sequence number
        self._emit(self._server_pkt("SA"), gap)
        self.server_seq += 1
        self._emit(self._client_pkt("A", self.client_seq), gap)

    def segment(self, size):
        """Builds (without emitting) the next client data segment and advances the client sequence space."""
        pkt = self._client_pkt("PA", self.client_seq, payload=bytes(size))
        self.client_seq += size
        return pkt

    def send(self, pkt, gap):
        """Emits a segment on the wire; sending the same segment twice is a retransmission."""
        return self._emit(pkt, gap)

    def server_ack(self, delay=0.002):
        """Pure ACK from the server. It repeats the same seq number and must never count as a retransmission."""
        self._emit(self._server_pkt("A"), delay, advance=False)

    def close(self, gap=0.05):
        self._emit(self._client_pkt("FA", self.client_seq), gap)
        self.client_seq += 1
        self._emit(self._server_pkt("FA"), 0.01)
        self.server_seq += 1
        self._emit(self._client_pkt("A", self.client_seq), 0.01)

    def write(self, filename):
        path = PROJECT_ROOT / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), self.packets)
        return path
