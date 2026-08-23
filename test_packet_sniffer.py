import pytest
from scapy.all import IP, TCP, Raw
import time
from packet_sniffer import process_packets, is_oversized, is_syn_ack_packets, is_ack_packet, is_syn_packets, check_syn_flood, print_summary

@pytest.fixture
def stats():
    return {
        "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0},
        "oversized_packets": [],
        "syn_timestamps_by_ip": {},
    }

def test_process_packets(stats):
    pkt1 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="S")
    process_packets(pkt1,stats)
    assert stats["protocol_counts"]["TCP"] == 1
    pkt2 = IP(src="2.3.4.5", dst="6.7.8.9") / TCP(flags="SA")
    process_packets(pkt2, stats)
    assert stats["protocol_counts"]["TCP"] == 2
    pkt3 = IP(src="3.4.5.6", dst="4.5.6.7") / TCP(flags="A")
    process_packets(pkt3, stats)
    assert stats["protocol_counts"]["TCP"] == 3

def test_is_oversized(stats):
    small = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="S")
    assert is_oversized(small,1000) == False
    big = IP(src="54.26.31.46", dst="51.61.17.81") / TCP(flags="SA") / Raw(load=b"A" * 2000)
    assert is_oversized(big, 500) == True

def test_is_syn_packet():
    pkt1 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="S")
    assert is_syn_packets(pkt1) == True
    pkt2 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="")
    assert is_syn_packets(pkt2) == False


def test_is_syn_ack_pacekt():
    pkt1 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="A")
    assert is_syn_ack_packets(pkt1) == False
    pkt2 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="SA")
    assert is_syn_ack_packets(pkt2) == True
    pkt2 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="S")
    assert is_syn_ack_packets(pkt2) == False
    
def test_is_ack_pacekt():
    pkt1 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="A")
    assert is_ack_packet(pkt1) == True
    pkt2 = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="SA")
    assert is_ack_packet(pkt2) == False

def test_check_syn_flood_detects_flood(stats):
    now = time.time()
    stats["syn_timestamps_by_ip"]["1.2.3.4"] = [now, now, now, now, now]
    assert check_syn_flood(stats, "1.2.3.4", window_seconds=1, count_threshold=3) == True
    now = time.time()
    stats["syn_timestamps_by_ip"]["1.2.3.4"] = [now, now, now, now]
    assert check_syn_flood(stats, "1.2.3.4", window_seconds=2, count_threshold=5) == False

def test_print_summary(stats, capsys):
    stats["protocol_counts"]["TCP"] = 5
    stats["oversized_packets"] = [1, 2]  # just need *something* in the list, length is what matters
    print_summary(stats)
    captured = capsys.readouterr()
    assert "5 TCP packets" in captured.out