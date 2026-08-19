from scapy.all import sniff, IP, TCP, DATA
from datetime import datetime

def capture_live(interface, stats):
    capture = sniff(iface=interface, prn  =lambda pkt: process_packets(pkt, stats), timeout=10)
    

def process_packets(packet, stats):
    if is_oversized(packet, 1500) == True:    
        return False
    else:
        time = datetime.now()
        count = 0
        stats["syn_timestamps_by_ip"["time_stamp"]] = time
        for packet[IP].src in packet:
            if packet[IP].src == stats["syn_timestamps_by_ip"["ip"]]:
                count+=1
            if stats["syn_timestamps_by_ip"["time_stamps"]]-packet["syn_timestamps_by_ip"["time_stamps"]] < 0.0001 and count > 10:
                stats["syn_timestamps_by_ip"["ip"]] = packet["syn_timestamps_by_ip"["ip"]]
                print(f"suspecios connection from ip {packet["syn_timestamps_by_ip"["ip"]]}")

def is_oversized(packet, threshold):
    return len(packet)>threshold

def is_syn_packets(packets):
    if packets.haslayer(TCP):
        return packets[TCP].flags == "s"
    return False

def main():
    stats = {"protocol counts": {"TCP", "UDP", "ICP", "ARP"}, 
             "oversized_packets":[], 
             "syn_timestamps_by_ip":{"ip", "time_stamp"}}
    capture_live("enp0s3",stats)
    pass

if __name__ == "__main__":
    main()