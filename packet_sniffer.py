from scapy.all import sniff, IP, TCP, PcapReader, UDP, ICMP, ARP
import time
import argparse

#done✅
def capture_live(interface, stats):
    capture = sniff(iface=interface, prn  =lambda pkt: process_packets(pkt, stats), timeout=10)

#read a list of packets saved on the secondary memory instead of reading real packets✅
def read_pcap_file(filepath, stats):
    try:
        for pkt in PcapReader(filepath):
            process_packets(pkt, stats)
    except FileNotFoundError:
        print("file does not exist")
        return False

#count how many packets from the same ip fall into the same time window then compares it to count threshhold to validate if its a flood
#not done
def check_syn_flood(stats, src_ip, window_seconds, count_threshold):
    count = 0
    for ts in stats["syn_timestamps_by_ip"][src_ip]:
        if time.time() - ts < window_seconds:
            count+=1
    if count >= count_threshold:
            print(f"{src_ip} might be suspecios")
            return True
    return False
    
#done✅
def is_oversized(packet, threshold):
    return len(packet)>threshold

#done✅
def is_syn_packets(packets):
    #checks if the packet has a tcp layer
    if packets.haslayer(TCP):
        #check if the tcp flack is S for syn packet which is the first packet sent from a client to create a connection
        return packets[TCP].flags == "S"
    return False

#doe✅
def is_syn_ack_packets(packets):
    if packets.haslayer(TCP):
        return packets[TCP].flags == "SA"
    return False

#doe✅
def is_ack_packet(packets):
    if packets.haslayer(TCP):
            return packets[TCP].flags == "A"
    return False

#doe✅
def process_packets(packet, stats):
    if (packet.haslayer(TCP)):
        stats["protocol_counts"]["TCP"] +=1
    elif (packet.haslayer(UDP)):
        stats["protocol_counts"]["UDP"] +=1
    elif (packet.haslayer(ICMP)):
        stats["protocol_counts"]["ICMP"] +=1
    elif (packet.haslayer(ARP)):
        stats["protocol_counts"]["ARP"] +=1
    if is_oversized(packet, 1500) == True: 
        print("packet is over size")  
        stats["oversized_packets"].append(packet)
    if is_syn_packets(packet) == True:
        #current time for the time stamp gives time not including date
        time_stamp = time.time()
        #src ip of the current packet
        src_ip = packet[IP].src
        #checks if the ip exists in the dictionary
        if src_ip in stats["syn_timestamps_by_ip"]:
            stats["syn_timestamps_by_ip"][src_ip].append(time_stamp)
        else:
            stats["syn_timestamps_by_ip"][src_ip] = []
            stats["syn_timestamps_by_ip"][src_ip].append(time_stamp)
        #checks for floding
        if check_syn_flood(stats, src_ip, 1, 100):
            print(f"flood detected from {src_ip}.")     
    
#done✅
def print_summary(stats):
    print(f"the are {stats['protocol_counts']['TCP']} TCP packets, {stats['protocol_counts']['UDP']} UDP packets, {stats['protocol_counts']['ICMP']} ICMP packets and {stats['protocol_counts']['ARP']} ARP packets. There were {len(stats['oversized_packets'])} over sized packets")

def main():
    stats = {"protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0}, 
             "oversized_packets":[], 
             "syn_timestamps_by_ip":{}}
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["live", "pcap"], required=True)
    parser.add_argument("--interface", default="enp0s3")
    parser.add_argument("--file", default="capture.pcap")
    args = parser.parse_args()
    if args.mode == "live":
        capture_live(args.interface, stats)
    elif args.mode == "pcap":
        read_pcap_file(args.file, stats)
    print_summary(stats)

if __name__ == "__main__":
    main()