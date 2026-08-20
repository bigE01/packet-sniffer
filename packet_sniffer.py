from scapy.all import sniff, IP, TCP, DATA, PcapReader, UDP, ICMP, ARP
import time

#done✅
def capture_live(interface, stats):
    capture = sniff(iface=interface, prn  =lambda pkt: process_packets(pkt, stats), timeout=10)

#read a list of packets saved on the secondary memory instead of reading real packets✅
def read_pcapfile():
    data = PcapReader("capture.pcap")
    return data

#count how many packets from the same ip fall into the same time window then compares it to count threshhold to validate if its a flood
#not done
def check_syn_flood(stats, src_ip, window_seconds, count_threshhold, packet):
    count = 0
    for pkt in stats:
        if pkt.haslayer(IP):
            if pkt[IP].src == src_ip:
                if time.time() - packet["syn_timestamps_by_ip"["time_stamp"]] < window_seconds:
                    count+=1
    if count >= count_threshhold:
            print(f"{IP} might be suspecios")
            return True
    return False
    
#done✅
def is_oversized(packet, threshold):
    return len(packet)>threshold

#doe✅
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
        return False
    
    if is_syn_packets(packet) == True:
        #current time for the time stamp gives time not including date
        time_stamp = time.time()
        #src ip of the current packet
        src_ip = packet[IP].src
        #checks if the ip exists in the dictionary
        if src_ip in stats["syn_time_stamps_by_ip"]:
            stats["syn_timestamps_by_ip"] = time_stamp
            stats["syn_timestamps_by_ip"].append(time_stamp)
            #checks for floding
            if check_syn_flood(stats, src_ip, 1, 100, packet):
                return
        else:
            stats["syn_timestamps_by_ip"][src_ip] = []
            stats["syn_timestamps_by_ip"][src_ip].append(time_stamp)
        return
    
#done✅
def print_summary(stats):
    stats.summary()

def main():
    stats = {"protocol_counts": {"TCP", "UDP", "ICP", "ARP"}, 
             "oversized_packets":[], 
             "syn_timestamps_by_ip":{}}
    #capture_live("enp0s3",stats)#good line
    print_summary(stats)

if __name__ == "__main__":
    main()