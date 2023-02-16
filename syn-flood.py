"""
This script is used to find suspicious addresses with attack of syn flood in a pcap file

The script is based on the following heuristics:
1. The attacker most send at more then the number we chose packets (8)
2. The attacker most send more then the number we chose syn packets (5)
3. The attacker most not send ack packets
4. We look in the src ip because the dst ip heuristics is not good enough (from what i saw)

author: Noam Shushan
"""

from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap
import os

SYN_ACK_FLAG = 18
ACK_FLAG = 16
RES_ACK_FLAG = 14
SYN_FLAG = 2

MAX_SYN_FLAG = 5
MIN_PCKS_TO_BE_SUSPICIOUS = 5


def find_suspicious_addresses():
    """
    :return: list of suspicious addresses
    """
    # read the pcap file
    packets = read_pcap_file()

    # group all TCP packets that send by src ip to a dict
    src_dict = group_packets(filter(lambda p: TCP in p, packets), 'src')

    # return all src ips that send a syn flood attack
    return [src for src in src_dict if is_syn_flood_attached(src_dict[src])]

    # i take the src heuristics because the dst heuristics is not good enough
    # but it is possible to take the dst heuristics by changing the 'src' to 'dst' and use the
    # is_get_syn_ack_but_not_answer function


def is_syn_flood_attached(packets_grouped_by_src):
    """
    check if the group of packets ure attached by the same src ip with syn flood attack
    :param packets_grouped_by_src: list of packets grouped by src ip
    :return: True if the packets that send by the same src ip are a syn flood attack
    """
    # the attacker most send at more then the number we chose packets
    if len(packets_grouped_by_src) < MIN_PCKS_TO_BE_SUSPICIOUS:
        return False

    # get the number of syn packets
    syn_count = len(list(filter(lambda p: p['flags'].value == SYN_FLAG, packets_grouped_by_src)))
    # get the number of ack packets
    ack_count = len(list(filter(lambda p: p['flags'].value == ACK_FLAG, packets_grouped_by_src)))

    # if the number of syn packets is bigger than the constant we have chose
    # and the number of ack packets is 0, we have a syn flood attack
    if syn_count > MAX_SYN_FLAG and ack_count == 0:
        return True

    return False


def is_get_syn_ack_but_not_answer(packets_grouped_by_dst, packets_grouped_by_src):
    """
    i don't use this function
    :param packets_grouped_by_dst: packets grouped by dst ip
    :param packets_grouped_by_src: packets grouped by src ip
    :return: True if the packets that send by the same dst ip are a syn flood attack
    """
    syn_ack_count = len(list(filter(lambda p: p['flags'].value == SYN_ACK_FLAG, packets_grouped_by_dst)))
    syn_count = len(list(filter(lambda p: p['flags'].value == SYN_FLAG, packets_grouped_by_src)))
    ack_count = len(list(filter(lambda p: p['flags'].value == ACK_FLAG, packets_grouped_by_src)))

    return syn_ack_count == syn_count and ack_count == 0


def group_packets(packets, src_or_dst):
    """
    group packets by src or dst ip
    for each packet we save only the ip and the flags to save memory and time
    :param packets: list of scapy packets
    :param src_or_dst: decide if we want to group by src ip or dst ip
    :return: a dictionary src or dst ip as key and list of packets as value
    """
    sorted_packets = []
    # sort packets by src or dst ip
    if src_or_dst == 'src':
        sorted_packets = sorted(packets, key=lambda p: p[IP].src)
    else:
        sorted_packets = sorted(packets, key=lambda p: p[IP].dst)

    result_dict = {}
    current_ip = sorted_packets[0][IP].src if src_or_dst == 'src' else sorted_packets[0][IP].dst
    packets_by_current = []
    for pck in sorted_packets:
        next_ip = pck[IP].src if src_or_dst == 'src' else pck[IP].dst
        if next_ip != current_ip:
            if len(packets_by_current) > 0:
                # set group of packets to the current src in the result dict
                result_dict[current_ip] = packets_by_current

            # reset
            current_ip = next_ip
            packets_by_current = []
        else:
            if src_or_dst == 'src':
                packets_by_current.append({'dst': pck[IP].dst, 'flags': pck[TCP].flags})
            else:
                packets_by_current.append({'src': pck[IP].src, 'flags': pck[TCP].flags})

    return result_dict


def read_pcap_file(pcap_file_name='SYNflood.pcap'):
    """
    Read the pcap file and return a list of packets
    :param pcap_file_name: sniffed pcap file
    :return: all packets in the pcap file
    """
    # check if the file exists
    if not os.path.exists(pcap_file_name):
        print("File does not exist")
        return
    # read the pcap file with scapy
    packets = rdpcap(pcap_file_name)
    return packets


if __name__ == '__main__':
    suspicious_addresses = find_suspicious_addresses()
    print(f'Count: {len(suspicious_addresses)}')
    print("\n".join(suspicious_addresses))

    # write all suspicious addresses to a txt file
    with open('suspicious_addresses.txt', 'w') as f:
        f.write("\n".join(suspicious_addresses))
