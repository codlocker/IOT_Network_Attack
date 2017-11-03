import os
import pyshark as pys
from RPL_Attack.PCAPManager import PCAPManager as pcapm
from RPL_Attack.AttackDetector import VersionAttackDetector as VAD

LOGS_FOLDER = "logs/"
title = "PCAP PARSER"


def write_to_file(file_name, data):
    file = open("logs/" + file_name, mode="w")
    for d in data:
        str_val = ""
        d_len = len(d)
        for v in range(0, d_len - 1):
            str_val += (str(d[v]) + ",")
        str_val += str(d[d_len - 1])
        file.write(str_val + "\n")
    file.close()


def get_pcap_files():
    list_radio_files = [f for f in os.listdir("./..") if f.startswith('radiolog') and f.endswith('.pcap')]
    return list_radio_files


def get_version_and_rank(packets):
    # print(dir(packets[487][3]))
    ranks_set = set()
    version_set = []
    for packet in packets:
        epoch_ts = packet.sniff_timestamp
        source_ip = packet[2].Src
        list_dirs = list(dir(packet[3]))
        rank, version_number = -1, -1
        if 'rpl_dio_dagid' in list_dirs:
            rank, version_number = packet[3].rpl_dio_rank, packet[3].rpl_dio_version

        if rank != -1 or version_number != -1:
            ranks_set.add((source_ip, rank))
            version_set.append((epoch_ts, version_number))
    return ranks_set, version_set


def send_message(tit, message):
    sentence = 'notify-send "{}" "{}"'.format(tit, message)
    os.system(sentence)
    return


def get_packet_data_and_headers(packets):
    data = []
    for packet in packets:
        epoch_ts = packet.sniff_timestamp
        list_dirs = dir(packet)
        src_ip = packet[2].host
        dest_ip = packet[2].dst_host
        if 'data' in list_dirs:
            data_val = str(packet[4].data)
        else:
            data_val = 'No Data in this packet'
        each_data = [epoch_ts, src_ip, dest_ip, data_val]
        data.append(each_data)
    return data


def collect_no_of_packets_for_each_node(data):
    count_of_src_packets = dict()
    for d in data:
        if d[1] in count_of_src_packets:
            count_of_src_packets[d[1]] += 1
        else:
            count_of_src_packets[d[1]] = 1
    for key in count_of_src_packets.keys():
        print(count_of_src_packets[key])
    list_of_count = [["Source Node", "No. of packets"]]
    list_of_data = [[k, v] for k, v in count_of_src_packets.items()]

    return list_of_count + list_of_data

if __name__ == "__main__":
    radioFiles = get_pcap_files()
    print(radioFiles)
    file_id = int(input("Enter the id of the pcap value to parse:"))
    filename = "./../" + radioFiles[file_id - 1]
    print("Enter the Fiter Value")
    filter_value = input().lower()
    data_of_packets = []
    set_of_ranks = []
    set_of_VNs = []
    packets_data = None
    if filter_value == "udp":
        packets_data = pys.FileCapture(filename, display_filter=filter_value)
        data_of_packets = get_packet_data_and_headers(packets_data)
        write_to_file("packets_data.csv", data_of_packets)
        s = collect_no_of_packets_for_each_node(data_of_packets)
        write_to_file("packets_summary.csv", s)
        send_message(title, "Pcap Parsing Process and Writing has Completed")
    elif filter_value == "icmpv6":
        packets_data = pys.FileCapture(filename, display_filter=filter_value)
        set_of_ranks, set_of_VNs = get_version_and_rank(packets_data)
        write_to_file("version.csv", set_of_VNs)
        write_to_file("rank.csv", set_of_ranks)
        send_message(title, "Pcap Parsing Process and Writing has Completed")
        vad_obj = VAD(LOGS_FOLDER + "version.csv")
        req_res = vad_obj.parse_file
        print("The Version Number changed {} times over a period of {} seconds".format(req_res[0], req_res[1]))
    elif filter_value == "auto":
        manager = pcapm(filename)
        manager.parse_pcap("icmpv6")
