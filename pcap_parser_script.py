from PCAPManager import *
from AttackDetector import VersionAttackDetector, VersionAttackFeatureDetails, LearningAlgos

LOGS_FOLDER = "logs/"
title = "PCAP PARSER"


def write_to_file(file_name, data):
    file = open(LOGS_FOLDER + file_name, mode="w")
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
            version_set.append((epoch_ts, source_ip, version_number))
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


def collect_id_for_each_ip(ip_list, possible_attackers):
    print(ip_list)
    feature = VersionAttackFeatureDetails()
    get_learning_res = LearningAlgos("./../Datasets/training/dataset.json")
    get_learning_res.create_dataframe()
    with open("../Datasets/testing/dataset.txt", mode='r') as f:
        data = f.readlines()
        req_data = feature.get_required_data_from_txt(data)[1:]
        id_in_dataset = set(int(d[1]) for d in req_data)
    print(sorted(id_in_dataset))
    for i in range(0, len(possible_attackers)):
        node_no = input("Enter node no. for {}:\n".format(possible_attackers[i]["ip"]))
        possible_attackers[i]["node_in_view"] = node_no
        verdict_res = feature.get_verdict_res(req_data, int(node_no))
        decision_tree_result = get_learning_res.perform_decision_tree_classification(verdict_res)
        if int(decision_tree_result[0]) == 2:
            possible_attackers[i]["node_status"] = "Attacker"
        elif int(decision_tree_result[0]) == 3:
            possible_attackers[i]["node_status"] = "Affected"
        else:
            possible_attackers[i]["node_status"] = "Unaffected"
    return possible_attackers


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
    print("1. Check VN Frequency\n2. Generate Training Data")
    action = int(input())
    if action == 1:
        radioFiles = get_pcap_files()
        for index, val in enumerate(radioFiles):
            print(index + 1, val)
        file_id = int(input("Enter the id of the pcap value to parse:"))
        filename = "./../" + radioFiles[file_id - 1]
        file_uid = radioFiles[file_id - 1].split(".")[0]
        # Create a Directory for Reach RadioLog
        if not os.path.exists("logs/" + file_uid):
            os.makedirs("logs/" + file_uid)
        LOGS_FOLDER = "logs/" + file_uid + "/"
        print(LOGS_FOLDER)
        print("Enter the Filter Value")
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
            vad_obj = VersionAttackDetector(LOGS_FOLDER + "version.csv")
            req_res = vad_obj.parse_file
            print("The Version Number changed {} times over a period of {} seconds".format(req_res[0], req_res[1]))
            # Now Proving Which is attacker and which is not!!
            set_of_ips = sorted(set(d[1] for d in set_of_VNs))
            vad_obj.attacker_nodes = collect_id_for_each_ip(set_of_ips, vad_obj.attacker_nodes)
            print(vad_obj.attacker_nodes)
        elif filter_value == "auto":
            manager = PCAPManager(filename, LOGS_FOLDER)
            manager.parse_pcap("icmpv6")
    elif action == 2:
        obj = VersionAttackFeatureDetails()
        option = int(input("1. Create CSV for the dataset\n2. Perform Analysis\n"))
        if option == 2:
            obj.organize_data(False)
        else:
            obj.organize_data(True)
