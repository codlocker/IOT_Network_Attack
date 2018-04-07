import pyshark as pys
import os
import time


class PCAPManager:
    rpl_control_msg_data = ""
    rcm_list, dio_msg_list, first_row = [], [], []
    rcm_file = ""
    dio_msg_file, LOGS_FOLDER = "", ""

    def __init__(self, file, logs):
        self.rpl_control_msg_data = file
        self.file_uid = self.rpl_control_msg_data.split(".")[0]
        self.rcm_file = "RPL_DIS_Messages.csv"
        self.dio_msg_file = "RPL_DIO_Messages.csv"
        self.LOGS_FOLDER = logs

    @staticmethod
    def write_to_file(file_name, data, first_row=None):
        if os.path.isfile(file_name):
            file = open(file_name, mode="a")
        else:
            file = open(file_name, mode="w")
            str_val = ""
            for v in range(0, len(first_row) - 1):
                str_val += (str(first_row[v]) + ",")
            str_val += str(first_row[len(first_row) - 1])
            file.write(str_val + "\n")
        for d in data:
            str_val = ""
            d_len = len(d)
            for v in range(0, d_len - 1):
                str_val += (str(d[v]) + ",")
            str_val += str(d[d_len - 1])
            file.write(str_val + "\n")
        file.close()

    def rpl_dio_data(self, packet, each_row):
        packet_message = packet[3]._ws_expert
        checksum = packet[3].checksum
        checksum_status = packet[3].checksum_status
        code = packet[3].code
        rsrvd = packet[3].reserved
        rpl_dag_id = packet[3].rpl_dio_dagid
        dstn_ad_trig_seq = packet[3].rpl_dio_dtsn
        dio_flags = packet[3].rpl_dio_flag
        dio_instance = packet[3].rpl_dio_instance
        dio_rank = packet[3].rpl_dio_rank
        dio_version = packet[3].rpl_dio_version
        dio_interval_doublings = packet[3].rpl_opt_config_interval_double
        dio_interval_min = packet[3].rpl_opt_config_interval_min
        dio_max_rank = packet[3].rpl_opt_config_max_rank_inc
        dio_max_hop_rank = packet[3].rpl_opt_config_min_hop_rank_inc
        rpl_option_length = packet[3].rpl_opt_length
        each_row += [rpl_dag_id, dstn_ad_trig_seq, dio_flags, dio_instance, dio_rank, dio_version,
                     dio_interval_doublings, dio_interval_min, dio_max_rank, dio_max_hop_rank,
                     rpl_option_length, checksum, checksum_status, code, rsrvd, packet_message]
        return each_row

    def rpl_dis_data(self, packet, each_row):
        checksum = packet[3].checksum
        checksum_status = packet[3].checksum_status
        reserved = packet[3].reserved
        flags = packet[3].rpl_dis_flags
        type = packet[3].type
        each_row += [checksum, checksum_status, reserved, flags, type]
        return each_row

    def store_rpl_packet_data(self, packets_data, count):
        # Parsing the IEEE and Frame Part
        each_row = []
        sequence_number = -1
        try:
            sequence_number = packets_data[0].seq_no
            extd_source = packets_data[0].src64
            destination_pan = packets_data[0].dst_pan
            destination = packets_data[0].dst16
            frame_length = packets_data[0].frame_length
            frame_control_field = packets_data[0].fcf
            frame_number = count
            each_row += [frame_number, frame_length, frame_control_field, sequence_number, extd_source, destination_pan,
                         destination]

            # Parsing the Next IPV6 Section
            ip_version = packets_data[2].ip_version
            layer_name = packets_data[2].layer_name
            ipv6_destination = packets_data[2].dst
            ipv6_source = packets_data[2].src
            hop_limit = packets_data[2].hlim
            next_header = packets_data[2].nxt
            each_row += [ip_version, layer_name, ipv6_destination, ipv6_source, hop_limit, next_header]
            # Parsing the Next ICMPV6 Section
            if int(packets_data[3].code) == 0:
                each_row = self.rpl_dis_data(packets_data, each_row)
                self.rcm_list.append(each_row)
            elif int(packets_data[3].code) == 1:
                each_row = self.rpl_dio_data(packets_data, each_row)
                self.dio_msg_list.append(each_row)
        except AttributeError as ae:
            print("Cant parse Malformed Packets SEQ_NO: " + str(count) + " " + str(ae))

    def parse_pcap(self, filter_value):
        packets_data = pys.FileCapture(self.rpl_control_msg_data, display_filter=filter_value)
        print("PCAP Parsing Started")
        count = 0
        t0 = time.time()
        for packet in packets_data:
            count += 1

            if int(packet[3].code) == 0:
                first_row = ["Frame Number", "Frame Length", "Frame Control Field", "Sequence Number",
                             "Extended Source", "Destination PAN", "Destination", "IP Version", "Layer Name",
                             "IP Destination", "IP Source", "Hop Limit", "Next Packet Header", "Checksum",
                             "Checksum Status", "Reserved", "Flags", "Packet Type"]
                self.store_rpl_packet_data(packet, count)
                # Write to File as CSV
                # print(self.rcm_list)
                if count % 200 == 0:
                    print(count)
                    self.write_to_file(self.LOGS_FOLDER + self.rcm_file, self.rcm_list, first_row)
                    self.rcm_list = []
            elif int(packet[3].code) == 1:
                first_row = ["Frame Number", "Frame Length", "Frame Control Field", "Sequence Number",
                             "Extended Source", "Destination PAN", "Destination", "IP Version", "Layer Name",
                             "IP Destination", "IP Source", "Hop Limit", "Next Packet Header", "RPL DAG ID",
                             "Destination Advertisement Trigger Sequence",
                             "DIO FLags", "DIO Instance", "DIO Rank", "DIO Version", "DIO Interval Doublings",
                             "DIO Minimum Interval", "DIO Max Rank",
                             "DIO Max Hop Rank", "ICMPV6 Option Length", "Checksum", "Checksum Status", "Code",
                             "Reserved",
                             "Packet Message"]
                self.store_rpl_packet_data(packet, count)
                # Write to File as CSV
                # print(self.rcm_list)
                if count % 200 == 0:
                    print(count)
                    self.write_to_file(self.LOGS_FOLDER + self.dio_msg_file, self.dio_msg_list, first_row)
                    self.dio_msg_list = []
        print("PCAP Parsing Ended in {0} secs for {1} data points".format(time.time() - t0, count))
