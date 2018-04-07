import os
import json
import pandas as pd
from sklearn import tree


class VersionAttackDetector:
    filename = ""
    parsedVNs = dict()
    elements_in_dict = 0
    list_of_keys = []

    def __init__(self, file):
        self.filename = file
        self.attacker_nodes = []

    def get_attacker_node(self):
        """

        :rtype: dict
        """
        version_txt = open(self.filename, mode="r")
        possible_attack_nodes = dict()
        # Get the initial Version Number as in the file
        init_version = int(version_txt.readline().split(",")[2])
        print("The initial Version is", init_version)
        for line in version_txt:
            res = line.split(",")
            if init_version == int(res[2]):  # Check only for First Occurence
                if res[1] in possible_attack_nodes.keys():
                    possible_attack_nodes[res[1]] += 1
                else:
                    possible_attack_nodes[res[1]] = 1
                init_version = (init_version + 1) % 257
        return possible_attack_nodes

    @staticmethod
    def print_error_probabilities(v_dict):
        """

        :rtype: None
        """
        sum_all = sum(list(v_dict.values()))
        for key in v_dict.keys():
            val = v_dict[key] / sum_all
            print("Probability: {} is {}".format(key, val))

    @property
    def parse_file(self):
        version_txt = open(self.filename, mode="r")
        for line in version_txt:
            res = line.split(",")
            self.parsedVNs[res[0]] = int(res[2])
        self.elements_in_dict = len(self.parsedVNs)
        self.list_of_keys = list(self.parsedVNs.keys())
        avg_vn = sum(self.parsedVNs.values()) / len(self.parsedVNs)
        std_vn, count = 0, 0
        prev_vn = avg_vn
        for d in self.parsedVNs.values():
            if prev_vn != d:
                count += 1
            std_vn += pow(abs(d - avg_vn), 2)
            prev_vn = d
        min_time = min(self.list_of_keys)
        max_time = max(self.list_of_keys)
        time_range = abs(float(max_time) - float(min_time))
        print("Version Number has a Variance of " + str(std_vn ** 0.5) + " in a time range of " + str(time_range))
        # Possible Value of the Attacker Node
        possible_attackers = VersionAttackDetector.get_attacker_node(self)
        for att in possible_attackers:
            new_node = dict()
            new_node['ip'] = att
            new_node['freq_changes'] = possible_attackers.get(att)
            self.attacker_nodes.append(new_node)
        if possible_attackers[max(possible_attackers)] > 1:
            VersionAttackDetector.print_error_probabilities(possible_attackers)
            print('The possible Attacker node in this set is ', max(possible_attackers))
        return count, time_range


class VersionAttackFeatureDetails:

    def __init__(self):
        self.ds_folder = "./../Datasets/training/"
        self.files = [file for file in os.listdir(self.ds_folder) if file.endswith(".txt")]
        self.features = ["Timestamp", "K(pack_len)", "Clock", "Clock", "timesynch_time", "link_Address of originator",
                         "Seqno", "hops", "0", "Unknown", "Unknown", "0", "cpu_power", "lpm_power", "transmit_power",
                         "listen_power", "parent_address", "parent_etx",
                         "current_route_metric (actual rt_metric divided by 2)", "num_neighbours", "beacon_interval",
                         "battery_voltage_sensor", "batteryIndictor", "light1_sensor", "light2_sensor", "temp_sensor",
                         "humidity_sensor", "etx1_sensor", "etx2_sensor", "etx3_sensor", "etx4_sensor"]
        self.feature_set = []

    def organize_data(self, make_csv=True):
        for dataset_file in self.files:
            with open(self.ds_folder + dataset_file) as f:
                print(self.ds_folder + dataset_file)
                data = f.readlines()
                all_data = self.get_required_data_from_txt(data, make_csv)
            if make_csv:
                csv_format = []  # Format for making CSV File is made here
                for d in all_data:
                    csv_format.append(",".join(d) + "\n")
                print("Creating Training DataSet")
                csv_file_name = dataset_file.split(".")[0] + ".csv"
                with open(self.ds_folder + csv_file_name, "w") as csv_fl:
                    csv_fl.writelines(csv_format)
                print("No. of lines in data", len(all_data))
            else:
                sorted_result = self.sort_data(all_data[1:], dataset_file)
                print(sorted_result)
                print("Completed Analysis....")
                with open(self.ds_folder + "dataset.json", mode='w') as f:
                    final_data = json.dumps({"features": self.feature_set})
                    f.write(final_data)

    def sort_data(self, data, file_origin):
        id_sorted_data = sorted(data, key=lambda x: x[1])
        all_ids = sorted(set(row[1] for row in id_sorted_data))
        for id_i in all_ids:
            data_dict = self.get_verdict_res(id_sorted_data, id_i)
            data_dict["origin_file"] = file_origin
            if data_dict["affected"] > 0.6:
                data_dict["verdict"] = 1
            else:
                data_dict["verdict"] = 0
            self.feature_set.append(data_dict)
            # print(curr_data)
        print("##################################################")
        return id_sorted_data

    def steep_rise_r_fall_check(self, data, beacon=False, rm=False):
        min_value, min_index = min(data), list(data).index(min(data))
        attacked = False
        try:
            max_value = max(list(data[min_index + 1: len(data)]))
            if beacon:
                if data[-1] < 150:
                    attacked = True
            else:
                if rm:
                    attacked = [True if float(max_value) / float(min_value) > 1.1 else False][0]
                else:
                    attacked = [True if float(max_value) / float(min_value) >= 3 else False][0]
        except ValueError as ve:
            max_value = data[-1]
            attacked = False
        return attacked, min_value, max_value

    def get_required_data_from_txt(self, data, make_csv=False):
        all_data = [["Timestamp", "ID", "Beacon Interval", "Current Routing Metric", "Power"]]
        for d in data:
            req_params = []
            parameters = d.split(" ")
            if make_csv:
                req_params.insert(len(req_params), parameters[0])
                req_params.insert(len(req_params), parameters[5])
                req_params.insert(len(req_params), parameters[20])
                req_params.insert(len(req_params), parameters[18])
                tot_power = float(int(parameters[14]) + int(parameters[15])) / 1000.0
                req_params.insert(len(req_params), str(tot_power))
            else:
                req_params.insert(len(req_params), int(parameters[0]))
                req_params.insert(len(req_params), int(parameters[5]))
                req_params.insert(len(req_params), int(parameters[20]))
                req_params.insert(len(req_params), int(parameters[18]))
                tot_power = float(int(parameters[14]) + int(parameters[15])) / 1000.0
                req_params.insert(len(req_params), tot_power)
            # all_data.append(",".join(req_params) + "\n")
            all_data.insert(len(all_data), req_params)
        return all_data

    def get_verdict_res(self, data, node_id):
        curr_data = [d for d in data if d[1] == node_id]
        curr_data.sort(key=lambda x: x[0])  # Sort by time
        beacon_data = self.steep_rise_r_fall_check([d[2] for d in curr_data], True, False)
        routing_metric_data = self.steep_rise_r_fall_check([d[3] for d in curr_data], False, True)
        power_data = self.steep_rise_r_fall_check([d[4] for d in curr_data], False, False)
        data_dict = {"id": self.feature_set[-1]["id"] + 1 if len(self.feature_set) > 0 else 1,
                     "beacon_interval": 1 if beacon_data[0] else 0,
                     "routing metric": 1 if routing_metric_data[0] else 0,
                     "power": 1 if power_data[0] else 0,
                     "statistics": {"beacon_interval":
                                        {"max": beacon_data[2], "min": beacon_data[1]},
                                    "power":
                                        {"max": power_data[2], "min": power_data[1]},
                                    "routing metric":
                                        {"max": routing_metric_data[2], "min": routing_metric_data[1]},
                                    },
                     "affected": float(int(beacon_data[0]) + int(routing_metric_data[0]) + int(power_data[0])) / 3.0}
        return data_dict


class LearningAlgos:

    def __init__(self, fold):
        self.training_data = fold
        self.data = None

    def create_dataframe(self):
        with open(self.training_data, mode='r') as f:
            data = f.read()
        json_form = json.loads(data)
        self.data = pd.DataFrame.from_dict(json_form["features"])

    def perform_decision_tree_classification(self, predict_data):
        clf = tree.DecisionTreeClassifier()
        df_for_tree = self.data.copy()
        y = df_for_tree.affected * 3
        x = df_for_tree.drop(['affected', 'id', 'verdict', 'origin_file', 'statistics'], axis=1)
        x = x.values.tolist()
        y = y.values.tolist()
        clf.fit(x, y)
        return clf.predict([[predict_data['beacon_interval'], predict_data['power'], predict_data['routing metric']]])
