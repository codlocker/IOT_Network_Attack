class VersionAttackDetector:
    filename = ""
    parsedVNs = dict()
    elements_in_dict = 0
    list_of_keys = []

    def __init__(self, file):
        self.filename = file

    def get_attacker_node(self):
        version_txt = open(self.filename, mode="r")
        possible_attack_nodes = dict()
        # TODO: Currently Hardcoded to Default Value of CONTIKI. Need to work around it
        init_version = 240
        for line in version_txt:
            res = line.split(",")
            if init_version == int(res[2]): # Check only for First Occurence
                if res[1] in possible_attack_nodes.keys():
                    possible_attack_nodes[res[1]] += 1
                else:
                    possible_attack_nodes[res[1]] = 1
                init_version = (init_version + 1) % 257
        return possible_attack_nodes

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
        print("The possible Attacker Nodes in this set is ", max(possible_attackers))
        return count, time_range
