class VersionAttackDetector:
    filename = ""
    parsedVNs = dict()
    elements_in_dict = 0
    list_of_keys = []

    def __init__(self, file):
        self.filename = file

    @property
    def parse_file(self):
        version_txt = open(self.filename, mode="r")
        for line in version_txt:
            res = line.split(",")
            self.parsedVNs[res[0]] = int(res[1])
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
        print("Version Number has a STD of " + str(std_vn) + " in a time range of " + str(time_range))
        return count, time_range
