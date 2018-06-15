class Switch:
    def __init__(self):
        self.id = None
        self.flow_table = None

    def process_packet(self, raw_packet):
        return

class FlowTable:
    def __init__(self):
        self.table = {}

    def create_flow(self, flow):
        return

    def delete_flow(self, id):
        return

    def check_timeout(self):
        """
        Iterate through the table and check for timeout
        """
        return

    def if_flow_exists(self, id):
        return


class Flow:
    def __init__(self):
        self.id = None
        self.src_ip = None
        self.dst_ip = None
        self.type = None
        self.src_port = None
        self.dst_port = None
        self.first_seen = None
        self.packet_time = None
        self.last_update = None

