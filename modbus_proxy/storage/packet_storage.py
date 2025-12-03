# storage/packet_storage.py
from typing import List
from modbus_proxy.storage.log_storage import LogStorage

class PacketStorage:
    def __init__(self):
        self.packets: List[object] = []

    def add(self, pkt):
        self.packets.append(pkt)

    def get_last(self, n=200):
        return self.packets[-n:]

    def clear(self):
        self.packets = []
