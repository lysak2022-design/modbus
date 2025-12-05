import time
from collections import deque
from threading import Lock


class ServerDataBroker:
    def __init__(self, history_seconds=300):
        self.history_seconds = history_seconds
        self.packet_history = deque(maxlen=history_seconds * 2)  # 2 точки в секунду
        self.lock = Lock()
        self.last_packets_per_sec = 0

    def update_packets(self, packets_per_sec: int):
        with self.lock:
            self.last_packets_per_sec = packets_per_sec
            self.packet_history.append((time.time(), packets_per_sec))

    def get_packets_history(self):
        with self.lock:
            return list(self.packet_history)

    def get_last_value(self):
        with self.lock:
            return self.last_packets_per_sec
