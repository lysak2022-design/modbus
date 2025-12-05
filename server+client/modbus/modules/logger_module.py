# modules/logger_module.py
import threading
import time

class Logger:
    def __init__(self, filename="modbus_log.txt"):
        self.filename = filename
        self.lock = threading.Lock()

    def log(self, message: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{timestamp}] {message}\n"
        with self.lock:
            with open(self.filename, "a") as f:
                f.write(line)

    def read_logs(self, last_n=100):
        with self.lock:
            try:
                with open(self.filename, "r") as f:
                    lines = f.readlines()
                return lines[-last_n:]
            except FileNotFoundError:
                return []
