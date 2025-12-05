import socket
import threading
import time
import random
import struct


class ModbusClientWorker:
    """
    Один клиент, который держит соединение с сервером и отправляет пакеты с заданной частотой (packets_per_second).
    """

    def __init__(self, host="127.0.0.1", port=15020, packets_per_second=10):
        self.host = host
        self.port = port
        self.packets_per_second = packets_per_second
        self.send_interval = 1.0 / packets_per_second
        self.running = False
        self.thread = None
        self.sent_packets = 0
        self.total_sent_packets = 0
        self.sock = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def update_rate(self, packets_per_second):
        self.packets_per_second = max(1, packets_per_second)
        self.send_interval = 1.0 / self.packets_per_second

    def _run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(2)
            self.sock.connect((self.host, self.port))

            next_send = time.time()
            while self.running:
                now = time.time()
                if now >= next_send:
                    packet = self._generate_modbus_request()
                    try:
                        self.sock.sendall(packet)
                        self.sent_packets += 1
                        self.total_sent_packets += 1
                    except:
                        pass
                    next_send += self.send_interval
                else:
                    time.sleep(min(0.01, next_send - now))

        except Exception:
            pass
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass

    def _generate_modbus_request(self) -> bytes:
        transaction_id = random.randint(0, 65535)
        protocol_id = 0
        unit_id = 1
        function_code = 3
        start_address = random.randint(0, 50)
        register_count = random.randint(1, 5)
        pdu = struct.pack(">BHH", function_code, start_address, register_count)
        length = len(pdu) + 1
        mbap = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
        return mbap + pdu
