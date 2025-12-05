import socket
import threading
import time


class ModbusTCPServer:
    def __init__(self, host="127.0.0.1", port=15020, data_broker=None):
        self.host = host
        self.port = port
        self.data_broker = data_broker
        self.server_socket = None
        self.running = False
        self.active_clients = 0
        self.total_packets = 0
        self.packets_per_sec = 0
        self._last_second = time.time()
        self._packets_counter = 0

    def start(self):
        """Запуск сервера в отдельном потоке"""
        if self.running:
            return
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        self.monitor_thread = threading.Thread(target=self._monitor_packets, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        """Остановка сервера"""
        self.running = False
        try:
            if self.server_socket:
                self.server_socket.close()
        except:
            pass

    def _run_server(self):
        """Основной цикл TCP сервера"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(20)

        print(f"[SERVER] Modbus TCP Server listening on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.active_clients += 1
                print(f"[SERVER] Client connected: {addr}")
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except OSError:
                break

    def _handle_client(self, client_socket, addr):
        """Обработка клиентских пакетов"""
        while self.running:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.total_packets += 1
                self._packets_counter += 1
                if self.data_broker:
                    self.data_broker.update_packets(self._packets_counter)
                response = self._create_modbus_echo_response(data)
                client_socket.sendall(response)
            except:
                break

        client_socket.close()
        self.active_clients -= 1
        print(f"[SERVER] Client disconnected: {addr}")

    def _create_modbus_echo_response(self, request: bytes) -> bytes:
        if len(request) < 8:
            return b""
        transaction_id = request[0:2]
        protocol_id = request[2:4]
        length = request[4:6]
        unit_id = request[6:7]
        pdu = request[7:]
        return transaction_id + protocol_id + length + unit_id + pdu

    def _monitor_packets(self):
        """Подсчёт пакетов в секунду и передача в брокер"""
        last_stat_reset = time.time()
        while self.running:
            time.sleep(0.1)
            now = time.time()
            if now - last_stat_reset >= 1:
                packets_now = self._packets_counter
                self.packets_per_sec = packets_now
                self._packets_counter = 0
                last_stat_reset = now
                if self.data_broker:
                    self.data_broker.update_packets(packets_now)
