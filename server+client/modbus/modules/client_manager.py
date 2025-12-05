from modules.client_module import ModbusClientWorker


class ClientManager:
    def __init__(self, host="127.0.0.1", port=15020):
        self.host = host
        self.port = port
        self.clients: list[ModbusClientWorker] = []
        self.max_clients = 10

    def add_client(self, packets_per_second=10):
        if len(self.clients) >= self.max_clients:
            return False
        client = ModbusClientWorker(host=self.host, port=self.port, packets_per_second=packets_per_second)
        client.start()
        self.clients.append(client)
        return True

    def remove_last_client(self):
        if not self.clients:
            return False
        client = self.clients.pop()
        client.stop()
        return True

    def stop_all(self):
        for c in self.clients:
            c.stop()
        self.clients.clear()

    def set_client_rate(self, client_index, pps):
        if 0 <= client_index < len(self.clients):
            self.clients[client_index].update_rate(pps)

    def get_total_sent_packets(self):
        return sum(c.total_sent_packets for c in self.clients)

    def get_active_clients(self):
        return len(self.clients)

    def get_total_packets_per_second(self):
        return sum(c.packets_per_second for c in self.clients)
