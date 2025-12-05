# modules/attacks_module.py
import time
import threading
import random


class AttackManager:
    def __init__(self, server, proxy_manager, client_manager):
        """
        Обновлённый конструктор AttackManager(self.server, self.proxy_manager, self.client_manager)
        """
        self.server = server
        self.proxy_manager = proxy_manager
        self.client_manager = client_manager

        # Активные атаки:
        # attack_id: {
        #     "client_index": int,
        #     "attack_type": str,
        #     "started": float,
        #     "thread": Thread,
        #     "running": bool
        # }
        self.active_attacks = {}
        self.attack_counter = 0

    # -----------------------------------------------------
    # PUBLIC API — вызывается из GUI
    # -----------------------------------------------------

    def start_attack_for_client(self, client_index: int, attack_type: str):
        """Запуск атаки на выбранного клиента"""
        if client_index >= len(self.client_manager.clients):
            print("[AttackManager] Invalid client index")
            return False

        attack_id = self.attack_counter
        self.attack_counter += 1

        entry = {
            "client_index": client_index,
            "attack_type": attack_type,
            "started": time.time(),
            "running": True,
            "thread": None
        }

        thread = threading.Thread(target=self._run_attack, args=(attack_id,), daemon=True)
        entry["thread"] = thread
        self.active_attacks[attack_id] = entry

        thread.start()
        return True

    def stop_attack(self, attack_id: int):
        """Остановка атаки: флаг + нормализация клиента"""
        if attack_id not in self.active_attacks:
            return False

        attack = self.active_attacks[attack_id]
        attack["running"] = False

        client_idx = attack["client_index"]
        client = self.client_manager.clients[client_idx]

        # --- ВОССТАНАВЛИВАЕМ КЛИЕНТА ---
        client.update_rate(client.default_rate if hasattr(client, "default_rate") else 1)

        print(f"[AttackManager] Requested stop attack {attack_id}")
        return True

    def list_attacks(self):
        """Вернуть список всех активных атак для GUI"""
        return [
            {
                "id": attack_id,
                "client_index": info["client_index"],
                "attack_type": info["attack_type"],
                "running": info["running"],
                "started": info["started"]
            }
            for attack_id, info in self.active_attacks.items()
        ]

    # -----------------------------------------------------
    # INTERNAL — логика исполнения конкретной атаки
    # -----------------------------------------------------

    def _run_attack(self, attack_id):
        entry = self.active_attacks[attack_id]
        attack_type = entry["attack_type"]
        client_index = entry["client_index"]

        client = self.client_manager.clients[client_index]

        # Сохраняем нормальный PPS клиента, чтобы потом восстановить
        if not hasattr(client, "default_rate"):
            client.default_rate = client.packets_per_second

        print(f"[Attack] Start {attack_type} on client #{client_index}")

        try:
            if attack_type == "SYN Flood":
                self._attack_syn_flood(attack_id, client)
            elif attack_type == "Function Spam":
                self._attack_function_spam(attack_id, client)
            elif attack_type == "Random Packets":
                self._attack_random_packets(attack_id, client)
            elif attack_type == "Slowloris":
                self._attack_slowloris(attack_id, client)

        except Exception as e:
            print(f"[Attack] ERROR in {attack_type}: {e}")

        # После завершения атаки восстанавливаем клиента
        client.update_rate(client.default_rate)

        print(f"[Attack] Stop {attack_type} on client #{client_index}")

        # --- АВТОУДАЛЕНИЕ АТАКИ ---
        if attack_id in self.active_attacks:
            del self.active_attacks[attack_id]

    # -----------------------------------------------------
    # ATTACK IMPLEMENTATIONS
    # -----------------------------------------------------

    def _attack_syn_flood(self, attack_id, client):
        while self.active_attacks[attack_id]["running"]:
            client.update_rate(client.packets_per_second + 5)
            time.sleep(0.3)

    def _attack_function_spam(self, attack_id, client):
        while self.active_attacks[attack_id]["running"]:
            client.update_rate(client.packets_per_second + 1)
            time.sleep(0.2)

    def _attack_random_packets(self, attack_id, client):
        while self.active_attacks[attack_id]["running"]:
            client.update_rate(random.randint(5, 50))
            time.sleep(0.2)

    def _attack_slowloris(self, attack_id, client):
        while self.active_attacks[attack_id]["running"]:
            client.update_rate(max(1, client.packets_per_second - 1))
            time.sleep(1)
