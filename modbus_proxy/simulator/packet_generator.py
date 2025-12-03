import random
import time


class PacketGenerator:
    """
    Полностью синтетический генератор Modbus-пакетов
    + MITM-атаки
    + DoS-перегрузка
    + нормальный рабочий трафик
    """

    FUNCTIONS = [3, 4, 6, 16]  # Holding/Input registers, Write Single, Write Multiple

    def __init__(self):
        self.dos_active = False
        self.mitm_active = False

        # параметры MITM
        self.mitm_manipulate_reg = 40001
        self.mitm_force_value = 999

    def generate_packet(self) -> dict:
        """
        Генерирует синтетический Modbus TCP пакет.
        """

        function = random.choice(self.FUNCTIONS)
        reg = random.randint(40000, 40020)
        val = random.randint(0, 100)

        # MITM модификация
        if self.mitm_active and reg == self.mitm_manipulate_reg:
            original = val
            val = self.mitm_force_value
            return {
                "function": function,
                "register": reg,
                "value": val,
                "type": "MITM",
                "details": {
                    "original": original,
                    "modified": val
                }
            }

        # стандартный пакет
        return {
            "function": function,
            "register": reg,
            "value": val,
            "type": "NORMAL",
            "details": {}
        }

    def generate_dos_packets(self, count: int):
        """
        Генерирует burst трафика для DoS.
        """
        packets = []
        for _ in range(count):
            packets.append({
                "function": 3,
                "register": random.randint(40000, 40020),
                "value": random.randint(0, 100),
                "type": "DoS",
                "details": {"burst": count}
            })
        return packets

    # ---------------------------------------------------------
    #       Управление состоянием атак
    # ---------------------------------------------------------
    def enable_dos(self):
        self.dos_active = True

    def disable_dos(self):
        self.dos_active = False

    def enable_mitm(self):
        self.mitm_active = True

    def disable_mitm(self):
        self.mitm_active = False
