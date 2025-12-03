import random
import time
from threading import Thread
from PyQt6.QtCore import pyqtSignal, QObject


class EmulatorSignals(QObject):
    new_value = pyqtSignal(int)          # новое показание регистра
    attack_detected = pyqtSignal(str)    # событие атаки
    log_event = pyqtSignal(str)          # любое событие для логов


class ModbusEmulator:
    def __init__(self):
        self.signals = EmulatorSignals()
        self._running = False
        self._thread = None
        self.register_value = 0

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        self.signals.log_event.emit("Эмулятор: старт симуляции трафика")

        while self._running:
            # 1) генерируем новое значение регистра
            self.register_value += random.randint(-3, 5)
            self.register_value = max(0, min(self.register_value, 200))

            self.signals.new_value.emit(self.register_value)
            self.signals.log_event.emit(f"Трафик: регистр = {self.register_value}")

            # 2) иногда симулируем атаку
            if random.random() < 0.07:
                attack = random.choice([
                    "Modbus Scan Detected",
                    "Write Multiple Coils Flood",
                    "Illegal Function Request",
                    "Register Overflow Attempt"
                ])
                self.signals.attack_detected.emit(attack)
                self.signals.log_event.emit(f"Атака обнаружена: {attack}")

            time.sleep(1)
