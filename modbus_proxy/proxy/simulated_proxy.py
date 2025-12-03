import threading
import time
import random
from collections import deque

from PyQt6.QtCore import QObject, pyqtSignal


# -------------------------------------------------------------
# Сигналы для GUI
# -------------------------------------------------------------
class ProxySignals(QObject):
    log = pyqtSignal(str)
    event = pyqtSignal(str)
    security_event = pyqtSignal(str)  # ⭐ новое: уведомления безопасности
    packet = pyqtSignal(object)


# -------------------------------------------------------------
# Упрощённая модель Modbus‑пакета
# -------------------------------------------------------------
class ModbusPacket:
    def __init__(self, source: str, function_code: int, data_value: int):
        self.source = source
        self.function_code = function_code
        self.data_value = data_value


# -------------------------------------------------------------
# Основной симулируемый Modbus Proxy
# -------------------------------------------------------------
class SimulatedProxy:

    VALID_FC = {1, 3, 5}             # допустимые FC
    MAX_DATA = 150                   # допустимый диапазон данных
    REPLAY_WINDOW = 6                # окно для обнаружения replay
    DOS_THRESHOLD = 30               # порог аномальной частоты пакетов

    def __init__(self, on_packet_callback, on_event_callback):
        self.on_packet_callback = on_packet_callback
        self.on_event_callback = on_event_callback

        self.signals = ProxySignals()

        self.running = False
        self.blocked_sources = set()

        self.attack_mode = "NONE"
        self.chart_values = []

        # решение безопасности
        self.last_values = {}        # история значений по источникам
        self.replay_cache = deque(maxlen=20)
        self.packet_times = deque(maxlen=40)

        self.thread = None

    # ---------------------------------------------------------
    # Управление
    # ---------------------------------------------------------
    def start(self):
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

        self.signals.log.emit("[PROXY] Запущен")

    def stop(self):
        self.running = False
        self.signals.log.emit("[PROXY] Остановлен")

    # ---------------------------------------------------------
    # Режим атаки
    # ---------------------------------------------------------
    def set_attack_mode(self, mode: str):
        self.attack_mode = mode
        self.signals.log.emit(f"[PROXY] Attack mode set: {mode}")
        self.on_event_callback(f"Атака активирована: {mode}")

    # ---------------------------------------------------------
    # Блокировка источника
    # ---------------------------------------------------------
    def block_source(self, src: str):
        self.blocked_sources.add(src)
        self.signals.security_event.emit(f"Источник заблокирован: {src}")

    # ---------------------------------------------------------
    # Безопасность — анализ пакетов
    # ---------------------------------------------------------
    def _security_inspect(self, pkt: ModbusPacket):
        src = pkt.source

        # 1) Недопустимый Function Code → Injection
        if pkt.function_code not in self.VALID_FC:
            msg = f"[INJECTION] Неверный Function Code {pkt.function_code} от {src}"
            self.signals.security_event.emit(msg)
            return False  # блокируем пакет

        # 2) Слишком большие значения (попытка записи)
        if pkt.data_value > self.MAX_DATA:
            msg = f"[INJECTION] Завышенное значение ({pkt.data_value}) от {src}"
            self.signals.security_event.emit(msg)
            return False

        # 3) Replay Detection
        fingerprint = (src, pkt.function_code, pkt.data_value)
        if fingerprint in self.replay_cache:
            self.signals.security_event.emit(
                f"[REPLAY] Повтор пакета от {src}: value={pkt.data_value}"
            )
            return False
        self.replay_cache.append(fingerprint)

        # 4) DoS Detection — слишком частые пакеты
        now = time.time()
        self.packet_times.append(now)
        if len(self.packet_times) >= 10:
            delta = now - self.packet_times[-10]
            if delta < 1.0:  # 10 пакетов/сек — аномалия
                self.signals.security_event.emit(
                    f"[DoS] Аномальная частота пакетов от {src}"
                )
                return False

        return True  # пакет валиден

    # ---------------------------------------------------------
    # Основной цикл
    # ---------------------------------------------------------
    def _run_loop(self):
        while self.running:
            time.sleep(0.5)

            src = random.choice(["PLC1", "PLC2", "SCADA1", "RTU7"])

            # блокировки источников
            if src in self.blocked_sources:
                self.signals.log.emit(f"[BLOCKED] Пакет от {src} отброшен")
                continue

            pkt = ModbusPacket(
                source=src,
                function_code=random.choice([1, 3, 5]),
                data_value=random.randint(0, 100)
            )

            # применяем атаки
            pkt = self._apply_attack(pkt)

            # ПРОВОДИМ ПРОВЕРКУ БЕЗОПАСНОСТИ
            if not self._security_inspect(pkt):
                continue  # пакет отбрасывается

            # сохраняем значения для DoS‑графика
            self.chart_values.append(pkt.data_value)
            if len(self.chart_values) > 200:
                self.chart_values.pop(0)

            # отправка в GUI
            try:
                self.on_packet_callback(pkt)
            except Exception as e:
                self.signals.log.emit(f"[ERROR] packet callback failed: {e}")

    # ---------------------------------------------------------
    # Логика атак
    # ---------------------------------------------------------
    def _apply_attack(self, pkt: ModbusPacket):
        mode = self.attack_mode

        if mode == "NONE":
            return pkt

        # MITM — модификация значения
        if mode == "MITM_MODIFY":
            original = pkt.data_value
            pkt.data_value += random.randint(-15, 20)
            self.on_event_callback(
                f"MITM_MODIFY: {pkt.source} {original} → {pkt.data_value}"
            )

        # MITM — Replay
        elif mode == "MITM_REPLAY":
            replay_val = random.choice([5, 10, 20, 40])
            original = pkt.data_value
            pkt.data_value = replay_val
            self.on_event_callback(
                f"MITM_REPLAY: {pkt.source} old={original} replay={replay_val}"
            )

        # DoS — резкий рост нагрузки
        elif mode == "DOS":
            if len(self.chart_values) < 2:
                pkt.data_value = random.randint(140, 220)
            else:
                prev = self.chart_values[-1]
                if random.random() < 0.15:
                    pkt.data_value = random.randint(40, 90)
                else:
                    pkt.data_value = prev + random.randint(-20, 35)

                pkt.data_value = max(0, min(250, pkt.data_value))

            self.on_event_callback(f"DOS: value → {pkt.data_value}")

        return pkt
