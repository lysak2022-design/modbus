# simulator/simulator.py
from PyQt6.QtCore import QObject, pyqtSignal
from dataclasses import dataclass, field
import threading
import time
import random
import struct
from typing import Optional, List, Dict, Any
import collections


@dataclass
class FakeModbusPacket:
    """
    Минимальное представление Modbus TCP пакета (request or response).
    MBAP (7 bytes) + PDU (FC + payload)
    """
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    address: int
    data_value: int
    source: str = "client"
    attack_type: Optional[str] = None
    ts: float = field(default_factory=time.time)

    def to_mbap_bytes(self) -> bytes:
        """
        Собирает MBAP + PDU в bytes:
        MBAP: transaction(2) protocol(2) length(2) unit(1)
        length = len(PDU) + 1 (unit)
        PDU: function (1) + payload (depending on function)
        Для простоты PDU = fc + addr(2) + value(2)
        """
        pdu = struct.pack(">BHH", self.function_code, self.address & 0xFFFF, self.data_value & 0xFFFF)
        length = len(pdu) + 1  # unit id included in MBAP length as per spec
        mbap = struct.pack(">HHHB", self.transaction_id & 0xFFFF, self.protocol_id & 0xFFFF, length & 0xFFFF, self.unit_id & 0xFF)
        return mbap + pdu

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "transaction_id": self.transaction_id,
            "protocol_id": self.protocol_id,
            "unit_id": self.unit_id,
            "function_code": self.function_code,
            "address": self.address,
            "data_value": self.data_value,
            "source": self.source,
            "attack_type": self.attack_type
        }


class TrafficSignals(QObject):
    packet_generated = pyqtSignal(object)   # emits FakeModbusPacket
    log = pyqtSignal(str)
    attack_started = pyqtSignal(str)
    attack_stopped = pyqtSignal(str)


class TrafficSimulator:
    """
    Потоковый симулятор Modbus Client/Server.

    Usage:
        sim = TrafficSimulator(proxy=some_proxy)  # proxy optional
        sim.start()
        sim.start_client()
        sim.start_server()
        sim.set_attack("DOS") / "MITM_MODIFY" / "MITM_REPLAY" / "NONE"
        sim.stop()
    """

    def __init__(self, proxy=None):
        self.signals = TrafficSignals()
        self.proxy = proxy  # если передан, simulator вызовет proxy.handle_packet(pkt)

        # control flags
        self._running = False
        self._client_running = False
        self._server_running = False

        # threads
        self._client_thread = None
        self._server_thread = None
        self._lock = threading.Lock()

        # replay buffer and other state
        self._replay_buffer: collections.deque = collections.deque(maxlen=500)
        self._blocked_sources = set()

        # attack mode: None / "MITM_MODIFY" / "MITM_REPLAY" / "DOS"
        self.attack_mode = None

        # parameters
        self.client_interval = 0.5  # seconds between client requests
        self.dos_burst_min = 10
        self.dos_burst_max = 30

        # transaction id counter
        self._tid = random.randint(0, 65535)

    # -------------------- lifecycle --------------------
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
        self.signals.log.emit("[SIM] Simulator started")

    def stop(self):
        with self._lock:
            self._running = False
            self._client_running = False
            self._server_running = False
        # join threads
        if self._client_thread and self._client_thread.is_alive():
            self._client_thread.join(timeout=1.0)
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=1.0)
        self.signals.log.emit("[SIM] Simulator stopped")

    # -------------------- attack control --------------------
    def set_attack(self, mode: Optional[str]):
        self.attack_mode = mode
        if mode and mode != "NONE":
            self.signals.attack_started.emit(mode)
            self.signals.log.emit(f"[SIM] Attack started: {mode}")
        else:
            self.signals.attack_stopped.emit("NONE")
            self.signals.log.emit("[SIM] Attack stopped")

    def block_source(self, src: str):
        self._blocked_sources.add(src)
        self.signals.log.emit(f"[SIM] Blocked source: {src}")

    def unblock_source(self, src: str):
        if src in self._blocked_sources:
            self._blocked_sources.remove(src)
            self.signals.log.emit(f"[SIM] Unblocked source: {src}")

    # -------------------- client/server control --------------------
    def start_client(self):
        if self._client_running:
            return
        self._client_running = True
        self._client_thread = threading.Thread(target=self._client_loop, daemon=True)
        self._client_thread.start()
        self.signals.log.emit("[SIM] Client started")

    def stop_client(self):
        self._client_running = False
        self.signals.log.emit("[SIM] Client stopped")

    def start_server(self):
        if self._server_running:
            return
        self._server_running = True
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()
        self.signals.log.emit("[SIM] Server started")

    def stop_server(self):
        self._server_running = False
        self.signals.log.emit("[SIM] Server stopped")

    # -------------------- loops --------------------
    def _next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def _client_loop(self):
        """
        Генерирует запросы от клиента к серверу.
        Каждая итерация создаёт FakeModbusPacket типа 'client' и передаёт его в proxy (если есть)
        и в replay buffer.
        При атаке DOS делает bursts; при MITM_REPLAY использует буфер для повторов; MITM_MODIFY помечает и изменяет value.
        """
        while self._client_running and self._running:
            try:
                # decide action based on attack mode
                if self.attack_mode == "DOS":
                    # generate a burst quickly
                    burst = random.randint(self.dos_burst_min, self.dos_burst_max)
                    for i in range(burst):
                        pkt = self._make_packet(source="client", attack_hint="DOS")
                        self._handle_outgoing(pkt)
                    # brief pause after burst
                    time.sleep(max(0.1, self.client_interval / 5.0))
                    continue

                if self.attack_mode == "MITM_REPLAY" and len(self._replay_buffer) >= 5 and random.random() < 0.3:
                    # replay random previous
                    fake = random.choice(list(self._replay_buffer))
                    # clone with new transaction id to simulate replay
                    pkt = FakeModbusPacket(
                        transaction_id=self._next_tid(),
                        protocol_id=fake.protocol_id,
                        unit_id=fake.unit_id,
                        function_code=fake.function_code,
                        address=fake.address,
                        data_value=fake.data_value,
                        source="client",
                        attack_type="REPLAY"
                    )
                    self._handle_outgoing(pkt)
                    time.sleep(self.client_interval)
                    continue

                # normal single request generation
                pkt = self._make_packet(source="client")
                # MITM modify: perform in-flight modification here (simulate attacker between client/server)
                if self.attack_mode == "MITM_MODIFY" and random.random() < 0.5:
                    # modify value
                    pkt.data_value = pkt.data_value + 123  # arbitrary modification
                    pkt.attack_type = "MITM_MODIFY"

                self._handle_outgoing(pkt)
                time.sleep(self.client_interval)
            except Exception as e:
                self.signals.log.emit(f"[SIM][CLIENT] error: {e}")
                time.sleep(0.5)

    def _server_loop(self):
        """
        Эмулирует сервер: читает из replay buffer and occasionally generates server-side events/responses.
        Здесь мы имитируем ответы на запросы; для простоты — раз в несколько секунд генерируем 'heartbeat' ответа.
        """
        while self._server_running and self._running:
            try:
                # occasionally produce an unsolicited update from server (server -> client)
                if random.random() < 0.2:
                    pkt = self._make_packet(source="server")
                    self._handle_outgoing(pkt)
                time.sleep(1.0)
            except Exception as e:
                self.signals.log.emit(f"[SIM][SERVER] error: {e}")
                time.sleep(0.5)

    # -------------------- helpers --------------------
    def _make_packet(self, source: str = "client", attack_hint: Optional[str] = None) -> FakeModbusPacket:
        tid = self._next_tid()
        protocol = 0
        unit = random.randint(1, 5)
        fc = random.choice([3, 4, 6, 16])  # common FCs
        addr = random.randint(0, 100)
        val = random.randint(0, 1000)
        pkt = FakeModbusPacket(
            transaction_id=tid,
            protocol_id=protocol,
            unit_id=unit,
            function_code=fc,
            address=addr,
            data_value=val,
            source=source,
            attack_type=attack_hint
        )
        # save to replay buffer (all outgoing)
        self._replay_buffer.append(pkt)
        return pkt

    def _handle_outgoing(self, pkt: FakeModbusPacket):
        # block check
        if pkt.source in self._blocked_sources:
            self.signals.log.emit(f"[SIM] Dropped packet from blocked source {pkt.source}")
            return

        # emit signal
        try:
            self.signals.packet_generated.emit(pkt)
        except Exception:
            pass

        # log summary
        self.signals.log.emit(f"[SIM] Packet {pkt.source} FC={pkt.function_code} VAL={pkt.data_value} TID={pkt.transaction_id}")

        # forward to proxy if available
        try:
            if self.proxy is not None:
                # if proxy expects object, call handle_packet
                try:
                    # If proxy has handle_packet, use it
                    if hasattr(self.proxy, "handle_packet"):
                        self.proxy.handle_packet(pkt)
                    # else try callback usage (some proxies expect function)
                    elif callable(getattr(self.proxy, "on_packet", None)):
                        self.proxy.on_packet(pkt)
                except Exception:
                    # as fallback, try proxy.handle_packet(pkt) and swallow exceptions
                    try:
                        self.proxy.handle_packet(pkt)
                    except Exception:
                        pass
        except Exception:
            pass

    # -------------------- utilities --------------------
    def get_replay_buffer(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in list(self._replay_buffer)]

    def set_client_rate(self, interval_seconds: float):
        self.client_interval = max(0.01, float(interval_seconds))

    def set_dos_params(self, burst_min: int, burst_max: int):
        self.dos_burst_min = int(burst_min)
        self.dos_burst_max = int(burst_max)
