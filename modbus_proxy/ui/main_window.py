# ui/main_window.py
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QTabWidget,
    QPlainTextEdit, QInputDialog, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
import psutil
import pyqtgraph as pg
import random
import time
import os

from storage.log_storage import LogStorage
from storage.event_storage import EventStorage
from proxy.simulated_proxy import SimulatedProxy


class ModbusProxyGUI(QWidget):

    update_chart_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Modbus Proxy Simulator")
        self.resize(1000, 650)

        # storages
        self.log_storage = LogStorage()
        self.event_storage = EventStorage()

        # attack logs & rules
        self.attack_logs = []      # list of dicts {time, src, type, desc, value}
        self.attack_rules = []     # list of strings like "value > 200 block"

        # автосохранение логов атак
        self.attack_log_file = "logs/attack_logs.txt"
        os.makedirs(os.path.dirname(self.attack_log_file), exist_ok=True)

        # подключаем прокси (callback-based)
        self.proxy = SimulatedProxy(
            on_packet_callback=self._packet_from_thread,
            on_event_callback=self._event_from_thread
        )

        # сигналы (потокобезопасно)
        self.proxy.signals.log.connect(self.on_log)
        self.proxy.signals.event.connect(self.on_event)

        # график — сигнальная передача от рабочих потоков
        self.update_chart_signal.connect(self._update_chart_attack_safe)

        # график - данные
        self.chart_values = []
        self.max_points = 200

        # таймер тестового сервера (локальная генерация графика)
        self.graph_timer = QTimer()
        self.graph_timer.timeout.connect(self._update_graph_fake)

        # UI
        self._build_ui()

    # ------------------------- потокобезопасные колбэки -------------------------
    def _packet_from_thread(self, pkt):

        try:
            self.update_chart_signal.emit(int(pkt.data_value))
            attack_type, desc = self.classify_packet(pkt)
            now = time.strftime("%H:%M:%S")
            entry = {
                "time": now,
                "src": getattr(pkt, "source", ""),
                "type": attack_type,
                "desc": desc,
                "value": getattr(pkt, "data_value", 0)
            }
            self.attack_logs.append(entry)
            self._save_attack_log(entry)

            if hasattr(self, "attack_table"):
                row = self.attack_table.rowCount()
                self.attack_table.insertRow(row)
                self.attack_table.setItem(row, 0, QTableWidgetItem(now))
                self.attack_table.setItem(row, 1, QTableWidgetItem(str(entry["src"])))
                self.attack_table.setItem(row, 2, QTableWidgetItem(attack_type))
                self.attack_table.setItem(row, 3, QTableWidgetItem(desc))

            mode = getattr(self.proxy, "attack_mode", "NONE")
            prefix = f"[ATTACK:{mode}] " if mode != "NONE" else "[PKT] "
            log = f"{prefix}{pkt.source} | FC={pkt.function_code} | VAL={pkt.data_value}"
            self.on_log(log)

            self._apply_rules_for_packet(pkt)

        except Exception as e:
            self.on_log(f"[ERROR] _packet_from_thread failed: {e}")

    def _event_from_thread(self, text: str):
        try:
            self.event_storage.add_event({"type": "INFO", "details": text})
            if hasattr(self, "event_table"):
                row = self.event_table.rowCount()
                self.event_table.insertRow(row)
                self.event_table.setItem(row, 0, QTableWidgetItem("INFO"))
                self.event_table.setItem(row, 1, QTableWidgetItem(text))
            self.on_log(f"[EVENT] {text}")
        except Exception:
            pass

    # ------------------------- классификация пакета -------------------------
    def classify_packet(self, pkt):
        try:
            val = int(getattr(pkt, "data_value", 0))
        except Exception:
            val = 0

        if len(self.chart_values) >= 1:
            prev = self.chart_values[-1]
            if abs(val - prev) > 40:
                return "MITM_MODIFY", f"Value jump {prev} → {val}"

        if len(self.chart_values) >= 5:
            if val == self.chart_values[-3] or val == self.chart_values[-4]:
                return "MITM_REPLAY", f"Replayed value {val}"

        if val >= 180:
            return "DOS", f"High load {val}"

        return "NORMAL", "OK"

    # ------------------------- применение правил -------------------------
    def _apply_rules_for_packet(self, pkt):
        try:
            val = int(getattr(pkt, "data_value", 0))
        except Exception:
            val = 0

        src = getattr(pkt, "source", None)
        if not src:
            return

        for r in list(self.attack_rules):
            rr = r.lower().strip()
            try:
                if "value >" in rr and "block" in rr:
                    threshold = int(rr.split(">")[1].split()[0])
                    if val > threshold:
                        self.proxy.block_source(src)
                        self.on_log(f"[RULE] Auto-block {src} by rule '{r}' (value={val})")
                elif "value <" in rr and "block" in rr:
                    threshold = int(rr.split("<")[1].split()[0])
                    if val < threshold:
                        self.proxy.block_source(src)
                        self.on_log(f"[RULE] Auto-block {src} by rule '{r}' (value={val})")
                elif "value ==" in rr and "block" in rr:
                    threshold = int(rr.split("==")[1].split()[0])
                    if val == threshold:
                        self.proxy.block_source(src)
                        self.on_log(f"[RULE] Auto-block {src} by rule '{r}' (value={val})")
            except Exception:
                continue

    # ------------------------- save attack log -------------------------
    def _save_attack_log(self, entry):
        try:
            with open(self.attack_log_file, "a", encoding="utf-8") as f:
                f.write(f"{entry['time']}\t{entry['src']}\t{entry['type']}\t{entry['desc']}\t{entry['value']}\n")
        except Exception as e:
            self.on_log(f"[ERROR] Failed to save attack log: {e}")

    # ------------------------- график -------------------------
    def _update_chart_attack_safe(self, value):
        mode = getattr(self.proxy, "attack_mode", "NONE")
        if mode == "MITM_MODIFY":
            value = value + random.randint(-10, 15)
        elif mode == "MITM_REPLAY":
            if len(self.chart_values) > 5:
                value = self.chart_values[-5]
        elif mode == "DOS":
            if len(self.chart_values) == 0:
                value = random.randint(160, 230)
            else:
                prev = self.chart_values[-1]
                if random.random() < 0.12:
                    value = random.randint(40, 90)
                else:
                    value = prev + random.randint(-20, 50)
                value = max(0, min(300, value))
        self.chart_values.append(int(value))
        if len(self.chart_values) > self.max_points:
            self.chart_values.pop(0)
        try:
            self.plot_curve.setData(self.chart_values)
        except Exception:
            pass

    # ------------------------- тестовый график -------------------------
    def _update_graph_fake(self):
        v = random.randint(10, 80)
        self.update_chart_signal.emit(v)

    # ------------------------- UI -------------------------
    def _build_ui(self):
        layout = QVBoxLayout()
        tabs = QTabWidget()
        tabs.addTab(self._monitor_tab(), "Монитор")
        tabs.addTab(self._attacks_tab(), "Атаки")
        tabs.addTab(self._attack_analyzer_tab(), "Анализ атаки")
        layout.addWidget(tabs)
        self.setLayout(layout)

    def _monitor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        control = QHBoxLayout()
        control.addWidget(QLabel("Интерфейс:"))
        self.interface_box = QComboBox()
        try:
            self.interface_box.addItems(psutil.net_if_addrs().keys())
        except Exception:
            self.interface_box.addItem("lo")
        control.addWidget(self.interface_box)
        self.start_btn = QPushButton("Запуск прокси")
        self.start_btn.clicked.connect(self._start_proxy)
        control.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Остоновка прокси")
        self.stop_btn.clicked.connect(self._stop_proxy)
        control.addWidget(self.stop_btn)
        self.server_btn = QPushButton("Запуск сервера")
        self.server_btn.clicked.connect(self._run_server)
        control.addWidget(self.server_btn)
        layout.addLayout(control)
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground("black")
        self.plot_curve = self.plot_widget.plot(pen=pg.mkPen("lime", width=2))
        layout.addWidget(self.plot_widget, stretch=3)
        self.live_log = QPlainTextEdit()
        self.live_log.setReadOnly(True)
        self.live_log.setMaximumHeight(160)
        layout.addWidget(self.live_log, stretch=1)
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(1)
        self.log_table.setHorizontalHeaderLabels(["Логи сообщений"])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.log_table, stretch=1)
        tab.setLayout(layout)
        return tab

    def _attacks_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        attack_ctrl = QHBoxLayout()
        attack_ctrl.addWidget(QLabel("Режим атаки:"))
        self.attack_mode_box = QComboBox()
        self.attack_mode_box.addItems(["Нет", "MITM_MODIFY", "MITM_REPLAY", "DOS"])
        attack_ctrl.addWidget(self.attack_mode_box)
        self.apply_attack_btn = QPushButton("Запустить атаку")
        self.apply_attack_btn.clicked.connect(self._apply_attack_mode)
        attack_ctrl.addWidget(self.apply_attack_btn)
        self.stop_attack_btn = QPushButton("Остановить атаку")
        self.stop_attack_btn.clicked.connect(self._stop_attack)
        attack_ctrl.addWidget(self.stop_attack_btn)
        layout.addLayout(attack_ctrl)
        self.event_table = QTableWidget()
        self.event_table.setColumnCount(2)
        self.event_table.setHorizontalHeaderLabels(["Тип", "Детали"])
        self.event_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.event_table, stretch=1)
        btns = QHBoxLayout()
        self.block_btn = QPushButton("Заблокировать выбранный процесс")
        self.block_btn.clicked.connect(self._block_selected)
        btns.addWidget(self.block_btn)
        self.clear_btn = QPushButton("Отчистить события")
        self.clear_btn.clicked.connect(self._clear_events)
        btns.addWidget(self.clear_btn)
        layout.addLayout(btns)
        tab.setLayout(layout)
        return tab

    def _attack_analyzer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.attack_table = QTableWidget()
        self.attack_table.setColumnCount(4)
        self.attack_table.setHorizontalHeaderLabels(["Время", "Источник", "Тип атаки", "Описание"])
        self.attack_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.attack_table, stretch=1)
        btns = QHBoxLayout()
        self.btn_block_attack = QPushButton("Заблокировать источник")
        self.btn_block_attack.clicked.connect(self._block_attack_source)
        btns.addWidget(self.btn_block_attack)
        self.btn_add_rule = QPushButton("Добавить правило")
        self.btn_add_rule.clicked.connect(self._add_rule_dialog)
        btns.addWidget(self.btn_add_rule)
        self.btn_show_rules = QPushButton("Показать правила")
        self.btn_show_rules.clicked.connect(self._show_rules_dialog)
        btns.addWidget(self.btn_show_rules)
        self.btn_save_attacks = QPushButton("Сохранить лог атаки")
        self.btn_save_attacks.clicked.connect(self._manual_save_attack_logs)
        btns.addWidget(self.btn_save_attacks)
        self.btn_clear_attacks = QPushButton("Отчистить лог атаки")
        self.btn_clear_attacks.clicked.connect(self._clear_attack_logs)
        btns.addWidget(self.btn_clear_attacks)
        layout.addLayout(btns)
        tab.setLayout(layout)
        return tab

    # ------------------------- Control -------------------------
    def _start_proxy(self):
        try:
            self.proxy.start()
            self.on_log("Прокси запущен")
        except Exception as e:
            self.on_log(f"[ERROR]Ошибка запуска прокси: {e}")

    def _stop_proxy(self):
        try:
            self.proxy.stop()
            self.on_log("Прокси остановлен")
        except Exception as e:
            self.on_log(f"[ERROR] Ошибка остоновки прокси: {e}")

    def _run_server(self):
        self.graph_timer.start(250)
        self.on_log("[SERVER] Сервер запущен")

    # ------------------------- logging -------------------------
    def on_event(self, msg: str):
        self.event_storage.add_event({"type": "INFO", "details": msg})
        try:
            if hasattr(self, "event_table"):
                r = self.event_table.rowCount()
                self.event_table.insertRow(r)
                self.event_table.setItem(r, 0, QTableWidgetItem("INFO"))
                self.event_table.setItem(r, 1, QTableWidgetItem(msg))
        except Exception:
            pass

    def on_log(self, text: str):
        try:
            self.log_storage.add_log(text)
        except Exception:
            pass
        try:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            self.log_table.setItem(row, 0, QTableWidgetItem(text))
            self.live_log.appendPlainText(text)
        except Exception:
            pass

    # ------------------------- attacks control -------------------------
    def _apply_attack_mode(self):
        mode = self.attack_mode_box.currentText()
        try:
            self.proxy.set_attack_mode(mode)
            if mode == "NONE":
                self.on_log("[Атака] Отключены, система работает в норме")
            else:
                self.on_log(f"[Атака] Активирован: {mode}")
            self.event_storage.add_event({"type": "ATTACK_MODE", "details": mode})
        except Exception as e:
            self.on_log(f"[Ошибка] set_attack_mode failed: {e}")

    def _stop_attack(self):
        try:
            self.proxy.set_attack_mode("NONE")
            self.on_log("[ATTACK] Все атаки остановлены вручную")
        except Exception as e:
            self.on_log(f"[Ошибка] Остановка атак не удалась: {e}")

    def _block_selected(self):
        row = self.event_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Block", "Select an event row first")
            return
        item = self.event_table.item(row, 1)
        if not item:
            QMessageBox.information(self, "Block", "No details available")
            return
        src = item.text().split()[-1]
        try:
            self.proxy.block_source(src)
            self.on_log(f"[Пользователь] Заблокирован: {src}")
        except Exception as e:
            self.on_log(f"[Ошибка] Ошибка блокировки: {e}")

    def _clear_events(self):
        try:
            self.event_storage.events.clear()
            if hasattr(self, "event_table"):
                self.event_table.setRowCount(0)
            self.on_log("Список событий очищен")
        except Exception:
            pass

    # ------------------------- attack analyzer actions -------------------------
    def _block_attack_source(self):
        row = self.attack_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Block", "Select an attack row first")
            return
        item = self.attack_table.item(row, 1)
        if not item:
            QMessageBox.information(self, "Block", "No source information")
            return
        src = item.text()
        try:
            self.proxy.block_source(src)
            self.on_log(f"[ANALYZER] Blocked {src}")
        except Exception as e:
            self.on_log(f"[ERROR] analyzer block failed: {e}")

    def _add_rule_dialog(self):
        txt, ok = QInputDialog.getText(self, "Добавить правило", "Введите правило (пример: число > 200 block):")
        if not ok or not txt:
            return
        self.attack_rules.append(txt.strip())
        self.on_log(f"[Правило] добавлено: {txt.strip()}")

    def _show_rules_dialog(self):
        if not self.attack_rules:
            QMessageBox.information(self, "Правило", "Нет правила для блокировки")
            return
        QMessageBox.information(self, "Rules", "\n".join(self.attack_rules))

    def _manual_save_attack_logs(self):
        try:
            os.makedirs("logs", exist_ok=True)
            with open("logs/manual_attack_logs.txt", "w", encoding="utf-8") as f:
                for a in self.attack_logs:
                    f.write(f"{a['time']}\t{a['src']}\t{a['type']}\t{a['desc']}\t{a['value']}\n")
            self.on_log("[SYSTEM] Attack logs manually saved to logs/manual_attack_logs.txt")
        except Exception as e:
            self.on_log(f"[ERROR] Manual attack log save failed: {e}")

    def _clear_attack_logs(self):
        self.attack_logs.clear()
        if hasattr(self, "attack_table"):
            self.attack_table.setRowCount(0)
        try:
            open(self.attack_log_file, "w", encoding="utf-8").close()
        except Exception:
            pass
        self.on_log("[SYSTEM] Логи атаки отчищены")
