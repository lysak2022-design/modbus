from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QPlainTextEdit,
    QSpinBox, QComboBox
)
from PyQt6.QtCore import QTimer
import pyqtgraph as pg
import time

# --- Модули приложения ---
from modules.broker import ServerDataBroker
from modules.server_module import ModbusTCPServer
from modules.client_manager import ClientManager
from modules.proxy_module import ProxyManager
from modules.attacks_module import AttackManager
from modules.logger_module import Logger


class ModbusGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modbus Server & Client Simulator")
        self.resize(1100, 700)

        # Источник данных
        self.data_broker = ServerDataBroker(history_seconds=300)

        # Сервер
        self.server = ModbusTCPServer(data_broker=self.data_broker)

        # Клиенты
        self.client_manager = ClientManager()

        # Прокси
        self.proxy_manager = ProxyManager(self.server)

        # Атаки
        self.attack_manager = AttackManager(self.server, self.proxy_manager, self.client_manager)

        # Логгер
        self.logger = Logger("server_log.txt")

        # UI
        self._build_ui()

        # Таймеры
        self.graph_timer = QTimer()
        self.graph_timer.timeout.connect(self._update_graph)
        self.graph_timer.start(1500)

        self.table_timer = QTimer()
        self.table_timer.timeout.connect(self._update_client_table)
        self.table_timer.start(1500)

        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self._update_logs)
        self.log_timer.start(1700)

        self.attack_timer = QTimer()
        self.attack_timer.timeout.connect(self._update_attacks_table)
        self.attack_timer.start(1600)

    # ------------------------------------------------------------
    # UI
    # ------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()

        self.tabs.addTab(self._monitor_tab(), "Монитор")
        self.tabs.addTab(self._clients_tab(), "Клиенты")
        self.tabs.addTab(self._proxy_tab(), "Прокси")
        self.tabs.addTab(self._attacks_tab(), "Атаки")
        self.tabs.addTab(self._logs_tab(), "Логи")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    # ------------------------------------------------------------
    # Monitor tab
    # ------------------------------------------------------------
    def _monitor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        control_layout = QHBoxLayout()

        self.server_btn = QPushButton("Запустить сервер")
        self.server_btn.clicked.connect(self._start_server)
        control_layout.addWidget(self.server_btn)

        self.packets_label = QLabel("Пакетов в секунду: 0")
        control_layout.addWidget(self.packets_label)

        layout.addLayout(control_layout)

        # График
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground("w")
        self.plot_curve = self.plot_widget.plot(pen=pg.mkPen("k", width=2))
        layout.addWidget(self.plot_widget, stretch=3)

        self.live_log = QPlainTextEdit()
        self.live_log.setReadOnly(True)
        self.live_log.setMaximumHeight(160)
        layout.addWidget(self.live_log, stretch=1)

        tab.setLayout(layout)
        return tab

    # ------------------------------------------------------------
    # Clients tab
    # ------------------------------------------------------------
    def _clients_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        control = QHBoxLayout()
        self.add_client_btn = QPushButton("+")
        self.add_client_btn.clicked.connect(self._add_client)
        control.addWidget(self.add_client_btn)

        self.remove_client_btn = QPushButton("-")
        self.remove_client_btn.clicked.connect(self._remove_client)
        control.addWidget(self.remove_client_btn)

        self.active_clients_label = QLabel("Активных клиентов: 0")
        control.addWidget(self.active_clients_label)

        layout.addLayout(control)

        self.client_table = QTableWidget()
        self.client_table.setColumnCount(4)
        self.client_table.setHorizontalHeaderLabels([
            "Клиент", "Отправлено пакетов", "Всего отправлено", "Пакетов/сек"
        ])
        self.client_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.client_table)

        tab.setLayout(layout)
        return tab

    # ------------------------------------------------------------
    # Proxy tab
    # ------------------------------------------------------------
    def _proxy_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        control = QHBoxLayout()

        self.proxy_start_btn = QPushButton("Запустить прокси")
        self.proxy_start_btn.clicked.connect(self._start_proxy)
        control.addWidget(self.proxy_start_btn)

        self.proxy_stop_btn = QPushButton("Остановить прокси")
        self.proxy_stop_btn.clicked.connect(self._stop_proxy)
        control.addWidget(self.proxy_stop_btn)

        layout.addLayout(control)

        self.proxy_table = QTableWidget()
        self.proxy_table.setColumnCount(3)
        self.proxy_table.setHorizontalHeaderLabels([
            "Клиент", "Статус", "Отправлено пакетов"
        ])
        self.proxy_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.proxy_table)

        tab.setLayout(layout)
        return tab

    # ------------------------------------------------------------
    # Attacks tab
    # ------------------------------------------------------------
    def _attacks_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        control = QHBoxLayout()

        self.client_select = QComboBox()
        control.addWidget(self.client_select)

        self.attack_select = QComboBox()
        self.attack_select.addItems([
            "SYN Flood",
            "Function Spam",
            "Random Packets",
            "Slowloris"
        ])
        control.addWidget(self.attack_select)

        self.start_attack_btn = QPushButton("Начать атаку")
        self.start_attack_btn.clicked.connect(self._start_attack)
        control.addWidget(self.start_attack_btn)

        layout.addLayout(control)

        self.attack_table = QTableWidget()
        self.attack_table.setColumnCount(4)
        self.attack_table.setHorizontalHeaderLabels([
            "ID", "Клиент", "Тип атаки", "Действие"
        ])
        self.attack_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.attack_table)

        tab.setLayout(layout)
        return tab

    def _start_attack(self):
        attack_type = self.attack_select.currentText()
        client_index = self.client_select.currentIndex()
        self.attack_manager.start_attack_for_client(client_index, attack_type)
        self._update_attacks_table()

    def _stop_attack(self, attack_id=None, _=None):
        """
        Остановка атаки.
        Если attack_id передан — останавливается конкретная атака.
        Если attack_id не передан — останавливается выбранная в таблице атака.
        Если ничего не выбрано — можно остановить все атаки.
        """
        if attack_id is None:
            selected_row = self.attack_table.currentRow()
            if selected_row < 0:
                # Если нет выбора, остановить все атаки
                stopped_any = False
                for aid in list(self.attack_manager.active_attacks.keys()):
                    stopped = self.attack_manager.stop_attack(aid)
                    stopped_any = stopped_any or stopped
                stopped = stopped_any
            else:
                # Получаем attack_id по выбранной строке
                attack_keys = list(self.attack_manager.active_attacks.keys())
                if selected_row < len(attack_keys):
                    attack_id = attack_keys[selected_row]
                    stopped = self.attack_manager.stop_attack(attack_id)
                else:
                    stopped = False
        else:
            # Остановка по переданному ID
            stopped = self.attack_manager.stop_attack(attack_id)

        if stopped:
            self.live_log.appendPlainText("[ATTACK] Атака остановлена")
        else:
            self.live_log.appendPlainText("[ATTACK] Нет активных атак")

        # Обновляем таблицу после остановки
        self._update_attacks_table()

    # ------------------------------------------------------------
    # Logs tab
    # ------------------------------------------------------------
    def _logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        layout.addWidget(self.logs_view)
        tab.setLayout(layout)
        return tab

    # ------------------------------------------------------------
    # Server control
    # ------------------------------------------------------------
    def _start_server(self):
        try:
            self.server.start()
            self.live_log.appendPlainText("[SERVER] Сервер запущен")
        except Exception as e:
            self.live_log.appendPlainText(f"[ERROR] Не удалось запустить сервер: {e}")

    # ------------------------------------------------------------
    # Proxy control
    # ------------------------------------------------------------
    def _start_proxy(self):
        self.proxy_manager.start()
        self.live_log.appendPlainText("[PROXY] Прокси запущен")

    def _stop_proxy(self):
        self.proxy_manager.stop()
        self.live_log.appendPlainText("[PROXY] Прокси остановлен")

    # ------------------------------------------------------------
    # Client control
    # ------------------------------------------------------------
    def _add_client(self):
        default_rate = 10
        if self.client_manager.add_client(default_rate):
            self.live_log.appendPlainText(f"[CLIENT] Клиент добавлен (скорость {default_rate} пак/с)")
        self._update_client_table()

    def _remove_client(self):
        if self.client_manager.remove_last_client():
            self.live_log.appendPlainText("[CLIENT] Клиент удалён")
        self._update_client_table()

    # ------------------------------------------------------------
    # Update tables & logs
    # ------------------------------------------------------------
    def _update_client_table(self):
        clients = self.client_manager.clients
        self.active_clients_label.setText(f"Активных клиентов: {len(clients)}")
        self.client_table.setRowCount(len(clients))

        # --- Обновляем список клиентов только если изменилось количество ---
        if self.client_select.count() != len(clients):
            self.client_select.clear()
            for idx in range(len(clients)):
                self.client_select.addItem(f"Client {idx + 1}")

        for idx, c in enumerate(clients):
            self.client_table.setItem(idx, 0, QTableWidgetItem(f"Client {idx + 1}"))
            self.client_table.setItem(idx, 1, QTableWidgetItem(str(c.sent_packets)))
            self.client_table.setItem(idx, 2, QTableWidgetItem(str(c.total_sent_packets)))

            spin = QSpinBox()
            spin.setRange(1, 2000)
            spin.setValue(int(c.packets_per_second))
            spin.valueChanged.connect(lambda val, client=c: client.update_rate(val))
            self.client_table.setCellWidget(idx, 3, spin)

    def _update_attacks_table(self):
        attacks = self.attack_manager.list_attacks()
        self.attack_table.setRowCount(len(attacks))
        for row, attack in enumerate(attacks):
            attack_id = attack["id"]
            self.attack_table.setItem(row, 0, QTableWidgetItem(str(attack_id)))
            self.attack_table.setItem(row, 1, QTableWidgetItem(f"Client {attack['client_index'] + 1}"))
            self.attack_table.setItem(row, 2, QTableWidgetItem(attack["attack_type"]))

            btn_stop = QPushButton("Остановить")
            btn_stop.clicked.connect(lambda _, a_id=attack_id: self._stop_attack(a_id))
            self.attack_table.setCellWidget(row, 3, btn_stop)

    def _update_logs(self):
        try:
            logs = self.logger.read_logs()
            self.logs_view.setPlainText("".join(logs))
        except:
            pass

    # ------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------
    def _update_graph(self):
        total_tps = self.client_manager.get_total_packets_per_second()
        self.data_broker.update_packets(total_tps)

        history = self.data_broker.get_packets_history()
        if history:
            t_now = time.time()
            x = [(t - t_now) / 60.0 for t, _ in history]
            y = [v for _, v in history]

            self.plot_curve.setData(x=x, y=y)
            self.plot_widget.setXRange(-5, 0)
            self.packets_label.setText(f"Пакетов в секунду: {total_tps}")
