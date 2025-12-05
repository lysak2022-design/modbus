# app.py
import sys
from PyQt6.QtWidgets import QApplication
from ui.main_window import ModbusGUI

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModbusGUI()
    window.show()
    sys.exit(app.exec())
