# main.py
import sys
from PyQt6.QtWidgets import QApplication, QDialog
from ui.login_window import LoginWindow
from ui.main_window import ModbusProxyGUI

def main():
    app = QApplication(sys.argv)

    login = LoginWindow()
    if login.exec() == QDialog.DialogCode.Accepted:  # <-- здесь исправлено
        role = login.user_role
        window = ModbusProxyGUI()

        # Ограничение прав по роли
        if role == "viewer":
            window.server_btn.setEnabled(False)
            window.start_btn.setEnabled(False)
            window.stop_btn.setEnabled(False)
            window.apply_attack_btn.setEnabled(False)
            window.stop_attack_btn.setEnabled(False)

        window.show()
        sys.exit(app.exec())

if __name__ == "__main__":
    main()
