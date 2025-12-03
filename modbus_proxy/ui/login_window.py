# ui/login_window.py
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox

class LoginWindow(QDialog):
    """
    Диалоговое окно авторизации.
    Поддерживает роли: admin и viewer.
    Возвращает выбранную роль через self.user_role после accept().
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Авторизация")
        self.resize(300, 150)
        self.user_role = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        # Метка и поле для логина
        self.username_label = QLabel("Логин:")
        layout.addWidget(self.username_label)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Введите логин")
        layout.addWidget(self.username_edit)

        # Метка и поле для пароля
        self.password_label = QLabel("Пароль:")
        layout.addWidget(self.password_label)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Введите пароль")
        layout.addWidget(self.password_edit)

        # Кнопка входа
        self.login_btn = QPushButton("Вход")
        self.login_btn.clicked.connect(self._check_login)
        layout.addWidget(self.login_btn)

        self.setLayout(layout)

    def _check_login(self):
        user = self.username_edit.text().strip()
        pwd = self.password_edit.text().strip()

        # Проверка на админа
        if user == "1" and pwd == "1":
            self.user_role = "admin"
            self.accept()
        # Проверка на обычного пользователя
        elif user.lower() == "viewer" and pwd == "1":
            self.user_role = "viewer"
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль")
            self.username_edit.clear()
            self.password_edit.clear()
            self.username_edit.setFocus()