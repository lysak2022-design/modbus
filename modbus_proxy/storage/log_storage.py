class LogStorage:
    def __init__(self):
        self.logs = []

    def add_log(self, text: str):
        self.logs.append(text)

    def get_logs(self):
        return self.logs
