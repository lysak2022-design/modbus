# modules/proxy_module.py

class ProxyManager:
    """
    Заглушка для ProxyManager, совместимая с GUI.
    Принимает сервер в качестве параметра.
    """

    def __init__(self, server):
        self.server = server
        self.running = False

    def start(self):
        print("[ProxyManager] start() called")
        self.running = True

    def stop(self):
        print("[ProxyManager] stop() called")
        self.running = False
