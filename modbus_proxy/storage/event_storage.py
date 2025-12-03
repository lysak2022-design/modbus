class EventStorage:
    def __init__(self):
        self.events = []

    def add_event(self, event: dict):
        self.events.append(event)

    def get_events(self):
        return self.events
