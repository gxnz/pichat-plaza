import threading, time
import cherrypy

class ResumableTimer:

    def __init__(self, timeout, callback):
        self.timeout = timeout
        self.callback = callback
        self.timer = threading.Timer(timeout, callback)
        self.startTime = time.time()

    def start(self):
        self.timer.start()

    def pause(self):
        self.timer.cancel()
        self.pauseTime = time.time()

    def resume(self):
        self.timer = threading.Timer(
            self.timeout - (self.pauseTime - self.startTime),
            self.callback)

        self.timer.start()