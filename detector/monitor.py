import json
import time
import threading
import logging
import os
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger("monitor")


class SharedState:
    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.ip_windows = defaultdict(deque)
        self.global_window = deque()
        self.ip_error_windows = defaultdict(deque)
        self.baseline_history = deque()
        self.hourly_slots = defaultdict(list)
        self.effective_mean = config["detection"]["baseline_mean_floor"]
        self.effective_stddev = config["detection"]["baseline_stddev_floor"]
        self.baseline_last_updated = 0.0
        self.banned_ips = {}
        self.top_ips = []
        self.total_requests = 0
        self._start_time = time.time()

    def get_uptime(self):
        return time.time() - self._start_time

    def get_global_rps(self):
        now = time.time()
        window_sec = self.config["detection"]["global_window_seconds"]
        with self.lock:
            cutoff = now - window_sec
            while self.global_window and self.global_window[0] < cutoff:
                self.global_window.popleft()
            return len(self.global_window) / window_sec

    def get_ip_rps(self, ip):
        now = time.time()
        window_sec = self.config["detection"]["per_ip_window_seconds"]
        with self.lock:
            dq = self.ip_windows[ip]
            cutoff = now - window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq) / window_sec

    def get_ip_error_rate(self, ip):
        now = time.time()
        window_sec = self.config["detection"]["per_ip_window_seconds"]
        with self.lock:
            dq = self.ip_error_windows[ip]
            cutoff = now - window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq) / window_sec

    def get_top_ips(self, n=10):
        now = time.time()
        window_sec = self.config["detection"]["per_ip_window_seconds"]
        cutoff = now - window_sec
        result = []
        with self.lock:
            for ip, dq in self.ip_windows.items():
                count = sum(1 for t in dq if t >= cutoff)
                if count > 0:
                    result.append((ip, count))
        result.sort(key=lambda x: x[1], reverse=True)
        return result[:n]


class LogMonitor:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.log_path = config["log"]["path"]
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location("anomaly_detector", "/app/detector.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.detector = mod.AnomalyDetector(config, state)
        self._current_second = 0
        self._current_second_count = 0
        self._window_ip = config["detection"]["per_ip_window_seconds"]
        self._window_global = config["detection"]["global_window_seconds"]
        self._baseline_window = config["detection"]["baseline_window_seconds"]

    def _parse_line(self, line):
        line = line.strip()
        if not line:
            return None
        try:
            entry = json.loads(line)
            ip_raw = entry.get("source_ip", "")
            if ip_raw and ip_raw != "-":
                ip = ip_raw.split(",")[0].strip()
            else:
                ip = "unknown"
            entry["source_ip"] = ip
            return entry
        except (json.JSONDecodeError, ValueError):
            return None

    def _record(self, entry):
        now = time.time()
        ip = entry["source_ip"]
        status = int(entry.get("status", 200))
        is_error = status >= 400
        cutoff_ip = now - self._window_ip
        cutoff_global = now - self._window_global

        with self.state.lock:
            dq = self.state.ip_windows[ip]
            while dq and dq[0] < cutoff_ip:
                dq.popleft()
            dq.append(now)

            gq = self.state.global_window
            while gq and gq[0] < cutoff_global:
                gq.popleft()
            gq.append(now)

            if is_error:
                eq = self.state.ip_error_windows[ip]
                while eq and eq[0] < cutoff_ip:
                    eq.popleft()
                eq.append(now)

            sec = int(now)
            if sec != self._current_second:
                if self._current_second > 0:
                    self.state.baseline_history.append(
                        (float(self._current_second), float(self._current_second_count))
                    )
                    hour = datetime.fromtimestamp(self._current_second).hour
                    self.state.hourly_slots[hour].append(float(self._current_second_count))
                    cutoff_b = now - self._baseline_window
                    while (self.state.baseline_history and
                           self.state.baseline_history[0][0] < cutoff_b):
                        self.state.baseline_history.popleft()
                self._current_second = sec
                self._current_second_count = 1
            else:
                self._current_second_count += 1

            self.state.total_requests += 1

    def run(self):
        logger.info(f"Starting log tail: {self.log_path}")
        while not os.path.exists(self.log_path):
            time.sleep(1)

        with open(self.log_path, "r") as f:
            f.seek(0, 2)
            logger.info("Tailing log from end of file")
            inode = os.fstat(f.fileno()).st_ino
            lines_processed = 0

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    try:
                        current_inode = os.stat(self.log_path).st_ino
                        if current_inode != inode:
                            logger.info("Log rotation detected — reopening")
                            f = open(self.log_path, "r")
                            inode = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        time.sleep(1)
                    continue

                entry = self._parse_line(line)
                if entry is None:
                    continue

                self._record(entry)
                lines_processed += 1
                if lines_processed % 1000 == 0:
                    logger.info(f"Processed {lines_processed} log lines")

                self.detector.check(entry)
