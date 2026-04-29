import time
import logging
import threading
from datetime import datetime

logger = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self._ip_cooldown = {}
        self._global_alert_cooldown = 0.0
        self._global_alert_interval = 30.0
        self.z_threshold = config["detection"]["z_score_threshold"]
        self.rate_mult = config["detection"]["rate_multiplier_threshold"]
        self.error_surge_mult = config["detection"]["error_surge_multiplier"]
        self.tight_z = config["detection"]["tightened_z_score"]
        self.tight_mult = config["detection"]["tightened_rate_multiplier"]
        self.min_samples = config["detection"]["min_baseline_samples"]

        from blocker import Blocker
        from notifier import SlackNotifier
        self.blocker = Blocker(config, state)
        self.notifier = SlackNotifier(config)

    def _z_score(self, rate, mean, stddev):
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def _is_anomalous(self, rate, mean, stddev, z_thresh, mult_thresh):
        z = self._z_score(rate, mean, stddev)
        if z > z_thresh:
            return True, f"z_score={z:.2f} > threshold={z_thresh}"
        if mean > 0 and rate > mult_thresh * mean:
            return True, f"rate={rate:.2f} > {mult_thresh}x mean={mean:.2f}"
        return False, ""

    def _has_error_surge(self, ip, baseline_mean):
        baseline_error_rate = max(baseline_mean * 0.05, 0.01)
        ip_error_rate = self.state.get_ip_error_rate(ip)
        return ip_error_rate >= self.error_surge_mult * baseline_error_rate

    def check(self, entry):
        now = time.time()
        ip = entry.get("source_ip", "unknown")

        with self.state.lock:
            mean = self.state.effective_mean
            stddev = self.state.effective_stddev
            has_baseline = self.state.baseline_last_updated > 0

        if not has_baseline:
            return

        with self.state.lock:
            if ip in self.state.banned_ips:
                return

        ip_rate = self.state.get_ip_rps(ip)
        last_trigger = self._ip_cooldown.get(ip, 0.0)

        if now - last_trigger >= 5.0:
            if self._has_error_surge(ip, mean):
                z_thresh = self.tight_z
                mult_thresh = self.tight_mult
                surge_note = " [TIGHTENED:error_surge]"
            else:
                z_thresh = self.z_threshold
                mult_thresh = self.rate_mult
                surge_note = ""

            anomalous, reason = self._is_anomalous(ip_rate, mean, stddev, z_thresh, mult_thresh)
            if anomalous:
                self._ip_cooldown[ip] = now
                logger.warning(f"IP ANOMALY: ip={ip} rate={ip_rate:.2f} mean={mean:.2f} {reason}{surge_note}")
                threading.Thread(
                    target=self._handle_ip_anomaly,
                    args=(ip, ip_rate, mean, stddev, reason + surge_note),
                    daemon=True
                ).start()

        global_rate = self.state.get_global_rps()
        if now - self._global_alert_cooldown >= self._global_alert_interval:
            anomalous, reason = self._is_anomalous(global_rate, mean, stddev,
                                                    self.z_threshold, self.rate_mult)
            if anomalous:
                self._global_alert_cooldown = now
                logger.warning(f"GLOBAL ANOMALY: rate={global_rate:.2f} mean={mean:.2f} {reason}")
                threading.Thread(
                    target=self._handle_global_anomaly,
                    args=(global_rate, mean, stddev, reason),
                    daemon=True
                ).start()

    def _handle_ip_anomaly(self, ip, rate, mean, stddev, reason):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        ban_duration = self.blocker.ban(ip, reason, rate, mean)
        self.notifier.send_ban_alert(
            ip=ip, condition=reason, rate=rate,
            mean=mean, stddev=stddev, timestamp=ts, ban_duration=ban_duration
        )

    def _handle_global_anomaly(self, rate, mean, stddev, reason):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.notifier.send_global_alert(
            condition=reason, rate=rate, mean=mean, stddev=stddev, timestamp=ts
        )
