"""
unbanner.py - Scheduled auto-unban with progressive backoff.

Checks every 30 seconds for IPs whose ban duration has expired.
Sends a Slack notification on every unban.
"""

import time
import logging
from datetime import datetime
from monitor import SharedState

logger = logging.getLogger("unbanner")


class Unbanner:
    """
    Runs in its own thread.
    Periodically scans banned_ips and releases expired bans.
    """

    def __init__(self, config: dict, state: SharedState):
        self.config = config
        self.state = state
        self.check_interval = 30  # seconds

        from blocker import Blocker
        from notifier import SlackNotifier
        self.blocker = Blocker(config, state)
        self.notifier = SlackNotifier(config)

    def run(self):
        logger.info("Unbanner started (checking every 30s)")
        while True:
            try:
                self._check_unbans()
            except Exception as e:
                logger.error(f"Unbanner error: {e}", exc_info=True)
            time.sleep(self.check_interval)

    def _check_unbans(self):
        now = time.time()
        to_unban = []

        with self.state.lock:
            for ip, info in list(self.state.banned_ips.items()):
                banned_until = info.get("banned_until", float("inf"))
                if banned_until == float("inf"):
                    continue  # permanent ban
                if now >= banned_until:
                    to_unban.append((ip, info))

        for ip, info in to_unban:
            logger.info(f"Auto-unbanning ip={ip} (ban expired)")
            self.blocker.unban(ip, reason="ban_expired")

            # Send Slack unban notification
            ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            ban_count = info.get("ban_count", 1)
            original_duration = info.get("duration_str", "unknown")
            reason = info.get("reason", "unknown")

            # Determine next ban duration if re-offends
            ban_schedule = self.config["blocking"]["ban_durations_minutes"]
            next_idx = min(ban_count, len(ban_schedule) - 1)
            next_dur = ban_schedule[next_idx]
            next_dur_str = "PERMANENT" if next_dur == -1 else f"{next_dur}min"

            self.notifier.send_unban_alert(
                ip=ip,
                timestamp=ts,
                original_duration=original_duration,
                ban_count=ban_count,
                next_ban_duration=next_dur_str,
                reason=reason
            )
