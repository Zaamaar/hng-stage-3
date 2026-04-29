"""
blocker.py - iptables-based IP blocking with backoff ban schedule.

Ban schedule: 10 min -> 30 min -> 2 hours -> permanent (-1).
Writes structured audit log entries for every ban.
"""

import subprocess
import time
import logging
from datetime import datetime
from monitor import SharedState

logger = logging.getLogger("blocker")


class Blocker:
    """
    Manages iptables DROP rules for banned IPs.
    Tracks ban count per IP to implement progressive backoff.
    """

    def __init__(self, config: dict, state: SharedState):
        self.config = config
        self.state = state
        self.audit_path = config["log"]["audit_path"]
        self.ban_schedule = config["blocking"]["ban_durations_minutes"]

    def _run_iptables(self, args: list) -> bool:
        """Execute an iptables command. Returns True on success."""
        try:
            result = subprocess.run(
                ["iptables"] + args,
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.warning(f"iptables error: {result.stderr.strip()}")
                return False
            return True
        except FileNotFoundError:
            logger.error("iptables not found — is this running with NET_ADMIN capability?")
            return False
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out")
            return False
        except Exception as e:
            logger.error(f"iptables unexpected error: {e}")
            return False

    def ban(self, ip: str, reason: str, rate: float, mean: float) -> str:
        """
        Add iptables DROP rule for ip.
        Returns human-readable ban duration string.
        """
        now = time.time()

        with self.state.lock:
            existing = self.state.banned_ips.get(ip)
            if existing:
                ban_count = existing.get("ban_count", 1)
            else:
                ban_count = 0

            # Determine duration from backoff schedule
            idx = min(ban_count, len(self.ban_schedule) - 1)
            duration_min = self.ban_schedule[idx]

            if duration_min == -1:
                banned_until = float("inf")
                duration_str = "PERMANENT"
            else:
                banned_until = now + duration_min * 60
                duration_str = f"{duration_min}min"

            self.state.banned_ips[ip] = {
                "ban_count": ban_count + 1,
                "banned_until": banned_until,
                "reason": reason,
                "rate": rate,
                "banned_at": now,
                "duration_str": duration_str,
            }

        # Add iptables rule
        success = self._run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"])
        if success:
            logger.warning(f"BANNED ip={ip} duration={duration_str} reason={reason}")
        else:
            logger.error(f"Failed to add iptables rule for ip={ip}")

        # Write audit log
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._write_audit("BAN", ip, reason, rate, mean, duration_str, ts)

        return duration_str

    def unban(self, ip: str, reason: str = "scheduled_unban"):
        """Remove iptables DROP rule for ip."""
        # Remove all matching iptables rules (may have duplicates)
        for _ in range(3):
            result = self._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
            if not result:
                break

        now = time.time()
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        with self.state.lock:
            ban_info = self.state.banned_ips.pop(ip, {})
            rate = ban_info.get("rate", 0.0)
            mean = self.state.effective_mean

        logger.info(f"UNBANNED ip={ip} reason={reason}")
        self._write_audit("UNBAN", ip, reason, rate, mean, "N/A", ts)

    def _write_audit(self, action: str, ip: str, condition: str,
                     rate: float, baseline: float, duration: str, ts: str):
        """Write a structured audit log entry."""
        line = (
            f"[{ts}] {action} ip={ip} | condition={condition} | "
            f"rate={rate:.4f} | baseline={baseline:.4f} | duration={duration}\n"
        )
        try:
            with open(self.audit_path, "a") as f:
                f.write(line)
        except Exception as e:
            logger.warning(f"Could not write audit log: {e}")
