"""
baseline.py - Rolling baseline calculator.

Every 60 seconds, recomputes mean and stddev from:
  1. The last 30 minutes of per-second request counts (baseline_history).
  2. Per-hour slots: if the current hour has >= 30 samples, prefer it.

Floor values prevent near-zero baselines from causing false positives.
"""

import time
import math
import logging
from datetime import datetime
from monitor import SharedState

logger = logging.getLogger("baseline")


def _mean(values: list) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: list, mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


class BaselineCalculator:
    """
    Runs in its own thread.
    Recalculates effective_mean and effective_stddev every recalc_interval seconds.
    Writes structured audit log on each recalculation.
    """

    def __init__(self, config: dict, state: SharedState):
        self.config = config
        self.state = state
        self.recalc_interval = config["detection"]["baseline_recalc_interval_seconds"]
        self.min_samples = config["detection"]["min_baseline_samples"]
        self.mean_floor = config["detection"]["baseline_mean_floor"]
        self.stddev_floor = config["detection"]["baseline_stddev_floor"]
        self.audit_path = config["log"]["audit_path"]
        self._recalc_count = 0

    def _write_audit(self, mean: float, stddev: float, sample_count: int, source: str):
        """Write a baseline recalculation audit entry."""
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"[{ts}] BASELINE_RECALC ip=global | condition=recalc | "
            f"rate={mean:.4f} | baseline={mean:.4f} | stddev={stddev:.4f} | "
            f"samples={sample_count} | source={source} | duration=N/A\n"
        )
        try:
            with open(self.audit_path, "a") as f:
                f.write(line)
        except Exception as e:
            logger.warning(f"Could not write audit log: {e}")
        logger.info(
            f"BASELINE_RECALC source={source} mean={mean:.4f} "
            f"stddev={stddev:.4f} samples={sample_count}"
        )

    def _recalculate(self):
        now = time.time()
        current_hour = datetime.fromtimestamp(now).hour

        with self.state.lock:
            # Extract counts from rolling 30-min window
            rolling_counts = [count for (_, count) in self.state.baseline_history]

            # Extract current-hour slot counts
            hourly_counts = list(self.state.hourly_slots.get(current_hour, []))

        # Decision: prefer current-hour data if it has enough samples
        if len(hourly_counts) >= self.min_samples:
            counts = hourly_counts
            source = f"hourly_slot_hour={current_hour}"
        elif len(rolling_counts) >= self.min_samples:
            counts = rolling_counts
            source = "rolling_30min"
        else:
            # Not enough data yet — use floor values
            logger.debug(
                f"Insufficient baseline data "
                f"(rolling={len(rolling_counts)}, hourly={len(hourly_counts)}) "
                f"— using floor values"
            )
            with self.state.lock:
                self.state.effective_mean = self.mean_floor
                self.state.effective_stddev = self.stddev_floor
                self.state.baseline_last_updated = now
            return

        m = _mean(counts)
        s = _stddev(counts, m)

        # Apply floor values
        effective_mean = max(m, self.mean_floor)
        effective_stddev = max(s, self.stddev_floor)

        with self.state.lock:
            self.state.effective_mean = effective_mean
            self.state.effective_stddev = effective_stddev
            self.state.baseline_last_updated = now

        self._recalc_count += 1
        self._write_audit(effective_mean, effective_stddev, len(counts), source)

    def run(self):
        """Run the recalculation loop every recalc_interval seconds."""
        logger.info(
            f"Baseline calculator started "
            f"(recalc every {self.recalc_interval}s, "
            f"min_samples={self.min_samples})"
        )
        # Initial short delay to let some traffic accumulate
        time.sleep(10)

        while True:
            try:
                self._recalculate()
            except Exception as e:
                logger.error(f"Baseline recalculation error: {e}", exc_info=True)
            time.sleep(self.recalc_interval)
