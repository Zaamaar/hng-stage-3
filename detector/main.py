"""
HNG Anomaly Detection Engine - Main Entry Point
Starts all threads: log monitor, baseline calculator, unbanner, dashboard.
"""

import threading
import time
import logging
import yaml
import os
import sys

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("main")


def load_config():
    config_path = os.environ.get("CONFIG_PATH", "/app/config.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def wait_for_log(log_path: str, timeout: int = 120):
    """Wait until the nginx log file exists before starting."""
    logger.info(f"Waiting for log file: {log_path}")
    elapsed = 0
    while not os.path.exists(log_path):
        time.sleep(2)
        elapsed += 2
        if elapsed >= timeout:
            logger.warning(f"Log file not found after {timeout}s — creating placeholder")
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            open(log_path, "a").close()
            return
    logger.info(f"Log file found: {log_path}")


def main():
    logger.info("=" * 60)
    logger.info("  HNG Anomaly Detection Engine Starting")
    logger.info("=" * 60)

    config = load_config()
    log_path = config["log"]["path"]
    wait_for_log(log_path)

    # Shared state object passed to all modules
    from monitor import SharedState
    state = SharedState(config)

    # Import all modules
    from monitor import LogMonitor
    from baseline import BaselineCalculator
    from unbanner import Unbanner
    from dashboard import DashboardServer

    # Start baseline calculator thread
    baseline_calc = BaselineCalculator(config, state)
    t_baseline = threading.Thread(target=baseline_calc.run, daemon=True, name="baseline")
    t_baseline.start()
    logger.info("Baseline calculator thread started")

    # Start unbanner thread
    unbanner = Unbanner(config, state)
    t_unban = threading.Thread(target=unbanner.run, daemon=True, name="unbanner")
    t_unban.start()
    logger.info("Unbanner thread started")

    # Start dashboard server thread
    dashboard = DashboardServer(config, state)
    t_dashboard = threading.Thread(target=dashboard.run, daemon=True, name="dashboard")
    t_dashboard.start()
    logger.info(f"Dashboard server thread started on port {config['dashboard']['port']}")

    # Start log monitor (blocking - runs in main thread loop via its own thread)
    monitor = LogMonitor(config, state)
    t_monitor = threading.Thread(target=monitor.run, daemon=True, name="monitor")
    t_monitor.start()
    logger.info("Log monitor thread started")

    logger.info("All systems operational. Watching for anomalies...")

    # Keep main thread alive
    try:
        while True:
            time.sleep(10)
            # Health check log
            logger.info(
                f"[HEALTH] uptime={state.get_uptime():.0f}s | "
                f"global_rps={state.get_global_rps():.2f} | "
                f"banned_ips={len(state.banned_ips)} | "
                f"baseline_mean={state.effective_mean:.3f} | "
                f"baseline_stddev={state.effective_stddev:.3f}"
            )
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
        sys.exit(0)


if __name__ == "__main__":
    main()
