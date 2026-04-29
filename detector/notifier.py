"""
notifier.py - Slack webhook notifications.

Sends structured alerts for:
  - IP ban (with condition, rate, baseline, duration)
  - Global anomaly alert
  - IP unban
"""

import json
import logging
import requests
from datetime import datetime

logger = logging.getLogger("notifier")


class SlackNotifier:
    """Sends formatted Slack messages via webhook."""

    def __init__(self, config: dict):
        self.webhook_url = config["slack"]["webhook_url"]

    def _send(self, payload: dict) -> bool:
        """POST payload to Slack webhook. Returns True on success."""
        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=8
            )
            if response.status_code != 200:
                logger.warning(
                    f"Slack returned {response.status_code}: {response.text[:200]}"
                )
                return False
            return True
        except requests.exceptions.Timeout:
            logger.error("Slack webhook request timed out")
            return False
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False

    def send_ban_alert(self, ip: str, condition: str, rate: float,
                       mean: float, stddev: float, timestamp: str, ban_duration: str):
        """Send IP ban notification."""
        payload = {
            "text": f":rotating_light: *IP BANNED* — `{ip}`",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 ANOMALY DETECTED — IP BANNED"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n`{ban_duration}`"},
                        {"type": "mrkdwn", "text": f"*Condition Fired:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Current Rate:*\n`{rate:.2f} req/s`"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n`{mean:.2f} req/s`"},
                        {"type": "mrkdwn", "text": f"*Baseline StdDev:*\n`{stddev:.2f}`"},
                        {"type": "mrkdwn", "text": f"*Timestamp (UTC):*\n`{timestamp}`"},
                        {"type": "mrkdwn", "text": f"*Action:*\niptables DROP rule added"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "HNG Anomaly Detection Engine | cloud.ng"}
                    ]
                }
            ]
        }
        ok = self._send(payload)
        if ok:
            logger.info(f"Slack ban alert sent for ip={ip}")

    def send_unban_alert(self, ip: str, timestamp: str, original_duration: str,
                         ban_count: int, next_ban_duration: str, reason: str):
        """Send IP unban notification."""
        payload = {
            "text": f":white_check_mark: *IP UNBANNED* — `{ip}`",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ IP UNBANNED — Auto-Release"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Reason:*\n{reason}"},
                        {"type": "mrkdwn", "text": f"*Original Duration:*\n`{original_duration}`"},
                        {"type": "mrkdwn", "text": f"*Total Bans (this IP):*\n`{ban_count}`"},
                        {"type": "mrkdwn", "text": f"*Next Ban If Re-offends:*\n`{next_ban_duration}`"},
                        {"type": "mrkdwn", "text": f"*Timestamp (UTC):*\n`{timestamp}`"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "HNG Anomaly Detection Engine | cloud.ng"}
                    ]
                }
            ]
        }
        ok = self._send(payload)
        if ok:
            logger.info(f"Slack unban alert sent for ip={ip}")

    def send_global_alert(self, condition: str, rate: float,
                           mean: float, stddev: float, timestamp: str):
        """Send global traffic anomaly alert (no block — alert only)."""
        payload = {
            "text": f":warning: *GLOBAL TRAFFIC ANOMALY* — rate={rate:.2f} req/s",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ GLOBAL TRAFFIC ANOMALY"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Condition Fired:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Global Rate:*\n`{rate:.2f} req/s`"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n`{mean:.2f} req/s`"},
                        {"type": "mrkdwn", "text": f"*Baseline StdDev:*\n`{stddev:.2f}`"},
                        {"type": "mrkdwn", "text": f"*Timestamp (UTC):*\n`{timestamp}`"},
                        {"type": "mrkdwn", "text": f"*Action:*\nSlack alert only (distributed attack)"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "HNG Anomaly Detection Engine | cloud.ng"}
                    ]
                }
            ]
        }
        ok = self._send(payload)
        if ok:
            logger.info(f"Slack global alert sent: rate={rate:.2f}")
