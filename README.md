# HNG Stage 3 — Anomaly Detection & DDoS Protection Engine

**Live Server IP:** http://52.6.62.133  
**Metrics Dashboard:** http://monitor.hngayotomiwa.online  
**GitHub:** https://github.com/Zaamaar/hng-stage-3  
**Blog Post:** https://medium.com/@ayotomiwavictor1/how-i-built-a-real-time-ddos-detection-engine-from-scratch-b252db662ac0

## What This Does

Real-time HTTP traffic anomaly detection engine. Watches every Nginx request, learns normal traffic patterns, and automatically blocks anomalous IPs via iptables. Slack alerts fire on ban, unban, and global anomaly events.

## Why Python?

Python was chosen for this project for several reasons. Python ships with a rich standard library that covers most of what this daemon needs: collections.deque for sliding windows, statistics for mean and standard deviation, threading for background workers, and http.server for the dashboard. The only third-party dependencies are pyyaml for config parsing, requests for Slack notifications, and psutil for system metrics. Python is also easy to read and audit, which matters for a security-adjacent tool where the logic must be transparent and verifiable. Performance is not a bottleneck here because the detection loop processes one log line at a time at the speed Nginx writes them, which is far below Python's throughput ceiling for this kind of I/O-bound work.

## Architecture
The system is composed of three Docker services connected on a shared bridge network:

Nginx receives all incoming HTTP requests on port 80 and proxies them to the Nextcloud container. It writes every request as a JSON object to a shared Docker volume at /var/log/nginx/hng-access.log. Each log entry contains the source IP, timestamp, HTTP method, path, response status, and response size.

Nextcloud is the protected application. It sits behind Nginx and never receives direct external traffic.

Detector mounts the Nginx log volume in read-only mode and tails the log file as a stream. For every new log entry it maintains sliding windows per IP, computes anomaly scores against a rolling baseline, and takes action when thresholds are exceeded. The detector container is given the NET_ADMIN capability so it can issue iptables commands that affect the host network.

The full flow for a single request is:

Client request
  -> Nginx (logs JSON entry to shared volume)
  -> Detector reads new log line
  -> Updates sliding windows and baseline
  -> Runs anomaly checks
  -> If anomaly: iptables DROP rule added, Slack alert sent, audit log written
  -> Dashboard reflects updated state within 3 seconds

## How the Sliding Window Works

Every request timestamp is appended to a per-IP deque and a global deque. Before every rate calculation, stale entries older than 60 seconds are evicted from the left with popleft(). Rate = len(deque) / window_seconds. No counters, no resets.

## How the Baseline Works

The baseline answers the question: what is the normal request rate on this system right now? It maintains two data structures simultaneously.

The first is a collections.deque with maxlen=1800. Each slot holds the total request count for one second. Because the deque is capped at 1800 entries, it automatically evicts counts older than 30 minutes when new ones are appended. This is the rolling window.

The second is a dictionary keyed by hour (0 through 23), where each value is a list of per-second counts recorded during that hour. This captures the natural traffic rhythm of the day: traffic at 2am behaves differently from traffic at 2pm. Each hourly list is trimmed to a maximum of 3600 entries (one hour of per-second samples) to bound memory usage.

Every time a new count is added via add_count(), the baseline checks whether 60 seconds have elapsed since the last recalculation. If so, it recomputes the mean and standard deviation using Python's statistics.mean and statistics.stdev. The data source for recalculation is chosen as follows: if the current hour's slot has more than 60 data points, it uses that slot because it reflects the traffic pattern for this specific time of day. Otherwise it falls back to the full 30-minute rolling window.

To prevent division by zero in the z-score formula, both mean and stddev are floored at 1.0 and 0.5 regardless of what the calculation produces.

mean=1.0, stddev=0.5).

## How Detection Works

Z-score: (ip_rate - mean) / stddev > 3.0 triggers a ban. Rate multiplier: ip_rate > 5x mean also triggers. Error surge tightens thresholds to z>2.0 and 3x. Global traffic check fires Slack-only alert.

Ban backoff: 10min, 30min, 2hr, permanent.

## Setup

    sudo apt update && sudo apt install -y docker.io git curl apache2-utils
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.6/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    git clone https://github.com/Zaamaar/hng-stage-3.git
    cd hng-stage-3
    cp detector/config.example.yaml detector/config.yaml
    # Edit config.yaml and add your Slack webhook
    docker-compose up -d --build

## Simulate Attack

    ab -n 3000 -c 300 -H "X-Forwarded-For: 5.6.7.8" http://localhost/
    sudo iptables -L INPUT -n
    docker exec hng-detector cat /app/data/audit.log

## Structure

    hng-stage-3/
    ├── docker-compose.yml
    ├── nginx/nginx.conf
    ├── detector/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── config.example.yaml
    │   ├── main.py
    │   ├── monitor.py
    │   ├── baseline.py
    │   ├── detector.py
    │   ├── blocker.py
    │   ├── unbanner.py
    │   ├── notifier.py
    │   └── dashboard.py
    └── README.md
