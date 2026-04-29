# HNG Stage 3 — Anomaly Detection & DDoS Protection Engine

**Live Server IP:** http://52.6.62.133  
**Metrics Dashboard:** http://monitor.hngayotomiwa.online  
**GitHub:** https://github.com/Zaamaar/hng-stage-3  
**Blog Post:** BLOG_URL_HERE

## What This Does

Real-time HTTP traffic anomaly detection engine. Watches every Nginx request, learns normal traffic patterns, and automatically blocks anomalous IPs via iptables. Slack alerts fire on ban, unban, and global anomaly events.

## Why Python?

collections.deque gives O(1) sliding window operations. Threading handles 4 daemon threads cleanly. subprocess calls iptables directly. Flask serves the metrics dashboard.

## How the Sliding Window Works

Every request timestamp is appended to a per-IP deque and a global deque. Before every rate calculation, stale entries older than 60 seconds are evicted from the left with popleft(). Rate = len(deque) / window_seconds. No counters, no resets.

## How the Baseline Works

Every second, the request count is stored in a 30-minute rolling deque and also bucketed by hour. Every 60 seconds, mean and stddev are recalculated. Priority: hourly slot (30+ samples) then rolling window then floor values (mean=1.0, stddev=0.5).

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
