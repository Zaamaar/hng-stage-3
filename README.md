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

Each IP address gets its own collections.deque that stores the Unix timestamps of every request that IP has made. A single global deque stores timestamps for all requests regardless of source. Neither deque has a fixed size limit; instead, stale entries are evicted on every log entry processed.

When a new log entry arrives, the current time (time.time()) is appended to both the IP-specific deque and the global deque. A cutoff value is then calculated as now - 60, representing the start of the 60-second window. Any timestamp at the left of the deque that is older than the cutoff is removed with popleft() until the oldest remaining entry is within the window. Because timestamps are always appended in chronological order, this eviction is always O(k) where k is the number of expired entries, not O(n) over the whole deque.

The length of the deque after eviction is the IP's request rate for the current 60-second window. This value is what gets compared against the baseline.

The same structure is used to track 4xx and 5xx error responses per IP, using a separate error deque per IP and one global error deque.

## How the Baseline Works

The baseline answers the question: what is the normal request rate on this system right now? It maintains two data structures simultaneously.

The first is a collections.deque with maxlen=1800. Each slot holds the total request count for one second. Because the deque is capped at 1800 entries, it automatically evicts counts older than 30 minutes when new ones are appended. This is the rolling window.

The second is a dictionary keyed by hour (0 through 23), where each value is a list of per-second counts recorded during that hour. This captures the natural traffic rhythm of the day: traffic at 2am behaves differently from traffic at 2pm. Each hourly list is trimmed to a maximum of 3600 entries (one hour of per-second samples) to bound memory usage.

Every time a new count is added via add_count(), the baseline checks whether 60 seconds have elapsed since the last recalculation. If so, it recomputes the mean and standard deviation using Python's statistics.mean and statistics.stdev. The data source for recalculation is chosen as follows: if the current hour's slot has more than 60 data points, it uses that slot because it reflects the traffic pattern for this specific time of day. Otherwise it falls back to the full 30-minute rolling window.

To prevent division by zero in the z-score formula, both mean and stddev are floored at 1.0 and 0.5 regardless of what the calculation produces.

mean=1.0, stddev=0.5).

## How Detection Works
For every log entry processed, the detector computes a z-score for the source IP:

z_score = (ip_rate - mean) / stddev

Where ip_rate is the number of requests from that IP in the last 60 seconds, and mean and stddev come from the baseline.

An IP is flagged as anomalous if either of two conditions is true:

The z-score exceeds 3.0. This means the IP's request rate is more than three standard deviations above the baseline mean, which is statistically unusual under normal traffic distributions.
The raw rate exceeds 5 times the baseline mean. This catches burst attackers who ramp up so fast that the standard deviation has not had time to widen to reflect the change.
A third condition modifies the z-score threshold rather than triggering a ban directly. If the proportion of 4xx and 5xx responses from an IP exceeds three times the global error proportion across all traffic, the z-score threshold for that IP is tightened from 3.0 to 2.0. This makes the detector more sensitive to IPs that are not just sending many requests but are also generating a high error rate, which is a common pattern in credential-stuffing and path-scanning attacks.

## How iptables Blocking Works
iptables is the Linux kernel's built-in packet filtering firewall. When the detector decides to block an IP, it runs the following command inside the container:

```
iptables -I DOCKER-USER -s <ip> -j DROP
```

The `-I DOCKER-USER` flag inserts the rule at the top of the `DOCKER-USER` chain, which Docker processes before its own forwarding rules, ensuring traffic from a blocked IP is dropped even for containerised services. The `-s <ip>` flag matches packets from the specified source address. The `-j DROP` target silently discards the packet without sending any response to the sender.

The system applies escalating ban durations based on how many times an IP has been banned before:

| Offence number | Ban duration |
|----------------|--------------|
| 1st            | 10 minutes   |
| 2nd            | 30 minutes   |
| 3rd            | 2 hours      |
| 4th and beyond | Permanent    |

A background thread checks every 30 seconds whether any active ban has expired. When a ban expires, the rule is removed with:

```
iptables -D DOCKER-USER -s <ip> -j DROP
```

The IP is then removed from the in-memory ban registry. A Slack alert is sent noting the next ban duration that will apply if the IP re-offends. Permanent bans are never automatically lifted.

---


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
