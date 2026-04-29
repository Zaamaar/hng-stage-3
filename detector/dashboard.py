import time
import logging
import psutil
from datetime import datetime, timezone
from flask import Flask, jsonify, Response
from flask_cors import CORS
from monitor import SharedState
from collections import deque

logger = logging.getLogger("dashboard")

# Store historical baseline snapshots for the graph
_baseline_history_snapshots = deque(maxlen=120)  # up to 120 snapshots (2hrs at 1/min)


def _format_uptime(seconds):
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


class DashboardServer:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.port = config["dashboard"]["port"]
        self.app = Flask(__name__)
        CORS(self.app)
        self._last_snapshot = 0.0
        self._setup_routes()

    def _take_snapshot(self):
        now = time.time()
        if now - self._last_snapshot >= 60:
            with self.state.lock:
                mean = self.state.effective_mean
                stddev = self.state.effective_stddev
            ts = datetime.utcnow().strftime("%H:%M")
            _baseline_history_snapshots.append({
                "time": ts,
                "mean": round(mean, 4),
                "stddev": round(stddev, 4),
            })
            self._last_snapshot = now

    def _setup_routes(self):
        app = self.app
        state = self.state

        @app.route("/")
        def index():
            return Response(DASHBOARD_HTML, mimetype="text/html")

        @app.route("/api/metrics")
        def metrics():
            self._take_snapshot()
            now = time.time()
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            top_ips = state.get_top_ips(10)

            with state.lock:
                banned = []
                for ip, info in state.banned_ips.items():
                    banned_until = info.get("banned_until", float("inf"))
                    if banned_until == float("inf"):
                        remaining = "PERMANENT"
                    else:
                        rem = max(0, banned_until - now)
                        remaining = f"{rem:.0f}s"
                    banned.append({
                        "ip": ip,
                        "reason": info.get("reason", "unknown"),
                        "ban_count": info.get("ban_count", 1),
                        "duration": info.get("duration_str", "unknown"),
                        "remaining": remaining,
                        "banned_at": datetime.fromtimestamp(
                            info.get("banned_at", now), tz=timezone.utc
                        ).strftime("%H:%M:%S UTC"),
                    })
                effective_mean = state.effective_mean
                effective_stddev = state.effective_stddev
                total_requests = state.total_requests
                baseline_updated = state.baseline_last_updated

            global_rps = state.get_global_rps()
            uptime = state.get_uptime()
            baseline_age = now - baseline_updated if baseline_updated > 0 else -1

            return jsonify({
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "uptime_seconds": round(uptime),
                "uptime_human": _format_uptime(uptime),
                "global_rps": round(global_rps, 3),
                "total_requests": total_requests,
                "top_ips": [{"ip": ip, "rps": round(count/60, 3), "count_60s": count} for ip, count in top_ips],
                "banned_ips": banned,
                "banned_count": len(banned),
                "baseline": {
                    "effective_mean": round(effective_mean, 4),
                    "effective_stddev": round(effective_stddev, 4),
                    "last_updated_seconds_ago": round(baseline_age, 1) if baseline_age >= 0 else None,
                    "history": list(_baseline_history_snapshots),
                },
                "system": {
                    "cpu_percent": cpu,
                    "memory_percent": mem.percent,
                    "memory_used_mb": round(mem.used/1024/1024, 1),
                    "memory_total_mb": round(mem.total/1024/1024, 1),
                }
            })

        @app.route("/health")
        def health():
            return jsonify({"status": "ok", "uptime": round(state.get_uptime())})

    def run(self):
        logger.info(f"Dashboard starting on port {self.port}")
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.WARNING)
        self.app.run(host="0.0.0.0", port=self.port, threaded=True, use_reloader=False)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detection Engine</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');
:root{--bg:#020408;--surface:#0a0f1a;--surface2:#0f1624;--border:#1a2535;--accent:#00d4ff;--accent3:#00ff88;--accent4:#ffb800;--text:#e0eaf5;--muted:#5a7a9a;--danger:#ff3860;--safe:#00ff88;--warn:#ffb800;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh;}
.container{max-width:1400px;margin:0 auto;padding:24px;}
header{display:flex;align-items:center;justify-content:space-between;padding:20px 0 32px;border-bottom:1px solid var(--border);margin-bottom:28px;}
.brand{display:flex;align-items:center;gap:14px;}
.brand-icon{width:42px;height:42px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;}
.brand-text h1{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;}
.brand-text p{font-size:11px;color:var(--muted);margin-top:2px;}
.status-bar{display:flex;align-items:center;gap:20px;font-size:12px;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--safe);animation:pulse 2s infinite;display:inline-block;margin-right:6px;}
.dot.danger{background:var(--danger);}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(0,255,136,0.4);}50%{opacity:.8;box-shadow:0 0 0 6px rgba(0,255,136,0);}}
.timestamp{color:var(--muted);font-size:11px;}
.grid{display:grid;gap:16px;}
.grid-4{grid-template-columns:repeat(4,1fr);}
.grid-3{grid-template-columns:2fr 1fr 1fr;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;}
.card-label{font-size:10px;font-weight:600;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;}
.metric-value{font-family:'Syne',sans-serif;font-size:36px;font-weight:800;line-height:1;}
.metric-value.accent{color:var(--accent);}
.metric-value.danger{color:var(--danger);}
.metric-value.safe{color:var(--safe);}
.metric-value.warn{color:var(--warn);}
.metric-sub{font-size:11px;color:var(--muted);margin-top:6px;}
.section-title{font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:var(--accent);letter-spacing:1px;text-transform:uppercase;margin:24px 0 12px;display:flex;align-items:center;gap:8px;}
.section-title::after{content:'';flex:1;height:1px;background:var(--border);}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;padding:8px 12px;color:var(--muted);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;border-bottom:1px solid var(--border);}
td{padding:10px 12px;border-bottom:1px solid rgba(26,37,53,0.5);}
.ip-tag{background:rgba(0,212,255,0.08);color:var(--accent);padding:2px 8px;border-radius:4px;font-size:11px;border:1px solid rgba(0,212,255,0.15);}
.banned-tag{background:rgba(255,56,96,0.1);color:var(--danger);padding:2px 8px;border-radius:4px;font-size:11px;border:1px solid rgba(255,56,96,0.2);}
.bar-container{background:var(--surface2);border-radius:4px;height:6px;margin-top:4px;overflow:hidden;}
.bar{height:100%;border-radius:4px;transition:width 0.5s ease;}
.bar.accent{background:linear-gradient(90deg,var(--accent),var(--accent3));}
.bar.danger{background:linear-gradient(90deg,var(--danger),var(--accent4));}
.empty-state{text-align:center;color:var(--muted);padding:24px;font-size:12px;}
.uptime-display{font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:600;color:var(--accent3);}
.refresh-indicator{position:fixed;top:16px;right:16px;font-size:10px;color:var(--muted);background:var(--surface);border:1px solid var(--border);padding:6px 12px;border-radius:20px;z-index:100;}
/* Baseline chart */
.chart-wrap{width:100%;overflow-x:auto;}
canvas#baselineChart{width:100%;height:180px;display:block;}
.chart-legend{display:flex;gap:20px;margin-top:10px;font-size:11px;}
.legend-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:5px;}
@media(max-width:900px){.grid-4{grid-template-columns:repeat(2,1fr);}.grid-3{grid-template-columns:1fr;}}
</style>
</head>
<body>
<div class="refresh-indicator">auto-refresh <span id="countdown">3</span>s</div>
<div class="container">
<header>
<div class="brand">
  <div class="brand-icon">&#128737;</div>
  <div class="brand-text"><h1>HNG Anomaly Detection Engine</h1><p>cloud.ng &middot; DDoS &amp; Anomaly Detection &middot; Powered by HNG</p></div>
</div>
<div class="status-bar">
  <span><span class="dot" id="status-dot"></span><span id="status-text">ONLINE</span></span>
  <span class="timestamp" id="last-updated">&mdash;</span>
</div>
</header>

<div class="grid grid-4">
<div class="card"><div class="card-label">Global Req/s</div><div class="metric-value accent" id="global-rps">&mdash;</div><div class="metric-sub">last 60 seconds</div></div>
<div class="card"><div class="card-label">Banned IPs</div><div class="metric-value danger" id="banned-count">&mdash;</div><div class="metric-sub">active blocks</div></div>
<div class="card"><div class="card-label">CPU Usage</div><div class="metric-value" id="cpu-pct">&mdash;</div><div class="bar-container"><div class="bar accent" id="cpu-bar" style="width:0%"></div></div></div>
<div class="card"><div class="card-label">Memory</div><div class="metric-value" id="mem-pct">&mdash;</div><div class="bar-container"><div class="bar danger" id="mem-bar" style="width:0%"></div></div></div>
</div>

<div class="grid grid-3" style="margin-top:16px">
<div class="card"><div class="card-label">Uptime</div><div class="uptime-display" id="uptime">00:00:00</div><div class="metric-sub" id="total-reqs">Total requests: &mdash;</div></div>
<div class="card"><div class="card-label">Baseline Mean</div><div class="metric-value safe" id="b-mean">&mdash;</div><div class="metric-sub">req/s effective</div></div>
<div class="card"><div class="card-label">Baseline StdDev</div><div class="metric-value warn" id="b-stddev">&mdash;</div><div class="metric-sub" id="b-age">last updated &mdash;</div></div>
</div>

<div class="section-title">Baseline Over Time</div>
<div class="card">
  <div class="chart-wrap"><canvas id="baselineChart"></canvas></div>
  <div class="chart-legend">
    <span><span class="legend-dot" style="background:var(--safe)"></span>effective_mean (req/s)</span>
    <span><span class="legend-dot" style="background:var(--warn)"></span>effective_stddev</span>
  </div>
  <div class="metric-sub" style="margin-top:8px" id="chart-note">Snapshots recorded every 60s. Run traffic to see the baseline adapt.</div>
</div>

<div class="section-title">Banned IPs</div>
<div class="card"><div id="banned-table-container"><div class="empty-state">No IPs currently banned</div></div></div>

<div class="section-title">Top 10 Source IPs</div>
<div class="card"><div id="top-ips-container"><div class="empty-state">Awaiting traffic...</div></div></div>
</div>

<script>
let countdown=3;
let chartData=[];

function drawChart(history){
  const canvas=document.getElementById('baselineChart');
  if(!canvas) return;
  const ctx=canvas.getContext('2d');
  const W=canvas.offsetWidth||800;
  const H=180;
  canvas.width=W;
  canvas.height=H;
  ctx.clearRect(0,0,W,H);

  if(!history||history.length<2){
    ctx.fillStyle='#5a7a9a';
    ctx.font='12px JetBrains Mono';
    ctx.textAlign='center';
    ctx.fillText('Accumulating data — snapshots taken every 60s',W/2,H/2);
    return;
  }

  const means=history.map(h=>h.mean);
  const stddevs=history.map(h=>h.stddev);
  const allVals=[...means,...stddevs];
  const minV=Math.min(...allVals)*0.8;
  const maxV=Math.max(...allVals)*1.2||1;
  const pad={top:16,right:20,bottom:32,left:48};
  const cW=W-pad.left-pad.right;
  const cH=H-pad.top-pad.bottom;
  const n=history.length;

  function xPos(i){return pad.left+(i/(n-1))*cW;}
  function yPos(v){return pad.top+cH-(((v-minV)/(maxV-minV))*cH);}

  // Grid lines
  ctx.strokeStyle='#1a2535';
  ctx.lineWidth=1;
  for(let i=0;i<=4;i++){
    const y=pad.top+(i/4)*cH;
    ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(pad.left+cW,y);ctx.stroke();
    const val=(maxV-((maxV-minV)*(i/4))).toFixed(2);
    ctx.fillStyle='#5a7a9a';ctx.font='10px JetBrains Mono';ctx.textAlign='right';
    ctx.fillText(val,pad.left-6,y+4);
  }

  // Mean line
  ctx.beginPath();
  ctx.strokeStyle='#00ff88';
  ctx.lineWidth=2;
  history.forEach((h,i)=>{
    i===0?ctx.moveTo(xPos(i),yPos(h.mean)):ctx.lineTo(xPos(i),yPos(h.mean));
  });
  ctx.stroke();

  // Stddev line
  ctx.beginPath();
  ctx.strokeStyle='#ffb800';
  ctx.lineWidth=2;
  ctx.setLineDash([4,3]);
  history.forEach((h,i)=>{
    i===0?ctx.moveTo(xPos(i),yPos(h.stddev)):ctx.lineTo(xPos(i),yPos(h.stddev));
  });
  ctx.stroke();
  ctx.setLineDash([]);

  // Dots on mean
  history.forEach((h,i)=>{
    ctx.beginPath();ctx.arc(xPos(i),yPos(h.mean),3,0,Math.PI*2);
    ctx.fillStyle='#00ff88';ctx.fill();
  });

  // X-axis labels (every 5th or all if few)
  ctx.fillStyle='#5a7a9a';ctx.font='9px JetBrains Mono';ctx.textAlign='center';
  history.forEach((h,i)=>{
    if(n<=10||i%Math.ceil(n/10)===0){
      ctx.fillText(h.time,xPos(i),H-8);
    }
  });
}

async function fetchMetrics(){
  try{
    const res=await fetch('/api/metrics');
    const d=await res.json();
    render(d);
  }catch(e){
    document.getElementById('status-text').textContent='ERROR';
    document.getElementById('status-dot').classList.add('danger');
  }
}

function render(d){
  document.getElementById('last-updated').textContent='Updated: '+d.timestamp;
  document.getElementById('global-rps').textContent=d.global_rps.toFixed(2);
  document.getElementById('banned-count').textContent=d.banned_count;
  document.getElementById('cpu-pct').textContent=d.system.cpu_percent.toFixed(1)+'%';
  document.getElementById('cpu-bar').style.width=d.system.cpu_percent+'%';
  document.getElementById('mem-pct').textContent=d.system.memory_percent.toFixed(1)+'%';
  document.getElementById('mem-bar').style.width=d.system.memory_percent+'%';
  document.getElementById('uptime').textContent=d.uptime_human;
  document.getElementById('total-reqs').textContent='Total requests: '+d.total_requests.toLocaleString();
  document.getElementById('b-mean').textContent=d.baseline.effective_mean.toFixed(4);
  document.getElementById('b-stddev').textContent=d.baseline.effective_stddev.toFixed(4);
  document.getElementById('b-age').textContent=d.baseline.last_updated_seconds_ago!==null?'updated '+d.baseline.last_updated_seconds_ago+'s ago':'not yet computed';

  if(d.baseline.history&&d.baseline.history.length>0){
    drawChart(d.baseline.history);
    document.getElementById('chart-note').textContent=d.baseline.history.length+' snapshot(s) recorded. Each point = 1 minute.';
  } else {
    drawChart([]);
  }

  const bc=document.getElementById('banned-table-container');
  if(d.banned_ips.length===0){bc.innerHTML='<div class="empty-state">No IPs currently banned</div>';}
  else{bc.innerHTML='<table><thead><tr><th>IP</th><th>Reason</th><th>Duration</th><th>Remaining</th><th>Bans</th><th>Banned At</th></tr></thead><tbody>'+d.banned_ips.map(b=>`<tr><td><span class="banned-tag">${b.ip}</span></td><td style="color:var(--muted)">${b.reason}</td><td>${b.duration}</td><td style="color:var(--warn)">${b.remaining}</td><td>${b.ban_count}</td><td style="color:var(--muted)">${b.banned_at}</td></tr>`).join('')+'</tbody></table>';}

  const tc=document.getElementById('top-ips-container');
  if(d.top_ips.length===0){tc.innerHTML='<div class="empty-state">Awaiting traffic...</div>';}
  else{const mx=d.top_ips[0]?d.top_ips[0].count_60s:1;tc.innerHTML='<table><thead><tr><th>#</th><th>IP Address</th><th>Req/s (60s)</th><th>Count (60s)</th><th>Distribution</th></tr></thead><tbody>'+d.top_ips.map((ip,i)=>{const pct=Math.min(100,(ip.count_60s/mx)*100);return`<tr><td style="color:var(--muted)">${i+1}</td><td><span class="ip-tag">${ip.ip}</span></td><td>${ip.rps.toFixed(3)}</td><td>${ip.count_60s}</td><td style="width:120px"><div class="bar-container"><div class="bar accent" style="width:${pct}%"></div></div></td></tr>`;}).join('')+'</tbody></table>';}

  document.getElementById('status-dot').className='dot'+(d.banned_count>0?' danger':'');
}

setInterval(fetchMetrics,3000);
fetchMetrics();
setInterval(()=>{countdown=countdown<=1?3:countdown-1;document.getElementById('countdown').textContent=countdown;},1000);
window.addEventListener('resize',()=>{const d=window._lastData;if(d)drawChart(d.baseline.history);});
</script>
</body>
</html>"""
