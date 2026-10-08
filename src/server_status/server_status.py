"""server-status: status.parumichinsan.xyz の公開ステータスページ。

- ページは1つだけ(ホスト判定も秘密パスもなし)。検索除けは robots.txt / noindex ヘッダ / meta。
- 状態の収集は gunicorn ワーカー内のバックグラウンドスレッドが行い、リクエストは最新の結果を返すだけ。
- 起動は `uv run server-status`(ワーカーは1つ。電気代の累計をプロセス内で持つため)。
"""
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import date
from pathlib import Path

import psutil
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

# ================= 設定 =================
BIND = os.environ.get("STATUS_BIND", "127.0.0.1:8001")
SAMPLE_INTERVAL = 3  # 秒。状態を集め直す間隔

SERVER_IP = "192.168.0.10"
SWANCTL = "/usr/sbin/swanctl"

# (swanctl の接続名, 画面に出す名前)。接続名は /etc/swanctl/conf.d/ の定義と一致させる。
VPN_CONNECTIONS = [
    ("pub", "vpn pub"),
    ("tunnel", "vpn tunnel"),
    ("admin", "vpn admin"),
]

# check の種類:
#   systemd  : systemctl is-active
#   listen   : このマシンで待ち受けているか(psutil)。UDP もこれ。
#   tcp      : 実際に接続してみる(別マシンに移したサービス用。TCP のみ)
#   vpn_conn : swanctl に接続定義が読み込まれているか
GROUPS = [
    {"title": "vpn", "items": [
        {"id": "strongswan", "label": "strongswan", "check": "systemd", "name": "strongswan"},
        *[{"id": f"vpn-{name}", "label": label, "check": "vpn_conn", "name": name}
          for name, label in VPN_CONNECTIONS],
    ]},
    {"title": "services", "items": [
        {"id": "adguard", "label": "adguard home (dns)", "check": "listen",
         "host": SERVER_IP, "port": 53, "proto": "udp"},
        {"id": "java", "label": "minecraft (java)", "check": "listen",
         "host": SERVER_IP, "port": 25565, "proto": "tcp"},
        {"id": "bedrock", "label": "minecraft (bedrock)", "check": "listen",
         "host": SERVER_IP, "port": 19132, "proto": "udp"},
    ]},
    {"title": "remote access", "items": [
        {"id": "ssh", "label": "ssh", "check": "systemd", "name": "ssh"},
        {"id": "xrdp", "label": "xrdp", "check": "systemd", "name": "xrdp"},
        {"id": "vnc", "label": "vnc", "check": "systemd", "name": "tigervncserver@:1.service"},
    ]},
]
VPN_SERVICE_ID = "strongswan"

# 消費電力の推定に使う値(ノートPC i5-6200U 想定)。サーバー機を替えたらここを直す。
POWER_PROFILE = {"idle_w": 6.0, "max_w": 25.0, "ref_mhz": 2400.0}
FALLBACK_RATE = 25.61  # 円/kWh。単価の取得に失敗したときの値

# リポジトリ直下の maintenance_log.txt(1行1件、新しいものが下)
MAINTENANCE_LOG_PATH = Path(
    os.environ.get("STATUS_MAINTENANCE_LOG",
                   Path(__file__).resolve().parents[2] / "maintenance_log.txt")
)


# ================= サーバー機の状態 =================
BOOT_TIME = psutil.boot_time()


def get_server_stats():
    cpu_percent = psutil.cpu_percent(interval=None)  # 前回呼び出しからの平均。待たない
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": cpu_percent,
        "freq_mhz": round(cpu_freq.current, 0) if cpu_freq else None,
        "memory_percent": mem.percent,
        "memory_used_gb": round(mem.used / 1024**3, 1),
        "memory_total_gb": round(mem.total / 1024**3, 1),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / 1024**3, 1),
        "disk_total_gb": round(disk.total / 1024**3, 1),
        "uptime_hours": round((time.time() - BOOT_TIME) / 3600, 1),
    }


# ================= サービス稼働確認(True / False / None=判定不能) =================
def check_systemd(name):
    try:
        r = subprocess.run(["systemctl", "is-active", name],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip() == "active"
    except Exception:
        return None


def is_port_listening(host, port, proto="tcp"):
    kind = "tcp" if proto == "tcp" else "udp"
    try:
        for conn in psutil.net_connections(kind=kind):
            if not conn.laddr or conn.laddr.port != port:
                continue
            if conn.laddr.ip not in (host, "0.0.0.0", "::"):
                continue
            if proto != "tcp" or conn.status == psutil.CONN_LISTEN:
                return True
        return False
    except Exception:
        return None


def check_tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def get_loaded_vpn_conns():
    """swanctl に読み込まれている接続名の集合。権限がなければ None。
    vici ソケットは root 専用なので sudoers で --list-conns だけ許可しておく。"""
    try:
        r = subprocess.run(["sudo", "-n", SWANCTL, "--list-conns"],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return set(re.findall(r"^(\S+): IKEv[12]", r.stdout, re.M))


def run_check(item, states, vpn_loaded):
    kind = item["check"]
    if kind == "systemd":
        return check_systemd(item["name"])
    if kind == "listen":
        return is_port_listening(item["host"], item["port"], item["proto"])
    if kind == "tcp":
        return check_tcp(item["host"], item["port"])
    if kind == "vpn_conn":
        if states.get(VPN_SERVICE_ID) == "down":
            return False
        return None if vpn_loaded is None else item["name"] in vpn_loaded
    return None


# ================= 消費電力・電気代の推定 =================
_power_total_wh = 0.0
_power_last_time = time.time()
_power_last_w = 0.0
_power_today_date = str(date.today())
_power_yesterday_cost = 0.0
_kansai_rate = FALLBACK_RATE


def fetch_kansai_rate():
    global _kansai_rate
    try:
        req = urllib.request.Request("https://testpage.jp/tool/denkidai.php",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as res:
            html = res.read().decode("utf-8", errors="replace")
        m = re.search(r"関西電力[：:]\s*([\d.]+)円", html)
        if m and 10 < float(m.group(1)) < 100:
            _kansai_rate = float(m.group(1))
    except Exception:
        pass


def power_daily_reset():
    global _power_total_wh, _power_today_date, _power_yesterday_cost
    today = str(date.today())
    if _power_today_date != today:
        _power_yesterday_cost = round(_power_total_wh / 1000 * _kansai_rate, 2)
        _power_total_wh = 0.0
        _power_today_date = today
        threading.Thread(target=fetch_kansai_rate, daemon=True).start()


def estimate_power_w(cpu_percent, freq_mhz):
    p = POWER_PROFILE
    freq_factor = (freq_mhz / p["ref_mhz"]) if freq_mhz else 1.0
    w = p["idle_w"] + (p["max_w"] - p["idle_w"]) * (cpu_percent / 100.0) * freq_factor
    return round(min(max(w, p["idle_w"]), p["max_w"]), 2)


def get_power_estimate(cpu_percent, freq_mhz):
    """サンプリングスレッドからだけ呼ぶ(積算値をロックなしで持つため)。"""
    global _power_total_wh, _power_last_time, _power_last_w
    now = time.time()
    power_daily_reset()
    _power_total_wh += _power_last_w * (now - _power_last_time) / 3600.0
    _power_last_w = estimate_power_w(cpu_percent, freq_mhz)
    _power_last_time = now
    return {
        "current_w": _power_last_w,
        "total_kwh": round(_power_total_wh / 1000, 4),
        "today_cost": round(_power_total_wh / 1000 * _kansai_rate, 2),
        "yesterday_cost": _power_yesterday_cost,
        "rate": _kansai_rate,
    }


# ================= メンテナンスログ =================
def get_maintenance_log():
    try:
        lines = [l.strip() for l in MAINTENANCE_LOG_PATH.read_text(encoding="utf-8").splitlines()]
        return [l for l in reversed(lines) if l]  # 新しいものが上
    except OSError:
        return []


# ================= 状態の収集(バックグラウンド) =================
def build_status():
    stats = get_server_stats()
    power = get_power_estimate(stats["cpu_percent"], stats["freq_mhz"])
    has_vpn = any(i["check"] == "vpn_conn" for g in GROUPS for i in g["items"])
    vpn_loaded = get_loaded_vpn_conns() if has_vpn else None

    states, groups = {}, []
    for g in GROUPS:
        items = []
        for it in g["items"]:
            result = run_check(it, states, vpn_loaded)
            state = "unknown" if result is None else ("up" if result else "down")
            states[it["id"]] = state
            items.append({"id": it["id"], "label": it["label"], "state": state})
        groups.append({"title": g["title"], "items": items})

    return {
        "server": stats,
        "power": power,
        "groups": groups,
        "maintenance_log": get_maintenance_log(),
        "updated_at": time.time(),
    }


_snapshot = None
_sampler_lock = threading.Lock()
_sampler_started = False


def _sampler_loop():
    global _snapshot
    while True:
        time.sleep(SAMPLE_INTERVAL)
        try:
            _snapshot = build_status()
        except Exception:
            app.logger.exception("status sampling failed")


def start_sampler():
    """ワーカー内で1回だけ呼ばれる(fork 後に呼ぶこと。スレッドは fork で引き継がれない)。"""
    global _snapshot, _sampler_started
    with _sampler_lock:
        if _sampler_started:
            return
        _sampler_started = True
        psutil.cpu_percent(interval=None)  # 基準点を作る
        time.sleep(0.2)
        _snapshot = build_status()
        threading.Thread(target=fetch_kansai_rate, daemon=True).start()
        threading.Thread(target=_sampler_loop, daemon=True).start()


def get_snapshot():
    if not _sampler_started:  # gunicorn を直接起動した場合などの保険
        start_sampler()
    return _snapshot


# ================= ルート =================
@app.route("/")
def index():
    return render_template("status.html", status=get_snapshot())


@app.route("/api/status")
def api_status():
    return jsonify(get_snapshot())


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@app.after_request
def add_headers(resp):
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ================= 起動(uv run server-status) =================
def main():
    from gunicorn.app.base import BaseApplication

    class StatusApp(BaseApplication):
        def __init__(self, options):
            self.options = options
            super().__init__()

        def load_config(self):
            for key, value in self.options.items():
                self.cfg.set(key, value)

        def load(self):
            return app

    StatusApp({
        "bind": BIND,
        "workers": 1,
        "threads": 4,
        "post_fork": lambda server, worker: start_sampler(),
    }).run()


if __name__ == "__main__":
    main()
