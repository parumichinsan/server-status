"""server-status: status.parumichinsan.xyz の公開ステータスページ。

- ページは1つだけ(ホスト判定も秘密パスもなし)。検索除けは robots.txt / noindex ヘッダ / meta。
- 状態の収集は gunicorn ワーカー内のバックグラウンドスレッドが行い、リクエストは最新の結果を返すだけ。
- 起動は `uv run server-status`(ワーカーは1つ。電気代の累計をプロセス内で持つため)。
"""
import os
import re
import socket
import struct
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
SAMPLE_INTERVAL = 1.5  # 秒。CPU・メモリ・電力を集め直す間隔
SERVICE_INTERVAL = 10  # 秒。サービスの稼働確認(プロセス起動を伴うので間隔を空ける)
VPN_CONN_INTERVAL = 60  # 秒。swanctl(sudo 経由)の確認。接続定義はめったに変わらないので長め

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


_cpu_prev = None


def get_cpu_percent():
    """全CPUの使用率(%)。/proc/stat の前回との差から htop と同じ式で出す。
    busy = 合計 - idle - iowait。guest 系は user/nice に含まれているので足さない。
    サンプリングスレッドからだけ呼ぶ(前回値をプロセス内で1つだけ持つため)。"""
    global _cpu_prev
    with open("/proc/stat") as f:
        user, nice, system, idle, iowait, irq, softirq, steal = map(int, f.readline().split()[1:9])
    total = user + nice + system + idle + iowait + irq + softirq + steal
    cur = (total - idle - iowait, total)
    prev, _cpu_prev = _cpu_prev, cur
    if prev is None or cur[1] <= prev[1]:
        return 0.0
    return round(100.0 * (cur[0] - prev[0]) / (cur[1] - prev[1]), 1)


def get_server_stats():
    cpu_percent = get_cpu_percent()  # 前回呼び出しからの平均。待たない
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
def check_systemd_batch(names):
    """systemctl を1回だけ呼んで {名前: True/False/None} を返す。"""
    if not names:
        return {}
    try:
        r = subprocess.run(["systemctl", "is-active", *names],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return {n: None for n in names}
    states = r.stdout.split()  # 引数と同じ順に1行ずつ返る
    if len(states) != len(names):
        return {n: None for n in names}
    return {n: state == "active" for n, state in zip(names, states)}


def read_listeners():
    """/proc/net から待ち受け中のソケットを読む。{"tcp": {(ip, port)}, "udp": {...}}。
    psutil.net_connections は全プロセスの fd を走査して重いので使わない。読めなければ None。"""
    result = {"tcp": set(), "udp": set()}
    readable = False
    for proto, files, want in (("tcp", ("tcp", "tcp6"), "0A"), ("udp", ("udp", "udp6"), "07")):
        for name in files:
            try:
                with open(f"/proc/net/{name}") as f:
                    lines = f.read().splitlines()[1:]
            except OSError:
                continue
            readable = True
            for line in lines:
                cols = line.split()
                if len(cols) < 4 or cols[3] != want:
                    continue
                addr_hex, port_hex = cols[1].rsplit(":", 1)
                if len(addr_hex) == 8:  # IPv4(リトルエンディアン)
                    ip = socket.inet_ntoa(struct.pack("<I", int(addr_hex, 16)))
                else:  # IPv6。全部0なら待ち受け(::)、それ以外は照合しない
                    ip = "::" if int(addr_hex, 16) == 0 else addr_hex
                result[proto].add((ip, int(port_hex, 16)))
    return result if readable else None


def is_listening(listeners, host, port, proto):
    if listeners is None:
        return None
    return any(p == port and ip in (host, "0.0.0.0", "::") for ip, p in listeners[proto])


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


def run_check(item, ctx):
    kind = item["check"]
    if kind == "systemd":
        return ctx["systemd"].get(item["name"])
    if kind == "listen":
        return is_listening(ctx["listeners"], item["host"], item["port"], item["proto"])
    if kind == "tcp":
        return check_tcp(item["host"], item["port"])
    if kind == "vpn_conn":
        if ctx["states"].get(VPN_SERVICE_ID) == "down":
            return False
        loaded = ctx["vpn_loaded"]
        return None if loaded is None else item["name"] in loaded
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
_service_t = 0.0
_service_groups = []
_vpn_loaded = None
_vpn_loaded_t = 0.0


def get_vpn_loaded_cached():
    """sudo を毎回呼ぶと重く、ログも増えるので VPN_CONN_INTERVAL ごとにだけ呼ぶ。"""
    global _vpn_loaded, _vpn_loaded_t
    if time.time() - _vpn_loaded_t >= VPN_CONN_INTERVAL:
        _vpn_loaded = get_loaded_vpn_conns()
        _vpn_loaded_t = time.time()
    return _vpn_loaded


def collect_services():
    items = [i for g in GROUPS for i in g["items"]]
    ctx = {
        "systemd": check_systemd_batch([i["name"] for i in items if i["check"] == "systemd"]),
        "listeners": read_listeners(),
        "vpn_loaded": get_vpn_loaded_cached() if any(i["check"] == "vpn_conn" for i in items) else None,
        "states": {},
    }
    groups = []
    for g in GROUPS:
        out = []
        for it in g["items"]:
            result = run_check(it, ctx)
            state = "unknown" if result is None else ("up" if result else "down")
            ctx["states"][it["id"]] = state
            out.append({"id": it["id"], "label": it["label"], "state": state})
        groups.append({"title": g["title"], "items": out})
    return groups


def build_status():
    global _service_t, _service_groups
    stats = get_server_stats()
    power = get_power_estimate(stats["cpu_percent"], stats["freq_mhz"])
    now = time.time()
    if now - _service_t >= SERVICE_INTERVAL:
        _service_groups = collect_services()
        _service_t = now
    return {
        "server": stats,
        "power": power,
        "groups": _service_groups,
        "maintenance_log": get_maintenance_log(),
        "updated_at": now,
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
        get_cpu_percent()  # 基準点を作る
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
