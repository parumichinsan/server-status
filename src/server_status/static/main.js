const API_URL = "/api/status";
const POLL_MS = 1000;
const STALE_SEC = 30;

const $ = (id) => document.getElementById(id);

function setState(id, state) {
  for (const part of ["dot", "text"]) {
    const el = $(`${id}-${part}`);
    if (!el) continue;
    el.classList.remove("up", "down", "unknown");
    el.classList.add(state);
    if (part === "text") el.textContent = state;
  }
}

function setBar(id, percent) {
  const el = $(id);
  if (el) el.style.width = `${percent}%`;
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function showNotice(message) {
  const el = $("notice");
  el.textContent = message;
  el.hidden = false;
}

function formatTime(epochSec) {
  return new Date(epochSec * 1000).toLocaleTimeString("ja-JP");
}

let lastUpdated = null;

function render(data) {
  const s = data.server;
  setText("cpu-value", `${s.cpu_percent}%`);
  setBar("cpu-bar", s.cpu_percent);
  setText("mem-value", `${s.memory_used_gb} / ${s.memory_total_gb} GB`);
  setBar("mem-bar", s.memory_percent);
  setText("disk-value", `${s.disk_used_gb} / ${s.disk_total_gb} GB`);
  setBar("disk-bar", s.disk_percent);
  setText("uptime-value", `${s.uptime_hours}h`);

  setText("power-w-value", `${data.power.current_w}W`);
  setText("power-cost-value", `¥${data.power.today_cost}`);

  for (const group of data.groups) {
    for (const item of group.items) setState(item.id, item.state);
  }

  lastUpdated = data.updated_at;
  setText("updated-at", formatTime(data.updated_at));
  if (Date.now() / 1000 - data.updated_at > STALE_SEC) {
    showNotice("データが古くなっています。サーバー側の収集が止まっている可能性があります。");
  } else {
    $("notice").hidden = true;
  }
}

async function refresh() {
  try {
    const res = await fetch(API_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    render(await res.json());
  } catch (err) {
    const since = lastUpdated ? `最後の更新: ${formatTime(lastUpdated)}` : "まだ取得できていません";
    showNotice(`サーバーに接続できません。${since}`);
  }
}

refresh();
setInterval(refresh, POLL_MS);
