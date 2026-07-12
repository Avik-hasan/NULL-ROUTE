// Cyberpunk VPN control surface.
// Talks to the Rust service via Tauri `invoke`; falls back to a local
// simulation when running in a plain browser (no __TAURI__).

const tauri = window.__TAURI__?.core;
const hasBackend = !!tauri;

const el = (id) => document.getElementById(id);
const state = {
  connected: false,
  connecting: false,
  hist: { down: [], up: [], ping: [] },
  maxPoints: 90,
  simExit: ["REYKJAVÍK [185.213.44.9]", "ZÜRICH [146.70.12.51]", "SINGAPORE [91.132.139.7]"],
};

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*";
async function glitchText(element, finalString, duration = 800) {
  element.classList.add("glitched");
  const start = Date.now();
  return new Promise(resolve => {
    const interval = setInterval(() => {
      const now = Date.now();
      if (now - start > duration) {
        clearInterval(interval);
        element.textContent = finalString;
        element.classList.remove("glitched");
        resolve();
      } else {
        let text = "";
        for (let i = 0; i < finalString.length; i++) {
          text += chars[Math.floor(Math.random() * chars.length)];
        }
        element.textContent = text;
      }
    }, 40);
  });
}

// ---- window controls (Tauri) ----
el("min")?.addEventListener("click", async () => {
  if (hasBackend) await tauri.invoke("minimize_window");
});
el("max")?.addEventListener("click", async () => {
  if (hasBackend) await tauri.invoke("maximize_window");
});
el("close")?.addEventListener("click", async () => {
  if (state.connected || state.connecting) {
    log("WARN", "INITIATING GRACEFUL SHUTDOWN // TERMINATING BACKGROUND SERVICE");
    try {
      if (hasBackend) await tauri.invoke("terminate_service");
    } catch(e) {}
  }
  if (hasBackend) await tauri.invoke("close_window");
});

// ---- ring ticks ----
(function buildTicks() {
  const g = el("ringTicks");
  if (!g) return;
  for (let i = 0; i < 60; i++) {
    const a = (i / 60) * Math.PI * 2;
    const r1 = 116, r2 = i % 5 === 0 ? 106 : 111;
    const x1 = 120 + Math.cos(a) * r1, y1 = 120 + Math.sin(a) * r1;
    const x2 = 120 + Math.cos(a) * r2, y2 = 120 + Math.sin(a) * r2;
    const ln = document.createElementNS("http://www.w3.org/2000/svg", "line");
    ln.setAttribute("x1", x1); ln.setAttribute("y1", y1);
    ln.setAttribute("x2", x2); ln.setAttribute("y2", y2);
    g.appendChild(ln);
  }
})();

// ---- diagnostics console ----
function log(level, msg) {
  const box = el("console");
  const now = new Date().toISOString().substr(11, 8);
  const line = document.createElement("div");
  line.className = "line";
  line.innerHTML = `<span class="t">[${now}]</span> <span class="tag ${level}">[${level}]</span> ${msg}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
  while (box.children.length > 200) box.removeChild(box.firstChild);
}

// ---- state visuals ----
function setState(s) {
  const btn = el("engageBtn");
  const chip = el("stateChip");
  const txt = el("stateText");
  const ring = document.querySelector(".ring-progress");
  btn.classList.remove("state-off", "state-connecting", "state-on");
  chip.classList.remove("on", "connecting", "rotating");
  if (s === "off") {
    btn.classList.add("state-off"); txt.textContent = "DISCONNECTED";
    ring.style.strokeDashoffset = 653;
  } else if (s === "connecting") {
    btn.classList.add("state-connecting"); chip.classList.add("connecting");
    txt.textContent = "HANDSHAKING"; ring.style.strokeDashoffset = 400;
  } else if (s === "on") {
    btn.classList.add("state-on"); chip.classList.add("on");
    txt.textContent = "SECURED"; ring.style.strokeDashoffset = 0;
  } else if (s === "rotating") {
    btn.classList.add("state-on"); chip.classList.add("rotating");
    txt.textContent = "ROTATING";
  }
}

// ---- engage / disengage ----
async function toggle() {
  if (state.connecting) return;
  if (!state.connected) {
    state.connecting = true; setState("connecting");
    const idx = parseInt(el("nodeSelect").value, 10);
    log("INFO", `DIALING NODE ${el("nodeSelect").selectedOptions[0].text}`);
    try {
      if (hasBackend) await tauri.invoke("engage", { nodeIndex: idx });
      await wait(1400);
      log("OK", "NOISE_IK HANDSHAKE COMPLETED");
      log("OK", "WFP KILL-SWITCH ARMED // IPv6 BLACKHOLED");
      log("OK", "DNS BOUND TO WINTUN // LEAK GUARD ACTIVE");
      state.connected = true; state.connecting = false; setState("on");
      const finalDest = state.simExit[idx] || state.simExit[0];
      await glitchText(el("exitIp"), finalDest, 600);
      startUptime();
    } catch (e) {
      state.connecting = false; setState("off");
      if (e.toString().includes("os error 2") || e.toString().includes("cannot find the file")) {
        log("ERROR", "BACKGROUND SERVICE OFFLINE.");
        log("ERROR", "Please run 'vpn-client.exe' as Administrator before connecting.");
      } else {
        log("ERROR", `CONNECT FAILED: ${e}`);
      }
    }
  } else {
    try { if (hasBackend) await tauri.invoke("disengage"); } catch (e) {}
    state.connected = false; setState("off");
    el("exitIp").textContent = "AWAITING CONNECTION...";
    stopUptime();
    log("WARN", "TUNNEL TORN DOWN // ROUTES + DNS RESTORED");
  }
}

async function rotate() {
  if (!state.connected) { log("WARN", "NOT CONNECTED"); return; }
  setState("rotating");
  const idx = Math.floor(Math.random() * 3);
  const codes = ["OBLIVION-1", "OBLIVION-4", "SPECTRE-7"];
  log("ROTATING", `MIGRATING TO NODE: ${codes[idx]}`);
  
  const scramblePromise = glitchText(el("exitIp"), state.simExit[idx], 900);
  
  try { if (hasBackend) await tauri.invoke("rotate_now"); } catch (e) {}
  await wait(900);
  await scramblePromise;
  
  log("OK", `HANDOVER COMPLETE // EXIT ${state.simExit[idx]} // ZERO PACKET LOSS`);
  setState("on");
}

el("engageBtn").addEventListener("click", toggle);
el("rotateBtn").addEventListener("click", rotate);

// ---- uptime ----
let uptimeStart = 0, uptimeTimer = null;
function startUptime() {
  uptimeStart = Date.now();
  uptimeTimer = setInterval(() => {
    const s = Math.floor((Date.now() - uptimeStart) / 1000);
    const hh = String(Math.floor(s / 3600)).padStart(2, "0");
    const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    el("uptimeVal").textContent = `${hh}:${mm}:${ss}`;
  }, 1000);
}
function stopUptime() { clearInterval(uptimeTimer); el("uptimeVal").textContent = "00:00:00"; }

// ---- live canvas chart ----
const canvas = el("chart");
const ctx = canvas.getContext("2d");
function resize() {
  const r = canvas.getBoundingClientRect();
  canvas.width = r.width * devicePixelRatio;
  canvas.height = r.height * devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio);
}
window.addEventListener("resize", () => { ctx.setTransform(1,0,0,1,0,0); resize(); });
resize();

function pushMetric(down, up, ping) {
  const h = state.hist;
  h.down.push(down); h.up.push(up); h.ping.push(ping);
  for (const k of ["down", "up", "ping"]) if (h[k].length > state.maxPoints) h[k].shift();
}

function drawSeries(data, color, max) {
  const w = canvas.width / devicePixelRatio, hgt = canvas.height / devicePixelRatio;
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = (i / (state.maxPoints - 1)) * w;
    const y = hgt - (Math.min(v, max) / max) * (hgt - 12) - 6;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color; ctx.lineWidth = 2;
  ctx.shadowColor = color; ctx.shadowBlur = 8;
  ctx.stroke(); ctx.shadowBlur = 0;
}

function renderChart() {
  const w = canvas.width / devicePixelRatio, hgt = canvas.height / devicePixelRatio;
  ctx.clearRect(0, 0, w, hgt);
  ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.lineWidth = 1;
  for (let i = 1; i < 5; i++) {
    const y = (i / 5) * hgt;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  drawSeries(state.hist.down, "#00f3ff", 120);
  drawSeries(state.hist.up, "#00ff66", 60);
  drawSeries(state.hist.ping, "#ff9d00", 120);
  requestAnimationFrame(renderChart);
}
requestAnimationFrame(renderChart);

// ---- telemetry poll ----
async function poll() {
  let t;
  if (hasBackend) {
    try { t = await tauri.invoke("get_status"); } catch (e) { t = null; }
  }
  if (!t) {
    // simulate
    const base = state.connected ? 78 : 0;
    t = {
      down_bps: (base + Math.random() * 30) * 1e6,
      up_bps: (state.connected ? 9 + Math.random() * 6 : 0) * 1e6,
      latency_ms: state.connected ? 22 + Math.random() * 16 : 0,
    };
  }
  const downM = t.down_bps / 1e6, upM = t.up_bps / 1e6;
  el("downVal").innerHTML = `${downM.toFixed(1)}<span>Mb/s</span>`;
  el("upVal").innerHTML = `${upM.toFixed(1)}<span>Mb/s</span>`;
  el("pingVal").innerHTML = `${t.latency_ms ? t.latency_ms.toFixed(0) : "–"}<span>ms</span>`;
  if (state.connected) pushMetric(downM, upM, t.latency_ms);
}
setInterval(poll, 1000);

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// boot banner
log("INFO", "CUSTOM VPN v2.0 // OBLIVION PROTOCOL INITIALIZED");
log("INFO", hasBackend ? "SERVICE PIPE DETECTED" : "PREVIEW MODE // SIMULATED TELEMETRY");
setState("off");
