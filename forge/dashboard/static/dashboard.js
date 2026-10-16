const ws = new WebSocket(`ws://${location.host}/ws`);
const connStatus = document.getElementById("conn-status");
const alertCount = document.getElementById("alert-count");
const alertTotal = document.getElementById("alert-total");
const alertFeed = document.getElementById("alert-feed");
const alarmBox = document.getElementById("alarms");

ws.onopen = () => {
  connStatus.textContent = "ONLINE";
  connStatus.className = "tag online";
};

ws.onclose = () => {
  connStatus.textContent = "OFFLINE";
  connStatus.className = "tag offline";
};

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === "state") updateState(msg);
  if (msg.type === "alert") addAlert(msg.alert);
};

function updateState(msg) {
  const p = msg.plant;

  setText("tank-level", p.tank_level.toFixed(1) + " %");
  setText("chlorine", p.chlorine_mg_l.toFixed(2) + " mg/L");
  setText("pressure", p.inlet_pressure.toFixed(1) + " PSI");
  setText("flow", p.flow_rate.toFixed(1) + " GPM");

  // Tank bar
  const tankBar = document.getElementById("tank-bar");
  tankBar.style.width = p.tank_level + "%";
  tankBar.className = "bar-fill" +
    (p.tank_level > 85 ? " danger" : p.tank_level > 70 ? " warn" : "");

  // Chlorine bar
  const clBar = document.getElementById("chlorine-bar");
  clBar.style.width = (p.chlorine_mg_l / 10 * 100) + "%";
  clBar.className = "bar-fill chlorine" +
    (p.chlorine_mg_l > 8 ? " danger" : "");

  // Actuators
  setActuator("act-intake", p.intake_pump, false);
  setActuator("act-dosing", p.dosing_pump, false);
  setActuator("act-outlet", p.outlet_valve, false);
  setActuator("act-estop", p.emergency_stop, true);

  // Alarms
  const alarms = [];
  if (p.tank_high_alarm) alarms.push("TANK HIGH");
  if (p.tank_low_alarm) alarms.push("TANK LOW");
  if (p.chlorine_high_alarm) alarms.push("CL₂ HIGH");
  if (p.chlorine_low_alarm) alarms.push("CL₂ LOW");
  alarmBox.innerHTML = alarms.map(a => `<span class="alarm-tag">${a}</span>`).join("");

  // Alert count
  alertCount.textContent = msg.alert_count + " alerts";
  alertTotal.textContent = "(" + msg.alert_count + ")";

  // Assets
  updateAssets(msg.assets);
}

function addAlert(a) {
  const div = document.createElement("div");
  div.className = "alert-item " + a.severity;
  const time = new Date(a.time * 1000).toLocaleTimeString();
  div.innerHTML = `
    <div class="alert-title">${esc(a.title)}
      <span class="mitre-tag">${esc(a.mitre_id)}</span>
      <span class="mitre-tag">${esc(a.mitre_tactic)}</span>
    </div>
    <div class="alert-meta">${time} — ${esc(a.src_ip)} — ${a.severity.toUpperCase()}</div>
    <div class="alert-detail">${esc(a.detail)}</div>`;
  alertFeed.prepend(div);

  // Cap at 200 entries
  while (alertFeed.children.length > 200)
    alertFeed.removeChild(alertFeed.lastChild);
}

function updateAssets(assets) {
  const tbody = document.querySelector("#asset-table tbody");
  tbody.innerHTML = "";
  for (const a of assets) {
    const tr = document.createElement("tr");
    const ago = Math.round(Date.now() / 1000 - a.last_seen);
    const roleClass = "role-" + a.role;
    tr.innerHTML = `
      <td>${esc(a.ip)}</td>
      <td class="${roleClass}">${esc(a.role)}</td>
      <td>${a.read_count}</td>
      <td>${a.write_count}</td>
      <td>${ago}s ago</td>`;
    tbody.appendChild(tr);
  }
}

function setText(id, val) {
  document.getElementById(id).textContent = val;
}

function setActuator(id, on, isEstop) {
  const el = document.getElementById(id);
  el.className = "actuator" + (on ? (isEstop ? " estop" : " on") : "");
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = String(s);
  return d.innerHTML;
}
