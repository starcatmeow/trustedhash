const phase = document.querySelector("#phase");
const credentials = document.querySelector("#credentials");
const rootPassword = document.querySelector("#root-password");
const vncPassword = document.querySelector("#vnc-password");
const attester = document.querySelector("#attester");
const stages = document.querySelector("#stages");
const output = document.querySelector("#output");
const createVm = document.querySelector("#create-vm");
const restart = document.querySelector("#restart");
const connectVnc = document.querySelector("#connect-vnc");
const novnc = document.querySelector("#novnc");

let novncUrl = "";

function setText(node, value) {
  if (node) {
    node.textContent = value;
  }
}

function setStatus(node, value, cls) {
  if (!node) {
    return;
  }
  node.textContent = value;
  node.className = `status ${cls}`;
}

function statusClass(status) {
  if (status === "ok" || status === "running" || status === "fail") {
    return status;
  }
  return "";
}

function updateNovncUrl(state) {
  if (!state.vm) {
    novncUrl = "";
    return;
  }
  const encrypt = window.location.protocol === "https:" ? "true" : "false";
  const host = window.location.hostname;
  const port = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
  novncUrl =
    `/novnc/vnc.html?autoconnect=true&resize=scale` +
    `&host=${encodeURIComponent(host)}` +
    `&port=${encodeURIComponent(port)}` +
    `&path=${encodeURIComponent("vnc-websocket")}` +
    `&encrypt=${encrypt}`;
}

async function refresh() {
  const res = await fetch("/api/state");
  const state = await res.json();
  setStatus(
    phase,
    state.phase,
    state.error ? "fail" : state.phase === "ready" ? "ok" : "running",
  );
  updateNovncUrl(state);

  createVm.disabled = Boolean(state.vm) || state.phase === "creating";
  restart.disabled = !state.vm || state.phase === "restarting";

  const view = state.attester;
  setStatus(
    attester,
    view.running ? "running" : view.last_ok ? "ok" : "failed",
    view.running ? "running" : view.last_ok ? "ok" : "fail",
  );

  if (stages) {
    stages.replaceChildren();
    for (const stage of view.stages) {
      const line = document.createElement("p");
      const badge = document.createElement("span");
      badge.className = `status ${statusClass(stage.status)}`;
      badge.textContent = `${stage.name}: ${stage.status}`;
      line.appendChild(badge);
      if (stage.detail) {
        const detail = document.createElement("span");
        detail.className = "value";
        detail.textContent = ` ${stage.detail}`;
        line.appendChild(detail);
      }
      stages.appendChild(line);
    }
  }

  setText(output, (view.output_tail || []).join("\n"));
}

restart?.addEventListener("click", async () => {
  const password = window.prompt("Enter the root password to restart this VM");
  if (!password) {
    return;
  }
  await fetch("/api/restart", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ root_password: password }),
  });
  await refresh();
});

createVm?.addEventListener("click", async () => {
  const res = await fetch("/api/start", { method: "POST" });
  const body = await res.json();
  if (res.ok && body.credentials) {
    credentials.hidden = false;
    setText(rootPassword, body.credentials.root_password);
    setText(vncPassword, body.credentials.vnc_password);
  }
  await refresh();
});

connectVnc?.addEventListener("click", () => {
  if (novnc && novncUrl) {
    novnc.src = novncUrl;
  }
});

void refresh();
setInterval(() => void refresh(), 3000);
