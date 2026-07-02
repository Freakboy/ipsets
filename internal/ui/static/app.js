const state = {
  username: localStorage.getItem("ipsets.username") || "admin",
};

const el = (id) => document.getElementById(id);

function redirectToLogin() {
  const next = encodeURIComponent(`${location.pathname}${location.search}`);
  location.href = `/login.html?next=${next}`;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      message = body.error || message;
    } catch (_) {
      // Keep the status message when the response is not JSON.
    }
    if (res.status === 401) {
      redirectToLogin();
      return new Promise(() => {});
    }
    throw new Error(message);
  }
  if (res.status === 204) return null;
  return res.json();
}

function toast(message) {
  const box = el("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    box.hidden = true;
  }, 3200);
}

function fmtDate(value) {
  if (!value) return "--";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function statusText(value) {
  if (value === "applied") return "已应用";
  if (value === "not_applied") return "未应用";
  if (value === "restored") return "已恢复";
  if (value === "pending") return "待重新应用";
  if (value === "error") return "状态异常";
  return "不可用";
}

function setOperationStatus(message, kind = "") {
  const status = el("operationStatus");
  status.textContent = message;
  status.className = `operation-status ${kind}`.trim();
}

function setOperationBusy(kind, busy) {
  const applyBtn = el("applyBtn");
  const restoreBtn = el("restoreBtn");
  const bannerAction = el("ruleBannerAction");
  applyBtn.disabled = busy;
  restoreBtn.disabled = busy;
  bannerAction.disabled = busy;
  if (kind === "apply") applyBtn.textContent = busy ? "应用中" : "应用规则";
  if (kind === "restore") restoreBtn.textContent = busy ? "恢复中" : "恢复原始状态";
}

function render(data) {
  el("status").textContent = "已连接";
  el("currentIP").textContent = data.currentIP || "--";
  el("firewallStatus").textContent = statusText(data.firewallStatus);
  renderFirewallState(data.firewallState);
  renderRuleBanner(data);
  el("portsInput").value = data.protectedPortsRaw || data.protectedPorts.join(",");

  const rows = el("entryRows");
  rows.innerHTML = "";
  for (const entry of data.entries || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code></code></td>
      <td><input class="note-edit" value=""></td>
      <td></td>
      <td><div class="row-actions"><button class="row-save" type="button">保存</button><button class="row-action" type="button">删除</button></div></td>
    `;
    tr.children[0].querySelector("code").textContent = entry.ip;
    tr.children[1].querySelector("input").value = entry.note || "";
    tr.children[2].textContent = fmtDate(entry.updatedAt);
    tr.children[3].querySelector(".row-save").addEventListener("click", async () => {
      await updateNote(entry.id, tr.children[1].querySelector("input").value);
    });
    tr.children[3].querySelector(".row-action").addEventListener("click", async () => {
      await removeEntry(entry.id);
    });
    rows.appendChild(tr);
  }
  el("emptyState").classList.toggle("show", !data.entries || data.entries.length === 0);
}

function renderFirewallState(state) {
  if (!state || !state.status) {
    setOperationStatus("");
    return;
  }
  const time = state.updatedAt ? fmtDate(state.updatedAt) : "";
  const suffix = time ? ` · ${time}` : "";
  const kind = state.status === "error" ? "error" : state.status === "pending" ? "pending" : "success";
  setOperationStatus(`${state.message || statusText(state.status)}${suffix}`, kind);
}

function renderRuleBanner(data) {
  const banner = el("ruleBanner");
  const title = el("ruleBannerTitle");
  const detail = el("ruleBannerDetail");
  const action = el("ruleBannerAction");
  const saved = data.firewallState || {};
  const actual = data.firewallStatus;
  const updated = saved.updatedAt ? ` · ${fmtDate(saved.updatedAt)}` : "";

  let mode = "idle";
  let heading = "规则未生效";
  let message = "当前没有检测到 ipsets 防火墙规则。配置会保存，但端口访问暂未被限制。";
  let actionText = "应用规则";
  let actionName = "apply";

  if (saved.status === "pending") {
    mode = "pending";
    heading = "配置已保存，规则待应用";
    message = `${saved.message || "端口或白名单已修改，需要点击“应用规则”后才会生效。"}${updated}`;
  } else if (saved.status === "error") {
    mode = "error";
    heading = "规则状态异常";
    message = `${saved.message || "当前规则状态和记录不一致，请重新应用或恢复规则。"}${updated}`;
  } else if (saved.status === "applied" && actual === "applied") {
    mode = "success";
    heading = "规则正在生效";
    message = `${saved.message || "当前保存的白名单和端口规则已应用。"}${updated}`;
    actionText = "刷新状态";
    actionName = "refresh";
  } else if (saved.status === "restored" || actual === "not_applied") {
    mode = "idle";
    heading = "规则未生效";
    message = `${saved.message || "当前没有启用 ipsets 防火墙规则。需要限制端口访问时请点击“应用规则”。"}${updated}`;
  } else if (actual === "unavailable") {
    mode = "error";
    heading = "无法检测规则状态";
    message = "防火墙后端不可用，暂时无法确认规则是否生效。";
    actionText = "刷新状态";
    actionName = "refresh";
  }

  banner.className = `rule-banner ${mode}`;
  title.textContent = heading;
  detail.textContent = message;
  action.textContent = actionText;
  action.dataset.action = actionName;
}

async function refresh() {
  try {
    render(await api("/api/state"));
  } catch (err) {
    el("status").textContent = "需要登录";
    toast(err.message);
  }
}

async function addCurrent() {
  await api("/api/whitelist/current", {
    method: "POST",
    body: JSON.stringify({ note: el("currentNote").value }),
  });
  el("currentNote").value = "";
  toast("当前 IP 已加入白名单，需要重新应用规则");
  await refresh();
}

async function addManual() {
  await api("/api/whitelist", {
    method: "POST",
    body: JSON.stringify({ ip: el("manualIP").value, note: el("manualNote").value }),
  });
  el("manualIP").value = "";
  el("manualNote").value = "";
  toast("IP 已加入白名单，需要重新应用规则");
  await refresh();
}

async function removeEntry(id) {
  await api(`/api/whitelist/${encodeURIComponent(id)}`, { method: "DELETE" });
  toast("白名单项已删除，需要重新应用规则");
  await refresh();
}

async function updateNote(id, note) {
  await api(`/api/whitelist/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ note }),
  });
  toast("备注已保存，需要重新应用规则");
  await refresh();
}

async function savePorts() {
  await api("/api/config/ports", {
    method: "PUT",
    body: JSON.stringify({ protectedPorts: el("portsInput").value }),
  });
  toast("端口列表已保存，需要重新应用规则");
  await refresh();
}

async function applyRules() {
  setOperationBusy("apply", true);
  setOperationStatus("正在应用防火墙规则...");
  try {
    await api("/api/apply", { method: "POST", body: "{}" });
    setOperationStatus("防火墙规则已应用", "success");
    toast("防火墙规则已应用");
    await refresh();
  } catch (err) {
    setOperationStatus(err.message, "error");
    toast(err.message);
  } finally {
    setOperationBusy("apply", false);
  }
}

async function restoreRules() {
  setOperationBusy("restore", true);
  setOperationStatus("正在恢复原始状态...");
  try {
    await api("/api/restore", { method: "POST", body: "{}" });
    setOperationStatus("已恢复原始状态", "success");
    toast("已恢复原始状态");
    await refresh();
  } catch (err) {
    setOperationStatus(err.message, "error");
    toast(err.message);
  } finally {
    setOperationBusy("restore", false);
  }
}

async function logout() {
  await api("/api/logout", { method: "POST", body: "{}" });
  redirectToLogin();
}

el("addCurrentBtn").addEventListener("click", () => addCurrent().catch((err) => toast(err.message)));
el("addManualBtn").addEventListener("click", () => addManual().catch((err) => toast(err.message)));
el("applyBtn").addEventListener("click", applyRules);
el("restoreBtn").addEventListener("click", restoreRules);
el("refreshBtn").addEventListener("click", refresh);
el("savePortsBtn").addEventListener("click", () => savePorts().catch((err) => toast(err.message)));
el("ruleBannerAction").addEventListener("click", () => {
  const action = el("ruleBannerAction").dataset.action;
  if (action === "refresh") {
    refresh().catch((err) => toast(err.message));
    return;
  }
  applyRules();
});
el("logoutBtn").addEventListener("click", () => logout().catch(() => redirectToLogin()));

refresh();
