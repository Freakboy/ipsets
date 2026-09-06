const state = {
  username: localStorage.getItem("ipsets.username") || "admin",
  busyDepth: 0,
  entries: [],
  data: {},
  sort: { key: "order", direction: "asc" },
  draggedID: "",
};

const el = (id) => document.getElementById(id);
const controlsSelector = "button, input, textarea, select";

function redirectToLogin() {
  const next = encodeURIComponent(`${location.pathname}${location.search}`);
  location.href = `/login.html?next=${next}`;
}

async function api(path, options = {}) {
  beginGlobalLoading(options.loadingText || "正在处理...");
  try {
    const { loadingText: _, ...fetchOptions } = options;
    const res = await fetch(path, {
      ...fetchOptions,
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
  } finally {
    endGlobalLoading();
  }
}

function beginGlobalLoading(message) {
  const loading = el("globalLoading");
  const loadingText = el("globalLoadingText");
  if (loadingText) loadingText.textContent = message || "正在处理...";
  state.busyDepth += 1;
  if (state.busyDepth !== 1) return;
  if (loading) loading.hidden = false;
  document.querySelectorAll(controlsSelector).forEach((control) => {
    if (control.disabled) {
      control.dataset.wasDisabled = "true";
      return;
    }
    control.disabled = true;
  });
}

function endGlobalLoading() {
  state.busyDepth = Math.max(0, state.busyDepth - 1);
  if (state.busyDepth !== 0) return;
  const loading = el("globalLoading");
  if (loading) loading.hidden = true;
  document.querySelectorAll(controlsSelector).forEach((control) => {
    if (control.dataset.wasDisabled === "true") {
      delete control.dataset.wasDisabled;
      return;
    }
    control.disabled = false;
  });
}

async function withGlobalLoading(message, action) {
  beginGlobalLoading(message);
  try {
    return await action();
  } finally {
    endGlobalLoading();
  }
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
  const syncCloudflareBtn = el("syncCloudflareBtn");
  if (kind === "apply") applyBtn.textContent = busy ? "应用中" : "应用规则";
  if (kind === "restore") restoreBtn.textContent = busy ? "恢复中" : "恢复原始状态";
  if (kind === "cloudflare") syncCloudflareBtn.textContent = busy ? "更新中" : "更新 Cloudflare 代理 IP";
}

function render(data) {
  state.data = data;
  el("status").textContent = "已连接";
  el("currentIP").textContent = data.currentIP || "--";
  el("firewallStatus").textContent = statusText(data.firewallStatus);
  renderFirewallState(data.firewallState);
  renderRuleBanner(data);
  el("portsInput").value = data.protectedPortsRaw || data.protectedPorts.join(",");

  state.entries = data.entries || [];
  const rows = el("entryRows");
  rows.innerHTML = "";
  const entries = [...state.entries].sort(compareEntries);
  entries.forEach((entry, index) => {
    const tr = document.createElement("tr");
    tr.draggable = true;
    tr.dataset.entryId = entry.id;
    tr.innerHTML = `
      <td class="entry-order"></td>
      <td><code></code></td>
      <td><input class="note-edit" value=""></td>
      <td></td>
      <td><div class="row-actions"><button class="row-save" type="button">保存</button><button class="row-action" type="button">删除</button></div></td>
    `;
    tr.children[0].textContent = index + 1;
    tr.children[1].querySelector("code").textContent = entry.ip;
    tr.children[2].querySelector("input").value = entry.note || "";
    tr.children[3].textContent = fmtDate(entry.updatedAt);
    tr.children[4].querySelector(".row-save").addEventListener("click", async () => {
      await updateNote(entry.id, tr.children[2].querySelector("input").value);
    });
    tr.children[4].querySelector(".row-action").addEventListener("click", async () => {
      await removeEntry(entry.id);
    });
    tr.addEventListener("dragstart", () => {
      state.draggedID = entry.id;
      tr.classList.add("dragging");
    });
    tr.addEventListener("dragend", () => {
      state.draggedID = "";
      tr.classList.remove("dragging");
    });
    tr.addEventListener("dragover", (event) => {
      event.preventDefault();
      tr.classList.add("drag-over");
    });
    tr.addEventListener("dragleave", () => tr.classList.remove("drag-over"));
    tr.addEventListener("drop", () => reorderEntries(entry.id));
    rows.appendChild(tr);
  });
  el("emptyState").classList.toggle("show", entries.length === 0);
  updateSortButtons();
}

function compareEntries(left, right) {
  const direction = state.sort.direction === "asc" ? 1 : -1;
  let result = 0;
  if (state.sort.key === "order") result = left.order - right.order;
  if (state.sort.key === "ip") result = compareIP(left.ip, right.ip);
  if (state.sort.key === "note") result = (left.note || "").localeCompare(right.note || "", "zh-CN");
  if (state.sort.key === "updatedAt") result = new Date(left.updatedAt) - new Date(right.updatedAt);
  return result === 0 ? left.ip.localeCompare(right.ip) : result * direction;
}

function compareIP(left, right) {
  const leftParts = left.split("/")[0].split(".").map(Number);
  const rightParts = right.split("/")[0].split(".").map(Number);
  if (leftParts.length === 4 && rightParts.length === 4) {
    for (let i = 0; i < 4; i += 1) {
      if (leftParts[i] !== rightParts[i]) return leftParts[i] - rightParts[i];
    }
    return Number(left.split("/")[1] || 32) - Number(right.split("/")[1] || 32);
  }
  return left.localeCompare(right);
}

function updateSortButtons() {
  document.querySelectorAll(".sortable").forEach((header) => {
    const active = header.dataset.sortKey === state.sort.key;
    header.dataset.direction = active ? state.sort.direction : "";
    header.setAttribute("aria-sort", active ? state.sort.direction : "none");
  });
}

async function reorderEntries(targetID) {
  if (!state.draggedID || state.draggedID === targetID) return;
  const entries = [...state.entries].sort(compareEntries);
  const from = entries.findIndex((entry) => entry.id === state.draggedID);
  const to = entries.findIndex((entry) => entry.id === targetID);
  if (from < 0 || to < 0) return;
  const [moved] = entries.splice(from, 1);
  entries.splice(to, 0, moved);
  state.sort = { key: "order", direction: "asc" };
  state.entries = entries.map((entry, order) => ({ ...entry, order }));
  render({ ...state.data, entries: state.entries });
  try {
    await api("/api/whitelist/order", {
      method: "PUT",
      body: JSON.stringify({ ids: entries.map((entry) => entry.id) }),
      loadingText: "正在保存白名单顺序...",
    });
    toast("白名单顺序已保存");
  } catch (err) {
    toast(err.message);
    await refresh();
  }
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
    render(await api("/api/state", { loadingText: "正在刷新状态..." }));
  } catch (err) {
    el("status").textContent = "需要登录";
    toast(err.message);
  }
}

async function addCurrent() {
  await withGlobalLoading("正在添加当前 IP...", async () => {
    await api("/api/whitelist/current", {
      method: "POST",
      body: JSON.stringify({ note: el("currentNote").value }),
      loadingText: "正在保存白名单...",
    });
    el("currentNote").value = "";
    toast("当前 IP 已加入白名单，需要重新应用规则");
    await refresh();
  });
}

async function addManual() {
  await withGlobalLoading("正在添加 IP / CIDR...", async () => {
    await api("/api/whitelist", {
      method: "POST",
      body: JSON.stringify({ ip: el("manualIP").value, note: el("manualNote").value }),
      loadingText: "正在保存白名单...",
    });
    el("manualIP").value = "";
    el("manualNote").value = "";
    toast("IP 已加入白名单，需要重新应用规则");
    await refresh();
  });
}

async function removeEntry(id) {
  await withGlobalLoading("正在删除白名单项...", async () => {
    await api(`/api/whitelist/${encodeURIComponent(id)}`, { method: "DELETE", loadingText: "正在删除白名单项..." });
    toast("白名单项已删除，需要重新应用规则");
    await refresh();
  });
}

async function updateNote(id, note) {
  await withGlobalLoading("正在保存备注...", async () => {
    await api(`/api/whitelist/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ note }),
      loadingText: "正在保存备注...",
    });
    toast("备注已保存，需要重新应用规则");
    await refresh();
  });
}

async function savePorts() {
  await withGlobalLoading("正在保存端口列表...", async () => {
    await api("/api/config/ports", {
      method: "PUT",
      body: JSON.stringify({ protectedPorts: el("portsInput").value }),
      loadingText: "正在保存端口列表...",
    });
    toast("端口列表已保存，需要重新应用规则");
    await refresh();
  });
}

async function syncCloudflare() {
  await withGlobalLoading("正在更新 Cloudflare 代理 IP...", async () => {
    setOperationBusy("cloudflare", true);
    setOperationStatus("正在更新 Cloudflare 代理 IP...");
    try {
      const result = await api("/api/whitelist/cloudflare", {
        method: "POST",
        body: "{}",
        loadingText: "正在更新 Cloudflare 代理 IP...",
      });
      const message = `Cloudflare 代理 IP 已更新：新增 ${result.added}，更新 ${result.updated}，移除 ${result.removed}，需要重新应用规则`;
      setOperationStatus(message, "pending");
      toast(message);
      await refresh();
    } catch (err) {
      setOperationStatus(err.message, "error");
      toast(err.message);
    } finally {
      setOperationBusy("cloudflare", false);
    }
  });
}

async function applyRules() {
  await withGlobalLoading("正在应用防火墙规则...", async () => {
    setOperationBusy("apply", true);
    setOperationStatus("正在应用防火墙规则...");
    try {
      await api("/api/apply", { method: "POST", body: "{}", loadingText: "正在应用防火墙规则..." });
      setOperationStatus("防火墙规则已应用", "success");
      toast("防火墙规则已应用");
      await refresh();
    } catch (err) {
      setOperationStatus(err.message, "error");
      toast(err.message);
    } finally {
      setOperationBusy("apply", false);
    }
  });
}

async function restoreRules() {
  await withGlobalLoading("正在恢复原始状态...", async () => {
    setOperationBusy("restore", true);
    setOperationStatus("正在恢复原始状态...");
    try {
      await api("/api/restore", { method: "POST", body: "{}", loadingText: "正在恢复原始状态..." });
      setOperationStatus("已恢复原始状态", "success");
      toast("已恢复原始状态");
      await refresh();
    } catch (err) {
      setOperationStatus(err.message, "error");
      toast(err.message);
    } finally {
      setOperationBusy("restore", false);
    }
  });
}

async function logout() {
  await withGlobalLoading("正在退出登录...", async () => {
    await api("/api/logout", { method: "POST", body: "{}", loadingText: "正在退出登录..." });
    redirectToLogin();
  });
}

el("addCurrentBtn").addEventListener("click", () => addCurrent().catch((err) => toast(err.message)));
el("addManualBtn").addEventListener("click", () => addManual().catch((err) => toast(err.message)));
el("syncCloudflareBtn").addEventListener("click", syncCloudflare);
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
document.querySelectorAll(".sortable").forEach((header) => {
  const sort = () => {
    const key = header.dataset.sortKey;
    if (state.sort.key === key) {
      state.sort.direction = state.sort.direction === "asc" ? "desc" : "asc";
    } else {
      state.sort = { key, direction: "asc" };
    }
    render({ ...state.data, entries: state.entries });
  };
  header.addEventListener("click", sort);
  header.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      sort();
    }
  });
});

refresh();
