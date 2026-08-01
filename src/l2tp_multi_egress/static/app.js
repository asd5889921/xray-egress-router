const $ = (q) => document.querySelector(q);
let csrf = sessionStorage.getItem("csrf") || "";
let state = null;
let pending = null;
let editorEgressId = "";
const testResults = {};

const esc = (v) => String(v ?? "").replace(/[&<>\"']/g, (c) => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"}[c]));
function errorText(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((x) => x.msg || JSON.stringify(x)).join("; ");
  return detail ? JSON.stringify(detail) : "请求失败";
}
function toast(message, bad = false) {
  const el = $("#toast");
  el.textContent = message;
  el.style.background = bad ? "#ba3434" : "#102b35";
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2800);
}
async function api(path, options = {}) {
  options.headers = {"Content-Type":"application/json", ...(options.headers || {})};
  if (options.method && options.method !== "GET") options.headers["X-CSRF-Token"] = csrf;
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(errorText(data.detail) || `HTTP ${response.status}`);
  return data;
}
function showDashboard() { $("#auth").classList.add("hidden"); $("#dashboard").classList.remove("hidden"); $("#logout").classList.remove("hidden"); refreshAll(); window.setInterval(refreshTraffic, 2000); }
async function refreshAll() { await Promise.all([refreshState(), refreshConnections(), refreshTraffic(), refreshSystem()]); }
async function refreshState() { const result = await api("/api/state"); state = result.state; pending = result.pending; renderRoutes(); renderPending(); }
function renderPending() {
  $("#pending").classList.toggle("hidden", !pending);
  if (pending) $("#countdown").textContent = `请在 ${Math.max(0, Math.ceil(pending.deadline_epoch - Date.now() / 1000))} 秒内确认`;
}
function toolbar(kind) { return `<div class="bulk-actions"><label><input type="checkbox" data-select-all="${kind}"> 全选</label><button class="danger" data-bulk-delete="${kind}">删除选中</button></div>`; }
function renderRoutes() {
  $("#egress-list").innerHTML = state.egresses.length ? `${toolbar("egresses")}<table><thead><tr><th></th><th>名称</th><th>类型</th><th>地址</th><th>最近测试</th><th>操作</th></tr></thead><tbody>${state.egresses.map((x) => `<tr><td><input type="checkbox" class="egress-select" value="${esc(x.id)}"></td><td>${esc(x.name)}</td><td>${esc(x.type)}</td><td>${esc(x.address)}:${x.port}</td><td class="test-result ${testResults[x.id]?.ok === false ? "bad" : ""}">${esc(testResults[x.id]?.text || "未测试")}</td><td class="actions"><button onclick="editEgress('${esc(x.id)}')">编辑</button><button onclick="testEgress('${esc(x.id)}')">测试</button><button class="danger" onclick="removeItem('egresses','${esc(x.id)}')">删除</button></td></tr>`).join("")}</tbody></table>` : "尚未配置出口";
  $("#binding-list").innerHTML = state.bindings.length ? `${toolbar("bindings")}<table><thead><tr><th></th><th>来源网段</th><th>出口</th><th>操作</th></tr></thead><tbody>${state.bindings.map((x) => `<tr><td><input type="checkbox" class="binding-select" value="${esc(x.id)}"></td><td>${esc(x.source_cidr)}</td><td>${esc(state.egresses.find((e) => e.id === x.egress_id)?.name || x.egress_id)}</td><td class="actions"><button onclick="editBinding('${esc(x.id)}')">编辑</button><button class="danger" onclick="removeItem('bindings','${esc(x.id)}')">删除</button></td></tr>`).join("")}</tbody></table>` : "尚未配置来源网段";
  document.querySelectorAll("[data-select-all]").forEach((el) => el.onchange = () => document.querySelectorAll(`.${el.dataset.selectAll === "egresses" ? "egress" : "binding"}-select`).forEach((x) => x.checked = el.checked));
  document.querySelectorAll("[data-bulk-delete]").forEach((el) => el.onclick = () => bulkDelete(el.dataset.bulkDelete));
}
function field(name, label, value = "", type = "text", required = true) { return `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" ${required ? "required" : ""}></label>`; }
const dialog = $("#editor");
const fields = $("#editor-fields");
let editorSave;
function openEditor(title, html, save) { $("#editor-title").textContent = title; fields.innerHTML = html; $("#form-error").textContent = ""; editorSave = save; dialog.showModal(); }
$("#cancel").onclick = () => dialog.close();
$("#editor-form").onsubmit = async (event) => { event.preventDefault(); try { await editorSave(new FormData(event.target)); dialog.close(); await refreshState(); toast("已应用，请在 60 秒内确认"); } catch (error) { $("#form-error").textContent = error.message; } };
function newInternalId() { return `new-${Math.random().toString(16).slice(2, 14)}`; }
async function autofillSs() {
  const uri = dialog.querySelector('[name="ss_uri"]')?.value.trim();
  if (!uri?.startsWith("ss://") || !uri.includes("@")) return;
  try {
    const parsed = await api("/api/parse-ss", {method:"POST", body:JSON.stringify({uri, egress_id:editorEgressId || newInternalId()})});
    ["name", "address", "port", "password", "method"].forEach((key) => { const input = dialog.querySelector(`[name="${key}"]`); if (input && parsed[key] != null) input.value = parsed[key]; });
  } catch (_) { /* validation is shown when the form is submitted */ }
}
async function saveEgress(form) {
  const item = {name:form.get("name"), type:form.get("type"), address:form.get("address"), port:Number(form.get("port")), username:form.get("username") || null, password:form.get("password") || null, method:form.get("method") || null};
  if (form.get("ss_uri")) Object.assign(item, await api("/api/parse-ss", {method:"POST", body:JSON.stringify({uri:form.get("ss_uri"), egress_id:editorEgressId || newInternalId()})}));
  if (editorEgressId) item.id = editorEgressId;
  await api(editorEgressId ? `/api/egresses/${encodeURIComponent(editorEgressId)}` : "/api/egresses", {method:editorEgressId ? "PUT" : "POST", body:JSON.stringify(item)});
}
window.editEgress = (id = "") => {
  editorEgressId = id;
  const x = state.egresses.find((e) => e.id === id) || {name:"", type:"shadowsocks", address:"", port:8388, username:"", password:"", method:"aes-256-gcm"};
  const draw = (type) => {
    const common = `${field("name", "名称", x.name)}<label>类型<select name="type"><option value="shadowsocks">Shadowsocks</option><option value="socks">SOCKS5</option><option value="http">HTTP</option></select></label>`;
    const proxy = type === "shadowsocks"
      ? `${field("ss_uri", "ss:// 链接（可选）", "", "text", false)}${field("address", "服务器地址", x.address)}${field("port", "端口", x.port, "number")}${field("password", "密码", x.password || "", "password")}${field("method", "加密方式", x.method || "aes-256-gcm")}`
      : `${field("address", "服务器地址", x.address)}${field("port", "端口", x.port, "number")}${field("username", "用户名（可选）", x.username || "", "text", false)}${field("password", "密码（可选）", x.password || "", "password", false)}`;
    fields.innerHTML = common + proxy;
    dialog.querySelector('[name="type"]').value = type;
    dialog.querySelector('[name="type"]').onchange = (event) => draw(event.target.value);
    dialog.querySelector('[name="ss_uri"]')?.addEventListener("input", autofillSs);
  };
  openEditor(id ? "编辑 Xray 出口" : "新增 Xray 出口", "", saveEgress);
  draw(x.type);
};
window.editBinding = (id = "") => {
  const x = state.bindings.find((b) => b.id === id) || {source_cidr:"", egress_id:state.egresses[0]?.id || "", enabled:true};
  openEditor(id ? "编辑分流" : "新增分流", `${field("source_cidr", "来源网段 CIDR", x.source_cidr)}<label>出口<select name="egress_id">${state.egresses.map((e) => `<option value="${esc(e.id)}">${esc(e.name)}</option>`).join("")}</select></label><label class="toggle"><input name="enabled" type="checkbox" ${x.enabled ? "checked" : ""}> 启用</label>`, async (form) => {
    const item = {source_cidr:form.get("source_cidr"), egress_id:form.get("egress_id"), enabled:!!form.get("enabled")};
    if (id) { item.id = id; item.tproxy_port = x.tproxy_port; item.mark = x.mark; await api(`/api/bindings/${encodeURIComponent(id)}`, {method:"PUT", body:JSON.stringify(item)}); }
    else await api("/api/bindings", {method:"POST", body:JSON.stringify(item)});
  });
  dialog.querySelector('[name="egress_id"]').value = x.egress_id;
};
$("#add-egress").onclick = () => editEgress();
$("#add-binding").onclick = () => state.egresses.length ? editBinding() : toast("请先新增出口", true);
window.removeItem = async (type, id) => { if (!confirm("确定删除？")) return; try { await api(`/api/${type}/${encodeURIComponent(id)}`, {method:"DELETE"}); await refreshState(); } catch (error) { toast(error.message, true); } };
async function bulkDelete(type) { const selector = type === "egresses" ? ".egress-select" : ".binding-select"; const ids = [...document.querySelectorAll(`${selector}:checked`)].map((x) => x.value); if (!ids.length) return toast("请先选择项目", true); if (!confirm(`确定删除选中的 ${ids.length} 项？`)) return; try { await api(`/api/${type}/bulk-delete`, {method:"POST", body:JSON.stringify({ids})}); await refreshState(); } catch (error) { toast(error.message, true); } }
window.testEgress = async (id) => { try { const result = await api(`/api/egresses/${encodeURIComponent(id)}/test`, {method:"POST"}); testResults[id] = {ok:result.ok, text:result.ok ? `${result.latency_ms} ms（启动 ${result.startup_ms ?? "?"} ms）` : (result.detail || "失败")}; renderRoutes(); } catch (error) { testResults[id] = {ok:false, text:error.message}; renderRoutes(); } };
async function refreshConnections() { try { const rows = await api("/api/connections"); $("#connection-list").innerHTML = rows.length ? `<table><thead><tr><th>接口</th><th>账号</th><th>协商 IP</th><th>来源诊断</th></tr></thead><tbody>${rows.map((x) => `<tr><td>${esc(x.interface)}</td><td>${esc(x.username)}</td><td>${esc(x.peer_ip)}</td><td>${esc(x.diagnostics.warning || x.diagnostics.observed_networks.join(", ") || "暂无样本")}</td></tr>`).join("")}</tbody></table>` : "暂无在线连接"; } catch (error) { toast(error.message, true); } }
function formatRate(bytes) { if (!bytes) return "0 B/s"; const units = ["B/s", "KB/s", "MB/s", "GB/s"]; let value = bytes; let index = 0; while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; } return `${value >= 10 || index === 0 ? Math.round(value) : value.toFixed(1)} ${units[index]}`; }
async function refreshTraffic() { try { const rows = await api("/api/traffic"); $("#traffic-list").innerHTML = rows.length ? `<table><thead><tr><th>来源内网 IP</th><th>匹配网段</th><th>当前出口</th><th class="rate">上行</th><th class="rate">下行</th></tr></thead><tbody>${rows.map((x) => `<tr><td><code>${esc(x.source_ip)}</code></td><td><code>${esc(x.source_cidr || "未匹配")}</code></td><td>${x.egress ? `${esc(x.egress.name)}<span class="traffic-type">${esc(x.egress.type)}</span>` : '<span class="bad">未匹配出口</span>'}</td><td class="rate">${formatRate(x.upstream_bps)}</td><td class="rate">${formatRate(x.downstream_bps)}</td></tr>`).join("")}</tbody></table>` : "暂无正在使用的内网 IP"; $("#traffic-updated").textContent = `● 已更新 ${new Date().toLocaleTimeString()}`; } catch (error) { toast(error.message, true); } }
async function refreshSystem() { try { const data = await api("/api/system"); $("#system-list").innerHTML = `<p>Xray: ${esc(data.xray_version)}</p>` + Object.entries(data.services).map(([name, status]) => `<div class="section-title"><span>${esc(name)} <strong class="${status === "active" ? "ok" : "bad"}">${esc(status)}</strong></span><button onclick="restartService('${esc(name)}')">重启</button></div>`).join(""); const log = await api("/api/log-settings"); $("#xray-log-level").value = log.xray_log_level; $("#log-retention-days").value = log.log_retention_days; } catch (error) { toast(error.message, true); } }
window.restartService = async (name) => { try { await api(`/api/system/${name}/restart`, {method:"POST"}); await refreshSystem(); } catch (error) { toast(error.message, true); } };
$("#save-log-settings").onclick = async () => { try { await api("/api/log-settings", {method:"PUT", body:JSON.stringify({xray_log_level:$("#xray-log-level").value, log_retention_days:Number($("#log-retention-days").value)})}); await api("/api/system/xray/restart", {method:"POST"}); await api("/api/system/xrer-watchdog/restart", {method:"POST"}); await refreshSystem(); } catch (error) { toast(error.message, true); } };
$("#export-config").onclick = async () => { try { const response = await fetch("/api/config/export"); if (!response.ok) throw Error(`HTTP ${response.status}`); const a = document.createElement("a"); a.href = URL.createObjectURL(await response.blob()); a.download = "xrer-config.json"; a.click(); } catch (error) { toast(error.message, true); } };
$("#import-config").onclick = () => $("#import-file").click();
$("#import-file").onchange = async (event) => { const file = event.target.files?.[0]; event.target.value = ""; if (!file) return; try { const backup = JSON.parse(await file.text()); if (!confirm("确认导入配置？当前配置会先自动保存。")) return; await api("/api/config/import", {method:"POST", body:JSON.stringify({backup})}); await refreshState(); } catch (error) { toast(`导入失败：${error.message}`, true); } };
document.querySelectorAll("nav button").forEach((button) => button.onclick = () => { document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === button)); document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("hidden", x.id !== button.dataset.tab)); });
$("#auth-form").onsubmit = async (event) => { event.preventDefault(); try { const body = JSON.stringify({username:$("#username").value, password:$("#password").value}); if (!(await api("/api/bootstrap")).initialized) { await api("/api/initialize", {method:"POST", body}); toast("管理员已初始化，请重新登录"); return; } const result = await api("/api/login", {method:"POST", body}); csrf = result.csrf; sessionStorage.setItem("csrf", csrf); showDashboard(); } catch (error) { toast(error.message, true); } };
$("#logout").onclick = async () => { try { await api("/api/logout", {method:"POST"}); } finally { sessionStorage.clear(); location.reload(); } };
$("#confirm").onclick = async () => { try { await api(`/api/transactions/${pending.id}/confirm`, {method:"POST"}); pending = null; renderPending(); } catch (error) { toast(error.message, true); } };
$("#rollback").onclick = async () => { try { await api(`/api/transactions/${pending.id}/rollback`, {method:"POST"}); await refreshState(); } catch (error) { toast(error.message, true); } };
document.querySelectorAll("[data-refresh]").forEach((button) => button.onclick = () => button.dataset.refresh === "system" ? refreshSystem() : refreshConnections());
(async () => { try { const info = await api("/api/bootstrap"); $("#auth-title").textContent = info.initialized ? "登录" : "初始化管理员"; if (csrf) { await api("/api/state"); showDashboard(); } } catch (error) { toast(error.message, true); } })();
