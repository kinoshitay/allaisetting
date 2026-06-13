const state = {
  report: null,
  tab: "settings",
  filter: "",
};

const summaryEl = document.querySelector("#summary");
const panels = {
  settings: document.querySelector("#settingsPanel"),
  skills: document.querySelector("#skillsPanel"),
  mcp: document.querySelector("#mcpPanel"),
  files: document.querySelector("#filesPanel"),
  cleanup: document.querySelector("#cleanupPanel"),
};
const emptyTemplate = document.querySelector("#emptyTemplate");

document.querySelector("#scanButton").addEventListener("click", scan);
document.querySelector("#filterInput").addEventListener("input", (event) => {
  state.filter = event.target.value.toLowerCase();
  render();
});
document.querySelector("#previewToggle").addEventListener("change", scan);
document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    state.tab = button.dataset.tab;
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab === button));
    Object.entries(panels).forEach(([key, panel]) => panel.classList.toggle("active", key === state.tab));
  });
});

async function scan() {
  const includePreviews = document.querySelector("#previewToggle").checked ? "1" : "0";
  document.querySelector("#scanButton").textContent = "Scanning...";
  document.querySelector("#scanButton").disabled = true;
  try {
    const response = await fetch(`/api/scan?previews=${includePreviews}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`Scan failed: ${response.status}`);
    state.report = await response.json();
    render();
  } catch (error) {
    summaryEl.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  } finally {
    document.querySelector("#scanButton").textContent = "Scan";
    document.querySelector("#scanButton").disabled = false;
  }
}

function render() {
  if (!state.report) return;
  renderSummary();
  renderSettings();
  renderSkills();
  renderMcp();
  renderFiles();
  renderCleanup();
}

function renderSummary() {
  const summary = state.report.summary || {};
  const metrics = [
    ["Context files", summary.context_files || 0],
    ["Skills", summary.skills || 0],
    ["MCP files", summary.mcp_config_files || 0],
    ["MCP servers", summary.mcp_servers || 0],
    ["Cleanup", summary.cleanup_candidates || 0],
  ];
  summaryEl.innerHTML = metrics.map(([label, value]) => `
    <article class="metric">
      <span>${label}</span>
      <strong>${value}</strong>
    </article>
  `).join("");
}

function renderSettings() {
  const settings = state.report.settings || {};
  const device = settings.device || {};
  const versions = settings.cli_versions || [];
  const env = settings.environment || {};
  const paths = settings.known_paths || [];
  panels.settings.innerHTML = `
    ${sectionTable("Device", ["Key", "Value"], Object.entries(device).map(([key, value]) => [key, String(value)]))}
    ${sectionTable("CLI Versions", ["Command", "Version"], versions.map((item) => [item.command, item.version]))}
    ${sectionTable("Known Paths", ["Status", "Path"], paths.map((item) => [item.exists ? "exists" : "missing", item.path]))}
    ${sectionTable("Environment", ["Key", "Value"], Object.entries(env).map(([key, value]) => [key, String(value)]))}
  `;
}

function renderSkills() {
  const skills = filterItems(state.report.skills || [], (skill) => `${skill.name} ${skill.path} ${skill.source} ${skill.description} ${skill.meaning_ja || ""} ${(skill.github_urls || []).join(" ")}`);
  panels.skills.innerHTML = skills.length ? sectionTable("Skills", ["スキル", "種別", "概要", "GitHub"], skills.map((skill) => [
    `<strong>${escapeHtml(skill.name)}</strong><div class="path">${escapeHtml(skill.path)}</div>`,
    skill.source,
    skill.meaning_ja || "",
    linkCell(skill.github_urls),
  ]), true) : emptyHtml();
}

function renderMcp() {
  const mcp = filterItems(state.report.mcp || [], (item) => `${item.path} ${item.meaning_ja || ""} ${JSON.stringify(item.servers || [])} ${(item.github_urls || []).join(" ")}`);
  const rows = mcp.flatMap((item) => {
    const servers = item.servers && item.servers.length ? item.servers : [{ name: "-", meaning_ja: "MCPサーバー名を検出できませんでした。", github_urls: item.github_urls }];
    return servers.map((server) => [
      `<strong>${escapeHtml(item.path)}</strong><div class="meta">${escapeHtml(item.meaning_ja || "MCP設定ファイルです。")}</div>`,
      `<span class="pill">${escapeHtml(server.name)}</span>`,
      server.meaning_ja || "",
      linkCell(server.github_urls || item.github_urls),
    ]);
  });
  panels.mcp.innerHTML = rows.length ? sectionTable("MCP", ["設定ファイル", "サーバー", "概要", "GitHub"], rows, true) : emptyHtml();
}

function renderFiles() {
  const files = filterItems(state.report.context_files || [], (item) => `${item.path} ${item.category} ${item.meaning_ja || ""} ${item.preview || ""} ${(item.github_urls || []).join(" ")}`);
  panels.files.innerHTML = files.length ? sectionTable("Files", ["ファイル", "種別", "概要", "GitHub"], files.map((item) => [
    `<strong>${escapeHtml(item.path)}</strong><div class="meta">${escapeHtml(item.type || "file")} · ${item.size || 0} bytes</div>`,
    item.category,
    item.meaning_ja || "",
    linkCell(item.github_urls),
  ]), true) : emptyHtml();
}

function renderCleanup() {
  const candidates = filterItems(state.report.cleanup_candidates || [], (item) => `${item.path} ${item.reason || ""}`);
  panels.cleanup.innerHTML = candidates.length ? sectionTable("Cleanup", ["ファイル", "理由", "操作"], candidates.map((item) => [
    `<strong>${escapeHtml(item.path)}</strong><div class="meta">${escapeHtml(item.type || "file")} · ${item.size || 0} bytes</div>`,
    item.reason || "隔離候補です。",
    `<button class="danger-button" type="button" data-quarantine-path="${escapeAttribute(item.path)}">Quarantine</button>`,
  ]), true) : `<div class="empty">No cleanup candidates.</div>`;

  panels.cleanup.querySelectorAll("[data-quarantine-path]").forEach((button) => {
    button.addEventListener("click", () => quarantinePath(button.dataset.quarantinePath));
  });
}

async function quarantinePath(path) {
  if (!path) return;
  const ok = window.confirm(`このファイルを隔離しますか？\n\n${path}\n\n完全削除ではなく ~/.all-ai-setting-trash に移動します。`);
  if (!ok) return;
  const response = await fetch("/api/quarantine", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) {
    window.alert(payload.error || "Quarantine failed.");
    return;
  }
  window.alert(`隔離しました:\n${payload.moved_to}`);
  scan();
}

function sectionTable(title, headers, rows, rawHtml = false) {
  return `
    <section class="table-section">
      <h2>${escapeHtml(title)}</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${rows.map((row) => `<tr>${row.map((cell) => `<td>${rawHtml ? cell : escapeHtml(cell)}</td>`).join("")}</tr>`).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function linksHtml(urls) {
  if (!urls || !urls.length) return "";
  const url = preferredUrl(urls);
  if (!url) return "";
  return `<div class="links"><a href="${escapeAttribute(url)}" target="_blank" rel="noreferrer">GitHub</a></div>`;
}

function linkCell(urls) {
  const url = preferredUrl(urls);
  return url ? `<a class="table-link" href="${escapeAttribute(url)}" target="_blank" rel="noreferrer">GitHub</a>` : "";
}

function uniqueUrls(urls) {
  return [...new Set((urls || []).filter(Boolean))];
}

function preferredUrl(urls) {
  const unique = uniqueUrls(urls);
  return unique.find((url) => url.includes("/tree/")) || unique[0] || "";
}

function filterItems(items, stringify) {
  if (!state.filter) return items;
  return items.filter((item) => stringify(item).toLowerCase().includes(state.filter));
}

function emptyHtml() {
  return emptyTemplate.innerHTML;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("'", "&#39;");
}

scan();
