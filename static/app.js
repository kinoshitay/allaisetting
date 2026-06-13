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
  const skills = filterItems(state.report.skills || [], (skill) => `${skill.name} ${skill.path} ${skill.source} ${skill.description} ${skill.meaning_ja || ""} ${skill.share_status || ""} ${skill.share_reason || ""} ${(skill.github_urls || []).join(" ")}`);
  panels.skills.innerHTML = skills.length ? sectionTable("Skills", ["Skill", "シンプルな説明", "入っている場所", "共有"], skills.map((skill) => [
    nameCell(skill.name, skill.path, skill.github_urls),
    conciseText(skill.meaning_ja || "", skill.name),
    sourceCell(skill.source),
    shareCell(skill),
  ]), true) : emptyHtml();

  panels.skills.querySelectorAll("[data-share-skill-path]").forEach((button) => {
    button.addEventListener("click", () => shareSkill(button.dataset.shareSkillPath));
  });
}

function renderMcp() {
  const mcp = filterItems(state.report.mcp || [], (item) => `${item.path} ${item.meaning_ja || ""} ${JSON.stringify(item.servers || [])} ${(item.github_urls || []).join(" ")}`);
  const rows = mcp.flatMap((item) => {
    const servers = item.servers && item.servers.length ? item.servers : [{ name: "-", meaning_ja: "MCPサーバー名を検出できませんでした。", github_urls: item.github_urls }];
    return servers.map((server) => [
      nameCell(server.name, item.path, server.github_urls || item.github_urls),
      conciseText(server.meaning_ja || "", server.name),
    ]);
  });
  panels.mcp.innerHTML = rows.length ? sectionTable("MCP", ["MCP", "シンプルな説明"], rows, true) : emptyHtml();
}

function renderFiles() {
  const files = filterItems(state.report.context_files || [], (item) => `${item.path} ${item.category} ${item.meaning_ja || ""} ${item.preview || ""} ${(item.github_urls || []).join(" ")}`);
  panels.files.innerHTML = files.length ? sectionTable("Files", ["ファイル", "シンプルな説明"], files.map((item) => [
    nameCell(shortName(item.path), item.path, item.github_urls),
    `${escapeHtml(item.meaning_ja || "")}<div class="meta">${escapeHtml(item.category)} · ${escapeHtml(item.type || "file")} · ${item.size || 0} bytes</div>`,
  ]), true) : emptyHtml();
}

function renderCleanup() {
  const candidates = filterItems(state.report.cleanup_candidates || [], (item) => `${item.path} ${item.reason || ""}`);
  panels.cleanup.innerHTML = candidates.length ? sectionTable("Cleanup", ["ファイル", "理由", "操作"], candidates.map((item) => [
    `<code title="${escapeAttribute(item.path)}">${escapeHtml(shortName(item.path))}</code><div class="meta">${escapeHtml(item.type || "file")} · ${item.size || 0} bytes</div>`,
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

async function shareSkill(path) {
  if (!path) return;
  const ok = window.confirm(`このSkillを共有フォルダへコピーしますか？\n\n${path}\n\n元のSkillは残します。`);
  if (!ok) return;
  const response = await fetch("/api/share-skill", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) {
    window.alert(payload.error || "Share failed.");
    return;
  }
  window.alert(`共有フォルダへコピーしました:\n${payload.copied_to}`);
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

function nameCell(name, title, urls) {
  const url = preferredUrl(urls);
  const code = `<code title="${escapeAttribute(title || "")}">${escapeHtml(name)}</code>`;
  return url ? `<a class="name-link" href="${escapeAttribute(url)}" target="_blank" rel="noreferrer">${code}</a>` : code;
}

function conciseText(text, fallback) {
  return escapeHtml(text || `${fallback} の設定です。`)
    .replaceAll(" MCP経由でエージェントから使えるようにする接続です。", " 連携です。")
    .replaceAll(" という名前の作業能力として検出されました。", " です。");
}

function sourceCell(source) {
  return `<span class="source-label">${escapeHtml(sourceLabel(source))}</span>`;
}

function shareCell(skill) {
  if (skill.share_allowed) {
    return `<button class="small-button" type="button" title="${escapeAttribute(skill.share_reason || "")}" data-share-skill-path="${escapeAttribute(skill.path)}">共有へコピー</button>`;
  }
  return `<span class="status-label" title="${escapeAttribute(skill.share_reason || "")}">${escapeHtml(skill.share_status || "-")}</span>`;
}

function sourceLabel(source) {
  const labels = {
    "Codex": "Codex",
    "Codex plugin cache": "Codex",
    "Codex system": "Codex system",
    "Claude": "Claude Code",
    "Claude Code plugin cache": "Claude Code",
    "Claude Code system": "Claude system",
    "Claude Code marketplace": "Claude Marketplace",
    "Agents shared skills": "共有",
  };
  return labels[source] || source || "-";
}

function shortName(path) {
  return String(path || "").split("/").filter(Boolean).pop() || path;
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
