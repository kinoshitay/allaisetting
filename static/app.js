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
}

function renderSummary() {
  const summary = state.report.summary || {};
  const metrics = [
    ["Context files", summary.context_files || 0],
    ["Skills", summary.skills || 0],
    ["MCP files", summary.mcp_config_files || 0],
    ["MCP servers", summary.mcp_servers || 0],
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
    <div class="settings-grid">
      ${settingsCard("Device", keyValues(device))}
      ${settingsCard("CLI Versions", versions.map((item) => `<p><strong>${escapeHtml(item.command)}</strong><br><span class="meta">${escapeHtml(item.version)}</span></p>`).join(""))}
      ${settingsCard("Known Paths", paths.map((item) => `<p><span class="pill ${item.exists ? "" : "warn"}">${item.exists ? "exists" : "missing"}</span> <span class="path">${escapeHtml(item.path)}</span></p>`).join(""))}
      ${settingsCard("Environment", keyValues(env))}
    </div>
  `;
}

function renderSkills() {
  const skills = filterItems(state.report.skills || [], (skill) => `${skill.name} ${skill.path} ${skill.source} ${skill.description} ${skill.meaning_ja || ""} ${(skill.github_urls || []).join(" ")}`);
  panels.skills.innerHTML = skills.length ? skills.map((skill) => `
    <article class="item">
      <div class="item-header">
        <div>
          <h2>${escapeHtml(skill.name)}</h2>
          <div class="path">${escapeHtml(skill.path)}</div>
        </div>
        <span class="pill">${escapeHtml(skill.source)}</span>
      </div>
      ${skill.meaning_ja ? `<p class="meaning">${escapeHtml(skill.meaning_ja)}</p>` : ""}
      ${linksHtml(skill.github_urls)}
      ${skill.error ? `<p class="meta">${escapeHtml(skill.error)}</p>` : ""}
    </article>
  `).join("") : emptyHtml();
}

function renderMcp() {
  const mcp = filterItems(state.report.mcp || [], (item) => `${item.path} ${item.meaning_ja || ""} ${JSON.stringify(item.servers || [])} ${(item.github_urls || []).join(" ")}`);
  panels.mcp.innerHTML = mcp.length ? mcp.map((item) => {
    const servers = item.servers && item.servers.length
      ? item.servers.map((server) => `
          <div class="server-row">
            <span class="pill">${escapeHtml(server.name)}</span>
            ${server.meaning_ja ? `<span class="server-meaning">${escapeHtml(server.meaning_ja)}</span>` : ""}
            ${linksHtml(uniqueUrls(server.github_urls))}
          </div>
        `).join("")
      : `<span class="pill warn">No names detected</span>`;
    return `
      <article class="item">
        <h2>${escapeHtml(item.path)}</h2>
        ${item.meaning_ja ? `<p class="meaning">${escapeHtml(item.meaning_ja)}</p>` : ""}
        <div class="server-list">${servers}</div>
      </article>
    `;
  }).join("") : emptyHtml();
}

function renderFiles() {
  const files = filterItems(state.report.context_files || [], (item) => `${item.path} ${item.category} ${item.meaning_ja || ""} ${item.preview || ""} ${(item.github_urls || []).join(" ")}`);
  panels.files.innerHTML = files.length ? files.map((item) => `
    <article class="item">
      <div class="item-header">
        <div>
          <h2>${escapeHtml(item.path)}</h2>
          <div class="meta">${escapeHtml(item.category)} · ${escapeHtml(item.type || "file")} · ${item.size || 0} bytes</div>
        </div>
        <span class="pill">${escapeHtml(item.exists ? "found" : "missing")}</span>
      </div>
      ${item.meaning_ja ? `<p class="meaning">${escapeHtml(item.meaning_ja)}</p>` : ""}
      ${linksHtml(item.github_urls)}
      ${item.error ? `<p class="meta">${escapeHtml(item.error)}</p>` : ""}
    </article>
  `).join("") : emptyHtml();
}

function settingsCard(title, body) {
  return `<article class="settings-card"><h2>${title}</h2>${body || `<p class="meta">No data.</p>`}</article>`;
}

function keyValues(object) {
  return `<dl class="kv">${Object.entries(object).map(([key, value]) => `
    <dt>${escapeHtml(key)}</dt>
    <dd>${escapeHtml(String(value))}</dd>
  `).join("")}</dl>`;
}

function linksHtml(urls) {
  if (!urls || !urls.length) return "";
  return `<div class="links">${uniqueUrls(urls).map((url) => `<a href="${escapeAttribute(url)}" target="_blank" rel="noreferrer">GitHub</a>`).join("")}</div>`;
}

function uniqueUrls(urls) {
  return [...new Set((urls || []).filter(Boolean))];
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
