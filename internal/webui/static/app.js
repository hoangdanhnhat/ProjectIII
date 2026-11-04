"use strict";

/* --------------------------------------------------------------------------
   DFIR Evidence Console
   Vanilla JS, no build step. All user-controlled strings are rendered with
   textContent (never innerHTML), and the server sends a strict CSP.
   -------------------------------------------------------------------------- */

const TOKEN_KEY = "dfir.operator.token";
const THEME_KEY = "dfir.theme";
const POLL_MS = 5000;
const SVG_NS = "http://www.w3.org/2000/svg";

const STATUS = {
  queued: { label: "Queued", tone: "gray" },
  running: { label: "Running", tone: "blue" },
  completed: { label: "Completed", tone: "green" },
  partial: { label: "Partial", tone: "amber" },
  failed: { label: "Failed", tone: "red" },
  skipped: { label: "Skipped", tone: "gray" },
  needs_configuration: { label: "Needs config", tone: "violet" },
};

const FILTERS = [
  { id: "all", label: "All", match: () => true },
  { id: "active", label: "Active", match: (j) => j.status === "queued" || j.status === "running" },
  { id: "completed", label: "Completed", match: (j) => j.status === "completed" },
  { id: "attention", label: "Attention", match: (j) => ["partial", "failed", "skipped", "needs_configuration"].includes(j.status) },
];

const KIND_LABELS = {
  upload: "Upload",
  apache_log: "Apache log",
  iis_log: "IIS log",
  netstat_snapshot: "Netstat & DNS",
  ti_report: "Threat Intel report",
  event_log: "Event log",
};

const TI_STATUS = {
  running: { label: "TI running", tone: "blue" },
  completed: { label: "TI completed", tone: "green" },
  partial: { label: "TI partial", tone: "amber" },
  skipped: { label: "TI skipped", tone: "gray" },
  failed: { label: "TI failed", tone: "red" },
  interrupted: { label: "TI interrupted", tone: "gray" },
};

const VERDICTS = {
  blacklisted: { label: "Blacklisted", tone: "red" },
  malicious: { label: "Malicious", tone: "red" },
  suspicious: { label: "Suspicious", tone: "amber" },
  clean: { label: "Clean", tone: "green" },
  whitelisted: { label: "Whitelisted", tone: "violet" },
  unrated: { label: "Unrated", tone: "gray" },
  private: { label: "Private", tone: "gray" },
  skipped: { label: "Skipped", tone: "gray" },
};

const ENTRY_TYPE_LABELS = {
  ip: "IP",
  cidr: "Network",
  domain: "Domain",
  domain_wildcard: "Wildcard",
};

const state = {
  token: "",
  meta: null,
  jobs: [],
  snapshot: "",
  query: "",
  filter: "all",
  selectedId: null,
  loadedOnce: false,
  pollTimer: null,
  // Threat intel state
  artifactData: new Map(), // artifact.id -> parsed JSON (or null when unparsable)
  reportForDetail: null,   // { jobId, indicators } backing the findings table
  tiTab: "findings",
  tiQuery: "",
  tiSettings: null,
  tiList: "whitelist",
  wlQuery: "",
};

const $ = (id) => document.getElementById(id);

const ui = {
  connectView: $("connect-view"),
  dashboardView: $("dashboard-view"),
  connectForm: $("connect-form"),
  tokenInput: $("token-input"),
  revealBtn: $("reveal-btn"),
  connectBtn: $("connect-btn"),
  connectError: $("connect-error"),
  conn: $("conn"),
  connText: $("conn-text"),
  themeBtn: $("theme-btn"),
  newBtn: $("new-btn"),
  signoutBtn: $("signout-btn"),
  dashboardSub: $("dashboard-sub"),
  updated: $("updated"),
  refreshBtn: $("refresh-btn"),
  statTotal: $("stat-total"),
  statActive: $("stat-active"),
  statCompleted: $("stat-completed"),
  statAttention: $("stat-attention"),
  searchInput: $("search-input"),
  filters: $("filters"),
  jobHead: $("job-head"),
  jobList: $("job-list"),
  empty: $("empty"),
  emptyNew: $("empty-new"),
  skeleton: $("skeleton"),
  footCount: $("foot-count"),
  newDialog: $("new-dialog"),
  newForm: $("new-form"),
  newClose: $("new-close"),
  newCancel: $("new-cancel"),
  hostInput: $("host-input"),
  scenarioSelect: $("scenario-select"),
  sinceInput: $("since-input"),
  newError: $("new-error"),
  createBtn: $("create-btn"),
  jobDialog: $("job-dialog"),
  detailTitle: $("detail-title"),
  detailSub: $("detail-sub"),
  detailBody: $("detail-body"),
  detailClose: $("detail-close"),
  sheetToasts: $("sheet-toasts"),
  toasts: $("toasts"),
  // Threat intel settings dialog
  tiBtn: $("ti-btn"),
  tiDialog: $("ti-dialog"),
  tiForm: $("ti-form"),
  tiClose: $("ti-close"),
  tiDoneBtn: $("ti-done-btn"),
  vtStateChip: $("vt-state-chip"),
  vtKeyInput: $("vt-key-input"),
  vtKeyReveal: $("vt-key-reveal"),
  vtAutoInput: $("vt-auto-input"),
  vtRateInput: $("vt-rate-input"),
  vtMaxInput: $("vt-max-input"),
  tiSaveBtn: $("ti-save-btn"),
  tiError: $("ti-error"),
  countWhitelist: $("count-whitelist"),
  countBlacklist: $("count-blacklist"),
  listHint: $("list-hint"),
  wlValueInput: $("wl-value-input"),
  wlNoteInput: $("wl-note-input"),
  wlAddBtn: $("wl-add-btn"),
  wlSearchInput: $("wl-search-input"),
  wlList: $("wl-list"),
  wlEmpty: $("wl-empty"),
  wlError: $("ti-error-wl"),
};

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/* --------------------------------------------------------------------------
   Small DOM helpers
   -------------------------------------------------------------------------- */

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (typeof value === "function" && key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (value === true) node.setAttribute(key, "");
      else node.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, cls) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", cls || "icon");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}

/* --------------------------------------------------------------------------
   Formatting
   -------------------------------------------------------------------------- */

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const ABSOLUTE = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const SHORT_TIME = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function asDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function relative(value) {
  const date = asDate(value);
  if (!date) return "—";
  const diff = (date.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  let unit = "second";
  let amount = diff;
  if (abs >= 86400) {
    unit = "day";
    amount = diff / 86400;
  } else if (abs >= 3600) {
    unit = "hour";
    amount = diff / 3600;
  } else if (abs >= 60) {
    unit = "minute";
    amount = diff / 60;
  }
  const rounded = Math.sign(amount) * Math.round(Math.abs(amount));
  return RELATIVE.format(rounded, unit);
}

function absolute(value) {
  const date = asDate(value);
  return date ? ABSOLUTE.format(date) : "—";
}

function shortTime(value) {
  const date = asDate(value);
  return date ? SHORT_TIME.format(date) : "—";
}

function duration(job) {
  const start = asDate(job.started_at || job.created_at);
  if (!start) return "—";
  const end = asDate(job.ended_at) || (job.status === "running" ? new Date() : null);
  if (!end) return "—";
  const ms = end.getTime() - start.getTime();
  if (Number.isNaN(ms) || ms < 0) return "—";
  if (ms < 1000) return "<1s";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return seconds + "s";
  const minutes = Math.floor(seconds / 60);
  const restSeconds = seconds % 60;
  if (minutes < 60) return minutes + "m " + restSeconds + "s";
  const hours = Math.floor(minutes / 60);
  return hours + "h " + (minutes % 60) + "m";
}

function bytes(value) {
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return n + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let size = n;
  let index = -1;
  do {
    size /= 1024;
    index += 1;
  } while (size >= 1024 && index < units.length - 1);
  return (size >= 10 ? size.toFixed(0) : size.toFixed(1)) + " " + units[index];
}

function shortId(id) {
  if (!id) return "—";
  return id.length > 14 ? id.slice(0, 12) + "…" : id;
}

function shortHash(hash) {
  if (!hash) return "—";
  return hash.slice(0, 16) + "…";
}

function fileName(source, fallback) {
  const parts = String(source || "").split(/[\\/]/);
  const base = parts[parts.length - 1].trim();
  return base || "artifact-" + String(fallback || "download").slice(0, 8);
}

function statusInfo(status) {
  return STATUS[status] || { label: status || "Unknown", tone: "gray" };
}

function kindLabel(kind) {
  return KIND_LABELS[kind] || kind || "Artifact";
}

function statusChip(status) {
  const info = statusInfo(status);
  return el("span", { class: "chip", "data-tone": info.tone },
    el("span", { class: "chip-dot" }),
    info.label
  );
}

function findJob(id) {
  return state.jobs.find((job) => job.id === id) || null;
}

/* --------------------------------------------------------------------------
   Toasts and connection state
   -------------------------------------------------------------------------- */

function toast(message, tone, host) {
  const popup = host || ui.toasts;
  if (!popup) return;
  const toneName = tone || "info";
  const iconName = toneName === "error" ? "alert-triangle" : toneName === "success" ? "check-circle" : "info";
  const node = el("div", { class: "toast", "data-tone": toneName, role: "status" },
    icon(iconName),
    el("span", { text: message })
  );
  popup.append(node);
  while (popup.children.length > 3) popup.firstElementChild.remove();
  window.setTimeout(() => {
    node.classList.add("toast--out");
    window.setTimeout(() => node.remove(), 220);
  }, 4200);
}

function setConnection(stateName, text) {
  ui.conn.dataset.state = stateName;
  ui.connText.textContent = text;
}

function showConnectError(message) {
  ui.connectError.textContent = message || "";
  ui.connectError.hidden = !message;
}

function showNewError(message) {
  ui.newError.textContent = message || "";
  ui.newError.hidden = !message;
}

/* --------------------------------------------------------------------------
   Auth and API
   -------------------------------------------------------------------------- */

async function responseMessage(response) {
  try {
    const text = (await response.text()).trim();
    if (text) return text;
  } catch (err) {
    // Fall through to the status line.
  }
  return (response.status + " " + response.statusText).trim();
}

async function fetchMeta(token) {
  let response;
  try {
    response = await fetch("/v1/meta", {
      headers: { Authorization: "Bearer " + token },
      cache: "no-store",
    });
  } catch (err) {
    throw new ApiError("Network error — is the server reachable?", 0);
  }
  if (response.status === 401) throw new ApiError("Token rejected.", 401);
  if (!response.ok) throw new ApiError(await responseMessage(response), response.status);
  return response.json();
}

async function api(path, options) {
  const opts = options || {};
  const headers = new Headers(opts.headers || {});
  if (state.token) headers.set("Authorization", "Bearer " + state.token);
  let response;
  try {
    response = await fetch(path, Object.assign({}, opts, { headers, cache: "no-store" }));
  } catch (err) {
    throw new ApiError("Network error — is the server reachable?", 0);
  }
  if (response.status === 401) {
    endSession("Your session expired. Reconnect with the operator token.");
    throw new ApiError("Unauthorized", 401);
  }
  if (!response.ok) throw new ApiError(await responseMessage(response), response.status);
  return response;
}

function clearSession() {
  state.token = "";
  state.meta = null;
  state.jobs = [];
  state.snapshot = "";
  state.loadedOnce = false;
  state.artifactData.clear();
  state.tiSettings = null;
  state.reportForDetail = null;
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch (err) {
    // sessionStorage can be unavailable in hardened browser modes.
  }
}

function endSession(message) {
  clearSession();
  stopPoll();
  if (ui.newDialog.open) ui.newDialog.close();
  if (ui.jobDialog.open) ui.jobDialog.close();
  if (ui.tiDialog.open) ui.tiDialog.close();
  state.reportForDetail = null;
  showConnect(message);
}

function showConnect(message) {
  ui.dashboardView.hidden = true;
  ui.connectView.hidden = false;
  ui.newBtn.hidden = true;
  ui.newBtn.disabled = true;
  ui.tiBtn.hidden = true;
  ui.signoutBtn.hidden = true;
  setConnection("idle", "Not connected");
  showConnectError(message || "");
  ui.tokenInput.value = "";
  ui.tokenInput.type = "password";
  ui.revealBtn.textContent = "Show";
  ui.revealBtn.setAttribute("aria-pressed", "false");
  ui.revealBtn.setAttribute("aria-label", "Show token");
  ui.tokenInput.focus();
}

function showDashboard() {
  ui.connectView.hidden = true;
  ui.dashboardView.hidden = false;
  ui.newBtn.hidden = false;
  ui.newBtn.disabled = false;
  ui.tiBtn.hidden = false;
  ui.signoutBtn.hidden = false;
  setConnection("ok", "Connected");
  const scenarios = metaScenarios();
  ui.dashboardSub.textContent = "Host " + (state.meta.host_id || "—") + " · " + scenarios.join(", ");
  fillScenarioOptions();
  ui.hostInput.value = state.meta.host_id || "";
}

function metaScenarios() {
  if (state.meta && Array.isArray(state.meta.scenarios) && state.meta.scenarios.length) {
    return state.meta.scenarios;
  }
  return ["webshell.v1"];
}

/* --------------------------------------------------------------------------
   Collections
   -------------------------------------------------------------------------- */

function matchesFilter(job) {
  const filter = FILTERS.find((item) => item.id === state.filter);
  return filter ? filter.match(job) : true;
}

function matchesQuery(job) {
  if (!state.query) return true;
  const haystack = [
    job.id,
    job.host_id,
    job.scenario,
    job.status,
    job.reason,
  ].concat((job.artifacts || []).map((artifact) => artifact.source));
  return haystack.join(" ").toLowerCase().includes(state.query);
}

function renderStats() {
  let active = 0;
  let completed = 0;
  let attention = 0;
  for (const job of state.jobs) {
    if (job.status === "queued" || job.status === "running") active += 1;
    if (job.status === "completed") completed += 1;
    if (["partial", "failed", "skipped", "needs_configuration"].includes(job.status)) attention += 1;
  }
  ui.statTotal.textContent = String(state.jobs.length);
  ui.statActive.textContent = String(active);
  ui.statCompleted.textContent = String(completed);
  ui.statAttention.textContent = String(attention);
}

function buildFilters() {
  ui.filters.replaceChildren(...FILTERS.map((filter) =>
    el("button", {
      class: "chip-filter",
      type: "button",
      "data-filter": filter.id,
      "aria-pressed": "false",
    }, filter.label, el("span", { class: "chip-count", text: "0" }))
  ));
}

function updateFilters() {
  for (const button of ui.filters.querySelectorAll("[data-filter]")) {
    const id = button.dataset.filter;
    const filter = FILTERS.find((item) => item.id === id);
    if (!filter) continue;
    const count = state.jobs.filter((job) => filter.match(job)).length;
    button.querySelector(".chip-count").textContent = String(count);
    const active = state.filter === id;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
}

function renderList() {
  const focusedJob = document.activeElement && document.activeElement.closest
    ? document.activeElement.closest("[data-job-id]")
    : null;
  const focusedId = focusedJob ? focusedJob.dataset.jobId : null;

  const visible = state.jobs.filter(matchesFilter).filter(matchesQuery);
  ui.jobList.replaceChildren(...visible.map(jobRow));
  ui.jobHead.hidden = visible.length === 0;
  ui.empty.hidden = visible.length > 0;

  const hasJobs = state.jobs.length > 0;
  ui.empty.querySelector("h3").textContent = hasJobs ? "No matching collections" : "No collections yet";
  ui.empty.querySelector("p").textContent = hasJobs
    ? "Adjust the search text or status filter."
    : "Queue a collection to pull evidence from the registered host.";

  ui.footCount.textContent = visible.length === state.jobs.length
    ? state.jobs.length + " total"
    : visible.length + " of " + state.jobs.length;

  if (focusedId) {
    const next = Array.from(ui.jobList.querySelectorAll("[data-job-id]"))
      .find((node) => node.dataset.jobId === focusedId);
    if (next) next.focus({ preventScroll: true });
  }
}

function jobRow(job) {
  return el("li", { class: "job-item" },
    el("button", {
      class: "job",
      type: "button",
      "data-job-id": job.id,
      "aria-label": "Open collection " + job.id + " for " + (job.host_id || "unknown host"),
    },
      el("span", { class: "job-status" }, statusChip(job.status)),
      el("span", { class: "job-main" },
        el("span", { class: "job-host", text: job.host_id || "unknown host" }),
        el("span", { class: "job-meta" },
          el("code", { class: "mono", text: shortId(job.id), title: job.id }),
          el("span", { class: "dot-sep", text: "·" }),
          el("span", { text: job.scenario || "—" })
        )
      ),
      el("span", { class: "job-artifacts" },
        el("strong", { text: String((job.artifacts || []).length) }),
        el("span", { class: "muted", text: " artifacts" })
      ),
      el("span", { class: "job-time", title: absolute(job.created_at) },
        el("span", { text: relative(job.created_at) }),
        el("span", { class: "job-time-abs", text: shortTime(job.created_at) })
      ),
      el("span", { class: "job-duration", text: duration(job) }),
      icon("chevron-right", "icon job-chevron")
    )
  );
}

async function loadJobs(options) {
  const opts = options || {};
  if (!state.token) return;
  if (!state.loadedOnce) ui.skeleton.hidden = false;
  ui.refreshBtn.disabled = true;
  ui.refreshBtn.classList.add("is-loading");

  const selectedBefore = state.selectedId;
  const previousDetail = selectedBefore ? JSON.stringify(findJob(selectedBefore)) : "";

  try {
    const response = await api("/v1/jobs");
    const data = await response.json();
    const jobs = Array.isArray(data.jobs) ? data.jobs : [];
    const snapshot = JSON.stringify(jobs);
    const changed = snapshot !== state.snapshot;

    state.jobs = jobs;
    state.snapshot = snapshot;
    state.loadedOnce = true;

    renderStats();
    updateFilters();
    if (changed) renderList();

    if (selectedBefore) {
      const selected = findJob(selectedBefore);
      if (!selected) ui.jobDialog.close();
      else if (JSON.stringify(selected) !== previousDetail) renderDetail(selected);
    }

    ui.updated.textContent = "Updated " + relative(new Date().toISOString());
    ui.updated.title = absolute(new Date().toISOString());
    setConnection("ok", "Connected");
  } catch (err) {
    if (err.status === 401) return;
    setConnection("error", "Connection issue");
    if (!opts.silent || !state.loadedOnce) toast(err.message, "error");
  } finally {
    ui.skeleton.hidden = true;
    ui.refreshBtn.disabled = false;
    ui.refreshBtn.classList.remove("is-loading");
    schedulePoll();
  }
}

function schedulePoll() {
  stopPoll();
  if (!state.token || document.hidden) return;
  state.pollTimer = window.setTimeout(() => loadJobs({ silent: true }), POLL_MS);
}

function stopPoll() {
  if (state.pollTimer) {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }
}

/* --------------------------------------------------------------------------
   Job detail
   -------------------------------------------------------------------------- */

function addKv(list, label, value, action) {
  list.append(el("dt", { text: label }), el("dd", {}, value, action || ""));
}

function copyButton(value, label) {
  if (!value) return null;
  const button = el("button", {
    class: "copy-btn",
    type: "button",
    "aria-label": "Copy " + label,
    title: "Copy " + label,
  }, icon("copy"));
  button.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(String(value));
      toast("Copied " + label, "success", ui.sheetToasts);
    } catch (err) {
      toast("Clipboard unavailable; select and copy manually.", "error", ui.sheetToasts);
    }
  });
  return button;
}

function downloadButton(job, artifact) {
  const button = el("button", {
    class: "btn btn--sm",
    type: "button",
    "aria-label": "Download " + fileName(artifact.source, artifact.id),
  }, icon("download"), "Download");
  button.addEventListener("click", () => downloadArtifact(job.id, artifact, button));
  return button;
}

async function downloadArtifact(jobId, artifact, button) {
  if (button.disabled) return;
  button.disabled = true;
  button.replaceChildren(icon("loader", "icon spin"), document.createTextNode("Saving…"));
  try {
    const response = await api("/v1/jobs/" + encodeURIComponent(jobId) + "/artifacts/" + encodeURIComponent(artifact.id));
    const blob = await response.blob();
    const name = fileName(artifact.source, artifact.id);
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast("Downloaded " + name, "success", ui.sheetToasts);
  } catch (err) {
    if (err.status !== 401) toast(err.message || "Download failed.", "error", ui.sheetToasts);
  } finally {
    button.disabled = false;
    button.replaceChildren(icon("download"), document.createTextNode("Download"));
  }
}

function artifactCard(job, artifact) {
  return el("article", { class: "artifact" },
    el("div", { class: "artifact-top" },
      el("span", { class: "kind", "data-kind": artifact.kind || "upload", text: kindLabel(artifact.kind) }),
      el("span", { class: "artifact-size", text: bytes(artifact.size) }),
      downloadButton(job, artifact)
    ),
    el("div", { class: "artifact-source mono break", text: artifact.source || "—" }),
    el("div", { class: "artifact-meta" },
      el("span", { text: "Modified " + absolute(artifact.modified_at) }),
      el("span", { class: "dot-sep", text: "·" }),
      el("span", { text: artifact.mode || "—" }),
      el("span", { class: "dot-sep", text: "·" }),
      el("span", { text: "Collected " + absolute(artifact.collected_at) })
    ),
    el("div", { class: "hash-line" },
      el("span", { class: "hash-label", text: "SHA-256" }),
      el("code", { class: "mono", text: shortHash(artifact.sha256), title: artifact.sha256 || "" }),
      copyButton(artifact.sha256, "SHA-256")
    )
  );
}

function renderDetail(job) {
  ui.detailTitle.textContent = job.host_id || "Collection";
  ui.detailSub.textContent = job.id;

  const info = statusInfo(job.status);
  const body = el("div");
  body.append(el("div", { class: "detail-statusline" },
    statusChip(job.status),
    el("span", { text: "Duration " + duration(job) }),
    el("span", { class: "dot-sep", text: "·" }),
    el("span", { text: "Created " + relative(job.created_at), title: absolute(job.created_at) })
  ));

  if (job.reason) {
    body.append(el("div", { class: "callout", "data-tone": info.tone },
      el("span", { class: "callout-label", text: "Result" }),
      el("p", { text: job.reason })
    ));
  }

  const facts = el("dl", { class: "kv" });
  addKv(facts, "Job ID", el("span", { class: "mono break", text: job.id }), copyButton(job.id, "job ID"));
  addKv(facts, "Host", job.host_id || "—");
  addKv(facts, "Scenario", job.scenario || "—");
  addKv(facts, "Created", absolute(job.created_at));
  addKv(facts, "Started", absolute(job.started_at));
  addKv(facts, "Ended", absolute(job.ended_at));
  if (job.since) addKv(facts, "Modified since", absolute(job.since));
  body.append(facts);

  if (job.scenario === "netstat.v1") {
    body.append(buildTISection(job));
  }

  const artifacts = Array.isArray(job.artifacts) ? job.artifacts : [];
  const section = el("section", { class: "section" },
    el("div", { class: "section-head" },
      el("h3", { text: "Artifacts" }),
      el("span", { class: "count-pill", text: String(artifacts.length) })
    )
  );
  if (artifacts.length === 0) {
    section.append(el("div", { class: "mini-empty" },
      icon("folder"),
      el("span", { text: job.status === "running" ? "Waiting for the agent to upload artifacts…" : "No artifacts were uploaded for this collection." })
    ));
  } else {
    const list = el("div", { class: "artifact-list" });
    for (const artifact of artifacts) list.append(artifactCard(job, artifact));
    section.append(list);
  }
  body.append(section);

  ui.detailBody.replaceChildren(body);
}

function openDetail(job, options) {
  const opts = options || {};
  state.selectedId = job.id;
  renderDetail(job);
  if (!ui.jobDialog.open) ui.jobDialog.showModal();
  if (opts.hash !== false) {
    const target = "#/job/" + encodeURIComponent(job.id);
    if (location.hash !== target) history.replaceState(null, "", target);
  }
}

function jobIdFromHash() {
  const match = /^#\/job\/([^/]+)$/.exec(location.hash);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch (err) {
    return null;
  }
}

function openJobFromHash() {
  const id = jobIdFromHash();
  if (!id) return;
  const job = findJob(id);
  if (job) openDetail(job, { hash: false });
}

/* --------------------------------------------------------------------------
   New collection
   -------------------------------------------------------------------------- */

function fillScenarioOptions() {
  const scenarios = metaScenarios();
  const current = ui.scenarioSelect.value;
  ui.scenarioSelect.replaceChildren(...scenarios.map((scenario) =>
    el("option", { value: scenario, text: scenario })
  ));
  if (scenarios.includes(current)) ui.scenarioSelect.value = current;
}

function openNewDialog() {
  fillScenarioOptions();
  ui.hostInput.value = (state.meta && state.meta.host_id) || "";
  ui.sinceInput.value = "";
  showNewError("");
  ui.newDialog.showModal();
  ui.hostInput.focus();
  ui.hostInput.select();
}

async function createCollection(event) {
  event.preventDefault();
  if (ui.createBtn.disabled) return;
  showNewError("");

  const host = ui.hostInput.value.trim();
  if (!host) {
    showNewError("Host ID is required.");
    ui.hostInput.focus();
    return;
  }

  const sinceRaw = ui.sinceInput.value;
  let since = null;
  if (sinceRaw) {
    const parsed = new Date(sinceRaw);
    if (Number.isNaN(parsed.getTime())) {
      showNewError("The date is not valid.");
      ui.sinceInput.focus();
      return;
    }
    if (parsed.getTime() > Date.now() + 60000) {
      showNewError("“Modified since” cannot be in the future.");
      ui.sinceInput.focus();
      return;
    }
    since = parsed.toISOString();
  }

  ui.createBtn.disabled = true;
  ui.createBtn.textContent = "Queueing…";
  try {
    const payload = { host_id: host, scenario: ui.scenarioSelect.value };
    if (since) payload.since = since;
    const response = await api("/v1/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const created = await response.json();
    ui.newDialog.close();
    toast("Collection queued for " + host, "success");
    await loadJobs({ silent: true });
    const job = created && created.id ? findJob(created.id) : null;
    if (job) openDetail(job);
  } catch (err) {
    if (err.status !== 401) showNewError(err.message || "Could not queue the collection.");
  } finally {
    ui.createBtn.disabled = false;
    ui.createBtn.textContent = "Queue collection";
  }
}

/* --------------------------------------------------------------------------
   Threat Intel: artifact loading, triage section, findings/connections/DNS
   -------------------------------------------------------------------------- */

const ARTIFACT_CACHE_LIMIT = 24;

function artifactById(job, kind) {
  const list = Array.isArray(job.artifacts) ? job.artifacts : [];
  let found = null;
  for (const artifact of list) {
    if (artifact.kind === kind) found = artifact; // latest wins
  }
  return found;
}

async function loadArtifactJSON(job, artifact) {
  if (state.artifactData.has(artifact.id)) {
    return state.artifactData.get(artifact.id);
  }
  let parsed = null;
  try {
    const response = await api("/v1/jobs/" + encodeURIComponent(job.id) + "/artifacts/" + encodeURIComponent(artifact.id));
    const text = await response.text();
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      parsed = null;
    }
  } catch (err) {
    if (err.status === 401) throw err; // session handling already fired
    // Negative caching: a failed download must not trigger a re-render
    // loop in buildTISection, which re-fetches whatever is uncached.
    parsed = null;
  }
  while (state.artifactData.size >= ARTIFACT_CACHE_LIMIT) {
    const oldest = state.artifactData.keys().next().value;
    state.artifactData.delete(oldest);
  }
  state.artifactData.set(artifact.id, parsed);
  return parsed;
}

function tiStatusChip(status) {
  const info = TI_STATUS[status] || { label: status, tone: "gray" };
  return el("span", { class: "chip", "data-tone": info.tone },
    el("span", { class: "chip-dot" }),
    info.label
  );
}

function verdictChip(verdict) {
  const info = VERDICTS[verdict] || { label: verdict || "—", tone: "gray" };
  return el("span", { class: "chip", "data-tone": info.tone },
    el("span", { class: "chip-dot" }),
    info.label
  );
}

// buildTISection renders the threat-intel block for a netstat.v1 job. Data
// is rendered synchronously when cached; otherwise a placeholder kicks off
// the fetch and re-renders the whole detail.
function buildTISection(job) {
  const section = el("section", { class: "section ti" });
  if (state.reportForDetail && state.reportForDetail.jobId !== job.id) {
    state.reportForDetail = null;
  }

  const snapshotArtifact = artifactById(job, "netstat_snapshot");
  const reportArtifact = artifactById(job, "ti_report");
  const canRun = !!snapshotArtifact && job.ti_status !== "running";

  const head = el("div", { class: "ti-head" },
    el("h3", { text: "Threat Intel" }),
    job.ti_status ? tiStatusChip(job.ti_status) : "",
    canRun
      ? el("button", {
          class: "btn btn--sm",
          type: "button",
          "data-ti-rerun": job.id,
          title: "Re-run the VirusTotal check with current settings and whitelist",
        }, icon("refresh"), "Re-run check")
      : ""
  );
  section.append(head);

  if (job.ti_reason) {
    const tone = job.ti_status === "failed" || job.ti_status === "partial" ? "amber" : "gray";
    section.append(el("p", { class: "ti-reason", text: job.ti_reason }));
  }

  if (job.ti_status === "running") {
    section.append(el("div", { class: "ti-loading" },
      icon("loader", "icon spin"),
      el("span", { text: "Checking indicators on VirusTotal… this can take a few minutes at the free-tier rate limit." })
    ));
  }

  const summary = reportSummaryFor(job, reportArtifact);
  if (summary) section.append(summary);

  const tabs = el("div", { class: "tabs", role: "group", "aria-label": "Threat intel views" },
    tabButton("findings", "Findings", "shield"),
    tabButton("connections", "Connections", "network"),
    tabButton("dns", "DNS cache", "server")
  );
  section.append(tabs);

  const tools = el("div", { class: "ti-tools" },
    el("div", { class: "search" },
      icon("search"),
      el("input", {
        id: "ti-search",
        type: "search",
        placeholder: "Filter by IP, domain, process, verdict…",
        "aria-label": "Filter threat intel tables",
        autocomplete: "off",
        value: state.tiQuery || "",
      })
    )
  );
  section.append(tools, el("div", { id: "ti-table" }));

  renderTITable(job);

  // Fetch missing artifacts in the background, then refresh once.
  const missing = [];
  if (snapshotArtifact && !state.artifactData.has(snapshotArtifact.id)) missing.push(snapshotArtifact);
  if (reportArtifact && !state.artifactData.has(reportArtifact.id)) missing.push(reportArtifact);
  if (missing.length) {
    Promise.allSettled(missing.map((artifact) => loadArtifactJSON(job, artifact))).then(() => {
      if (state.selectedId === job.id) {
        const fresh = findJob(job.id);
        if (fresh) renderDetail(fresh);
      }
    });
  }
  return section;
}

function tabButton(id, label, iconName) {
  return el("button", {
    class: "tab" + (state.tiTab === id ? " is-active" : ""),
    type: "button",
    "data-ti-tab": id,
    "aria-pressed": state.tiTab === id ? "true" : "false",
  }, icon(iconName), label, el("span", { class: "count-pill", id: "ti-count-" + id, text: "…" }));
}

function reportSummaryFor(job, reportArtifact) {
  if (!reportArtifact || job.ti_status === "running") return null;
  const report = state.artifactData.get(reportArtifact.id);
  if (!report || !report.summary) return null;
  const s = report.summary;
  const items = [
    ["blacklisted", s.blacklisted],
    ["malicious", s.malicious],
    ["suspicious", s.suspicious],
    ["clean", s.clean],
    ["whitelisted", s.whitelisted],
    ["unrated", s.unrated],
    ["skipped", s.skipped],
    ["private", s.private],
  ];
  const chips = el("div", { class: "ti-summary" });
  for (const [key, count] of items) {
    if (!count) continue;
    const info = VERDICTS[key] || { label: key, tone: "gray" };
    chips.append(el("span", { class: "chip", "data-tone": info.tone, title: key },
      el("span", { class: "chip-dot" }),
      count + " " + info.label
    ));
  }
  return chips.children.length ? chips : null;
}

// renderTITable fills the #ti-table container for the currently selected
// job. Called on tab switches, filter input, and detail re-renders.
function renderTITable(job) {
  const host = document.getElementById("ti-table");
  if (!host) return;
  const snapshotArtifact = artifactById(job, "netstat_snapshot");
  const reportArtifact = artifactById(job, "ti_report");
  const snapshot = snapshotArtifact ? state.artifactData.get(snapshotArtifact.id) : null;
  const report = reportArtifact ? state.artifactData.get(reportArtifact.id) : null;

  if (state.tiTab === "findings") {
    host.replaceChildren(findingsTable(job, report, snapshot, reportArtifact));
  } else if (state.tiTab === "connections") {
    host.replaceChildren(connectionsTable(job, snapshot, snapshotArtifact));
  } else {
    host.replaceChildren(dnsTable(job, snapshot, snapshotArtifact));
  }
  updateTICounts(job, report, snapshot);
}

function updateTICounts(job, report, snapshot) {
  const findings = document.getElementById("ti-count-findings");
  const conns = document.getElementById("ti-count-connections");
  const dns = document.getElementById("ti-count-dns");
  if (findings) findings.textContent = report && report.indicators ? String(report.indicators.length) : "0";
  if (conns) conns.textContent = snapshot && snapshot.connections ? String(snapshot.connections.length) : "0";
  if (dns) dns.textContent = snapshot && snapshot.dns_cache ? String(snapshot.dns_cache.length) : "0";
}

function flaggedByValue(report) {
  const flagged = new Map(); // value -> tone
  if (!report || !Array.isArray(report.indicators)) return flagged;
  for (const ind of report.indicators) {
    if (ind.verdict === "blacklisted" || ind.verdict === "malicious") {
      flagged.set(String(ind.value), "red");
    } else if (ind.verdict === "suspicious") {
      flagged.set(String(ind.value), "amber");
    }
  }
  return flagged;
}

function matchesTIQuery(parts) {
  if (!state.tiQuery) return true;
  return parts.join(" ").toLowerCase().includes(state.tiQuery);
}

function findingsTable(job, report, snapshot, reportArtifact) {
  const wrap = el("div", { class: "table-wrap ti-table--findings" });
  if (!reportArtifact) {
    return wrap.append(emptyRow(job.ti_status === "running"
      ? "Waiting for the threat intel report…"
      : "No threat intel report yet — run a check to triage this collection.")), wrap;
  }
  if (!report || !Array.isArray(report.indicators)) {
    return wrap.append(emptyRow("The report artifact could not be parsed.")), wrap;
  }
  state.reportForDetail = { jobId: job.id, indicators: report.indicators };
  wrap.append(el("div", { class: "thead" },
    el("span", { text: "Indicator" }),
    el("span", { text: "Verdict" }),
    el("span", { text: "Detections" }),
    el("span", { text: "Process / route" }),
    el("span", { text: "" })
  ));
  const rows = el("div");
  let shown = 0;
  report.indicators.forEach((ind, index) => {
    const parts = [ind.value, ind.type, ind.verdict, (ind.domains || []).join(" "), (ind.processes || []).join(" "), ind.classification];
    if (!matchesTIQuery(parts)) return;
    shown++;
    const vt = ind.vt || {};
    const tone = ind.verdict === "blacklisted" || ind.verdict === "malicious" ? "red" : ind.verdict === "suspicious" ? "amber" : null;
    const row = el("div", { class: "trow", "data-tone": tone || undefined },
      el("div", { class: "cell" },
        el("div", { class: "cell-main" },
          el("span", { class: "tag", "data-type": ind.type === "ip" ? "ip" : "domain", text: ind.type === "ip" ? "IP" : "Domain" }),
          el("span", { class: "mono cell-value", text: ind.value })
        ),
        (ind.domains || []).length
          ? el("div", { class: "cell-sub" }, ...ind.domains.map((d) => el("span", { class: "mono", text: d })))
          : "",
        ind.blacklist_match
          ? el("div", { class: "cell-sub" },
              "blacklisted via " + ind.blacklist_match +
              (ind.whitelist_match ? " · also whitelisted via " + ind.whitelist_match : ""))
          : ind.whitelist_match
            ? el("div", { class: "cell-sub" }, "whitelisted via " + ind.whitelist_match)
            : ""
      ),
      el("div", { class: "cell" }, verdictChip(ind.verdict)),
      el("div", { class: "cell" },
        vt.detections ? el("span", { class: "ratio", text: vt.detections }) : el("span", { class: "muted", text: "—" }),
        vt.error ? el("div", { class: "cell-sub", title: vt.error, text: vt.error }) : ""
      ),
      el("div", { class: "cell" },
        (ind.processes || []).length
          ? el("span", { class: "cell-value", text: ind.processes.join(", ") })
          : el("span", { class: "muted", text: ind.type === "domain" ? "DNS cache" : "—" }),
        ind.connections ? el("div", { class: "cell-sub", text: ind.connections + " connection" + (ind.connections > 1 ? "s" : "") }) : ""
      ),
      el("div", { class: "cell-actions" },
        vt.link
          ? el("a", { class: "vt-link", href: vt.link, target: "_blank", rel: "noopener noreferrer", "aria-label": "Open VirusTotal report for " + ind.value, title: "VirusTotal report" }, icon("external"))
          : "",
        canListIndicator(ind)
          ? el("button", {
              class: "wl-mini",
              type: "button",
              "data-ti-wl": String(index),
              "aria-label": "Whitelist " + ind.value,
              title: "Whitelist " + ind.value + " and re-run the check",
            }, icon("check"))
          : "",
        canListIndicator(ind)
          ? el("button", {
              class: "wl-mini wl-mini--ban",
              type: "button",
              "data-ti-bl": String(index),
              "aria-label": "Blacklist " + ind.value,
              title: "Blacklist " + ind.value + " and re-run the check",
            }, icon("ban"))
          : ""
      )
    );
    rows.append(row);
  });
  wrap.append(rows);
  if (!shown) wrap.append(emptyRow("No indicators match this filter."));
  return wrap;
}

function canListIndicator(ind) {
  return ind.classification === "public" || ind.verdict === "skipped" || ind.verdict === "unrated" ||
    ind.verdict === "clean" || ind.verdict === "suspicious" || ind.verdict === "malicious";
}

function connectionsTable(job, snapshot, snapshotArtifact) {
  const wrap = el("div", { class: "table-wrap ti-table--connections" });
  if (!snapshotArtifact) {
    return wrap.append(emptyRow("No netstat snapshot was uploaded for this collection.")), wrap;
  }
  if (!snapshot || !Array.isArray(snapshot.connections)) {
    return wrap.append(emptyRow("The snapshot artifact could not be parsed.")), wrap;
  }
  const reportArtifact = artifactById(job, "ti_report");
  const report = reportArtifact ? state.artifactData.get(reportArtifact.id) : null;
  const flagged = flaggedByValue(report);
  wrap.append(el("div", { class: "thead" },
    el("span", { text: "Remote" }),
    el("span", { text: "Local" }),
    el("span", { text: "Proto · state" }),
    el("span", { text: "Process" }),
    el("span", { text: "Domains" })
  ));
  const rows = el("div");
  let shown = 0;
  for (const conn of snapshot.connections) {
    const parts = [conn.remote_addr, conn.local_addr, conn.proto, conn.state, conn.process, String(conn.pid), (conn.domains || []).join(" ")];
    if (!matchesTIQuery(parts)) continue;
    shown++;
    const tone = flagged.get(String(conn.remote_addr));
    rows.append(el("div", { class: "trow", "data-tone": tone || undefined },
      el("div", { class: "cell" },
        el("span", { class: "mono cell-value", text: conn.remote_addr ? conn.remote_addr + ":" + (conn.remote_port || 0) : "—" }),
        (conn.domains || []).length ? el("div", { class: "cell-sub" }, ...conn.domains.map((d) => el("span", { class: "mono", text: d }))) : ""
      ),
      el("div", { class: "cell" }, el("span", { class: "mono cell-value", text: conn.local_addr + ":" + conn.local_port })),
      el("div", { class: "cell" },
        el("span", { class: "cell-value", text: conn.proto }),
        conn.state ? el("div", { class: "cell-sub", text: conn.state }) : ""
      ),
      el("div", { class: "cell" },
        conn.process ? el("span", { class: "cell-value", text: conn.process }) : el("span", { class: "muted", text: "—" }),
        el("div", { class: "cell-sub", text: "pid " + conn.pid })
      ),
      el("div", { class: "cell" },
        (conn.domains || []).length
          ? el("span", { class: "cell-value", text: conn.domains.join(", ") })
          : el("span", { class: "muted", text: "—" })
      )
    ));
  }
  wrap.append(rows);
  if (!shown) wrap.append(emptyRow("No connections match this filter."));
  return wrap;
}

function dnsTable(job, snapshot, snapshotArtifact) {
  const wrap = el("div", { class: "table-wrap ti-table--dns" });
  if (!snapshotArtifact) {
    return wrap.append(emptyRow("No netstat snapshot was uploaded for this collection.")), wrap;
  }
  if (!snapshot || !Array.isArray(snapshot.dns_cache) || snapshot.dns_cache.length === 0) {
    return wrap.append(emptyRow(snapshotArtifact && snapshot && !snapshot.dns_cache
      ? "The DNS client cache was empty or unavailable on the endpoint."
      : "The snapshot artifact could not be parsed.")), wrap;
  }
  const reportArtifact = artifactById(job, "ti_report");
  const report = reportArtifact ? state.artifactData.get(reportArtifact.id) : null;
  const flagged = flaggedByValue(report);
  wrap.append(el("div", { class: "thead" },
    el("span", { text: "Name" }),
    el("span", { text: "Type" }),
    el("span", { text: "TTL" }),
    el("span", { text: "Data" })
  ));
  const rows = el("div");
  let shown = 0;
  for (const rec of snapshot.dns_cache) {
    const parts = [rec.name, rec.type, rec.data, String(rec.ttl || 0)];
    if (!matchesTIQuery(parts)) continue;
    shown++;
    const tone = flagged.get(String(rec.name));
    rows.append(el("div", { class: "trow", "data-tone": tone || undefined },
      el("div", { class: "cell" }, el("span", { class: "mono cell-value break", text: rec.name })),
      el("div", { class: "cell" }, el("span", { class: "tag", "data-type": "dns", text: rec.type })),
      el("div", { class: "cell" }, el("span", { class: "ratio", text: rec.ttl ? rec.ttl + "s" : "—" })),
      el("div", { class: "cell" }, el("span", { class: "mono cell-value break", text: rec.data }))
    ));
  }
  wrap.append(rows);
  if (!shown) wrap.append(emptyRow("No DNS entries match this filter."));
  return wrap;
}

function emptyRow(message) {
  return el("div", { class: "trow-empty", text: message });
}

async function rerunTI(jobId) {
  try {
    const response = await api("/v1/jobs/" + encodeURIComponent(jobId) + "/ti", { method: "POST" });
    await response.json();
    toast("Threat intel check re-queued.", "info", ui.sheetToasts);
    await loadJobs({ silent: true });
  } catch (err) {
    if (err.status !== 401) toast(err.message || "Could not re-run the check.", "error", ui.sheetToasts);
  }
}

async function whitelistFromFindings(jobId, indicator) {
  try {
    const response = await api("/v1/whitelist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: indicator.value, note: "whitelisted from collection " + jobId }),
    });
    await response.json();
    toast("Whitelisted " + indicator.value + " — re-running the check.", "success", ui.sheetToasts);
    await rerunTI(jobId);
  } catch (err) {
    if (err.status !== 401) toast(err.message || "Could not whitelist " + indicator.value + ".", "error", ui.sheetToasts);
  }
}

async function blacklistFromFindings(jobId, indicator) {
  try {
    const response = await api("/v1/blacklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: indicator.value, note: "blacklisted from collection " + jobId }),
    });
    await response.json();
    toast("Blacklisted " + indicator.value + " — re-running the check.", "success", ui.sheetToasts);
    await rerunTI(jobId);
  } catch (err) {
    if (err.status !== 401) toast(err.message || "Could not blacklist " + indicator.value + ".", "error", ui.sheetToasts);
  }
}

function onDetailBodyClick(event) {
  const tab = event.target.closest("[data-ti-tab]");
  if (tab) {
    state.tiTab = tab.dataset.tiTab;
    const job = findJob(state.selectedId);
    if (job) renderDetail(job);
    return;
  }
  const rerun = event.target.closest("[data-ti-rerun]");
  if (rerun) {
    rerunTI(rerun.dataset.tiRerun);
    return;
  }
  const wl = event.target.closest("[data-ti-wl]");
  if (wl && state.reportForDetail) {
    const { jobId, indicators } = state.reportForDetail;
    const indicator = indicators[Number(wl.dataset.tiWl)];
    if (indicator) whitelistFromFindings(jobId, indicator);
    return;
  }
  const bl = event.target.closest("[data-ti-bl]");
  if (bl && state.reportForDetail) {
    const { jobId, indicators } = state.reportForDetail;
    const indicator = indicators[Number(bl.dataset.tiBl)];
    if (indicator) blacklistFromFindings(jobId, indicator);
  }
}

function onDetailBodyInput(event) {
  if (event.target.id === "ti-search") {
    state.tiQuery = event.target.value.trim().toLowerCase();
    const job = findJob(state.selectedId);
    if (job) renderTITable(job);
  }
}

/* --------------------------------------------------------------------------
   Threat Intel settings dialog
   -------------------------------------------------------------------------- */

async function openTIDialog() {
  showTIError("");
  showWLError("");
  ui.tiDialog.showModal();
  ui.vtKeyInput.value = "";
  await refreshTISettings();
}

async function refreshTISettings() {
  try {
    const response = await api("/v1/settings/ti");
    state.tiSettings = await response.json();
    renderTISettings();
  } catch (err) {
    if (err.status !== 401) showTIError(err.message || "Could not load settings.");
  }
}

function renderTISettings() {
  const settings = state.tiSettings;
  if (!settings) return;
  const vt = settings.vt || {};
  const configured = !!vt.configured;
  ui.vtStateChip.dataset.tone = configured ? "green" : "gray";
  ui.vtStateChip.replaceChildren(
    el("span", { class: "chip-dot" }),
    document.createTextNode(configured ? "Configured " + (vt.key_preview || "") : "Not configured")
  );
  ui.vtKeyInput.placeholder = configured ? "Configured — paste a new key to replace it" : "Paste a key to enable VirusTotal checks";
  ui.vtAutoInput.checked = !!vt.auto_enrich;
  ui.vtRateInput.value = String(vt.rate_per_min || 4);
  ui.vtMaxInput.value = String(vt.max_queries_per_job || 40);
  renderLists();
}

// listEntries returns the entries of one list from the loaded settings.
function listEntries(name) {
  const settings = state.tiSettings;
  const list = settings && settings[name];
  return list && Array.isArray(list.entries) ? list.entries : [];
}

function listEndpoint() {
  return state.tiList === "blacklist" ? "/v1/blacklist" : "/v1/whitelist";
}

function listLabel() {
  return state.tiList === "blacklist" ? "blacklist" : "whitelist";
}

function setActiveList(name) {
  state.tiList = name === "blacklist" ? "blacklist" : "whitelist";
  showWLError("");
  renderLists();
}

function renderLists() {
  const whitelist = listEntries("whitelist");
  const blacklist = listEntries("blacklist");
  ui.countWhitelist.textContent = String(whitelist.length);
  ui.countBlacklist.textContent = String(blacklist.length);

  for (const tab of [document.getElementById("list-tab-whitelist"), document.getElementById("list-tab-blacklist")]) {
    if (!tab) continue;
    const active = tab.dataset.listTab === state.tiList;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-pressed", active ? "true" : "false");
  }

  const black = state.tiList === "blacklist";
  ui.listHint.textContent = black
    ? "Blacklisted IPs, networks, domains and wildcard domains are known bad: they appear in reports with verdict Blacklisted and are never sent to VirusTotal. The blacklist wins when a value is on both lists."
    : "Whitelisted IPs, networks, domains and wildcard domains are trusted: they appear in reports but are never sent to VirusTotal. Examples: 1.1.1.1, 10.0.0.0/8, example.com, *.example.com.";
  ui.wlValueInput.placeholder = black
    ? "Known-bad IP, CIDR, domain or *.wildcard"
    : "IP, CIDR, domain or *.wildcard";

  const entries = black ? blacklist : whitelist;
  const query = state.wlQuery;
  const visible = entries.filter((entry) => !query || String(entry.value).toLowerCase().includes(query));
  const rows = visible.map((entry) => el("li", { class: "wl-row" },
    el("span", { class: "tag", "data-type": entry.type, text: ENTRY_TYPE_LABELS[entry.type] || entry.type }),
    el("span", { class: "wl-main" },
      el("span", { class: "mono wl-value", text: entry.value }),
      entry.note ? el("span", { class: "wl-note", title: entry.note, text: entry.note }) : ""
    ),
    el("span", { class: "wl-added", title: entry.created_at || "", text: entry.created_at ? relative(entry.created_at) : "" }),
    el("button", {
      class: "icon-btn icon-btn--danger",
      type: "button",
      "data-wl-remove": entry.id,
      "aria-label": "Remove " + entry.value + " from the " + listLabel(),
      title: "Remove",
    }, icon("trash"))
  ));
  ui.wlList.replaceChildren(...rows);
  ui.wlEmpty.hidden = visible.length > 0;
  if (entries.length && visible.length === 0) {
    ui.wlEmpty.textContent = "Nothing matches this filter.";
  } else if (black) {
    ui.wlEmpty.textContent = "The blacklist is empty — all public indicators go through VirusTotal.";
  } else {
    ui.wlEmpty.textContent = "The whitelist is empty — every public indicator will be checked.";
  }
}

async function saveTISettings(event) {
  event.preventDefault();
  if (ui.tiSaveBtn.disabled) return;
  showTIError("");
  const rate = Number.parseInt(ui.vtRateInput.value, 10);
  const max = Number.parseInt(ui.vtMaxInput.value, 10);
  const body = { vt_auto_enrich: ui.vtAutoInput.checked };
  if (Number.isFinite(rate)) body.vt_rate_per_min = rate;
  if (Number.isFinite(max)) body.vt_max_queries_per_job = max;
  const key = ui.vtKeyInput.value.trim();
  if (key) body.vt_api_key = key;
  ui.tiSaveBtn.disabled = true;
  ui.tiSaveBtn.textContent = "Saving…";
  try {
    const response = await api("/v1/settings/ti", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await response.json();
    ui.vtKeyInput.value = "";
    toast("Threat Intel settings saved.", "success");
    await refreshTISettings();
  } catch (err) {
    if (err.status !== 401) showTIError(err.message || "Could not save settings.");
  } finally {
    ui.tiSaveBtn.disabled = false;
    ui.tiSaveBtn.textContent = "Save settings";
  }
}

async function addListEntry() {
  if (ui.wlAddBtn.disabled) return;
  showWLError("");
  const value = ui.wlValueInput.value.trim();
  const note = ui.wlNoteInput.value.trim();
  if (!value) {
    showWLError("Enter an IP, CIDR, domain or *.wildcard value.");
    ui.wlValueInput.focus();
    return;
  }
  const endpoint = listEndpoint();
  const label = state.tiList === "blacklist" ? "Blacklisted" : "Whitelisted";
  ui.wlAddBtn.disabled = true;
  try {
    const response = await api(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value, note }),
    });
    await response.json();
    ui.wlValueInput.value = "";
    ui.wlNoteInput.value = "";
    toast(label + " " + value, "success");
    await refreshTISettings();
  } catch (err) {
    if (err.status !== 401) showWLError(err.message || "Could not add the entry.");
  } finally {
    ui.wlAddBtn.disabled = false;
  }
}

async function removeListEntry(id) {
  const label = listLabel();
  try {
    const response = await api(listEndpoint() + "/" + encodeURIComponent(id), { method: "DELETE" });
    if (response.status === 204) toast("Removed from the " + label + ".", "success");
    await refreshTISettings();
  } catch (err) {
    if (err.status !== 401) toast(err.message || "Could not remove the entry.", "error");
  }
}

function showTIError(message) {
  ui.tiError.textContent = message || "";
  ui.tiError.hidden = !message;
}

function showWLError(message) {
  ui.wlError.textContent = message || "";
  ui.wlError.hidden = !message;
}

/* --------------------------------------------------------------------------
   Theme
   -------------------------------------------------------------------------- */

function currentTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function updateThemeButton() {
  const dark = currentTheme() === "dark";
  const label = dark ? "Switch to light theme" : "Switch to dark theme";
  ui.themeBtn.setAttribute("aria-label", label);
  ui.themeBtn.title = label;
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch (err) {
    // Theme still applies for this page load.
  }
  updateThemeButton();
}

/* --------------------------------------------------------------------------
   Events and bootstrap
   -------------------------------------------------------------------------- */

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

async function onConnect(event) {
  event.preventDefault();
  if (ui.connectBtn.disabled) return;
  showConnectError("");
  const token = ui.tokenInput.value.trim();
  if (!token) {
    showConnectError("Enter the operator token.");
    ui.tokenInput.focus();
    return;
  }

  setBusy(ui.connectBtn, true, "Connecting…");
  try {
    const meta = await fetchMeta(token);
    state.token = token;
    state.meta = meta;
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch (err) {
      // Session storage may be disabled; the token still works until reload.
    }
    ui.tokenInput.value = "";
    showDashboard();
    await loadJobs();
    openJobFromHash();
  } catch (err) {
    if (err.status === 401) showConnectError("That token was rejected by the server.");
    else showConnectError("Cannot reach the server. " + err.message);
  } finally {
    setBusy(ui.connectBtn, false, "Connect");
  }
}

async function resumeSession() {
  try {
    state.meta = await fetchMeta(state.token);
    showDashboard();
    await loadJobs();
    openJobFromHash();
  } catch (err) {
    if (err.status === 401) {
      clearSession();
      showConnect("The stored token was rejected. Connect again.");
    } else {
      showConnect("Cannot reach the server. " + err.message);
    }
  }
}

function bindEvents() {
  ui.connectForm.addEventListener("submit", onConnect);

  ui.revealBtn.addEventListener("click", () => {
    const reveal = ui.tokenInput.type === "password";
    ui.tokenInput.type = reveal ? "text" : "password";
    ui.revealBtn.textContent = reveal ? "Hide" : "Show";
    ui.revealBtn.setAttribute("aria-pressed", reveal ? "true" : "false");
    ui.revealBtn.setAttribute("aria-label", reveal ? "Hide token" : "Show token");
  });

  ui.signoutBtn.addEventListener("click", () => endSession("Disconnected."));
  ui.themeBtn.addEventListener("click", toggleTheme);
  ui.newBtn.addEventListener("click", openNewDialog);
  ui.emptyNew.addEventListener("click", openNewDialog);

  ui.refreshBtn.addEventListener("click", () => loadJobs());

  ui.searchInput.addEventListener("input", () => {
    state.query = ui.searchInput.value.trim().toLowerCase();
    renderList();
  });

  ui.filters.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]");
    if (!button) return;
    state.filter = button.dataset.filter;
    updateFilters();
    renderList();
  });

  ui.jobList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-job-id]");
    if (!button) return;
    const job = findJob(button.dataset.jobId);
    if (job) openDetail(job);
  });

  ui.newForm.addEventListener("submit", createCollection);
  ui.newClose.addEventListener("click", () => ui.newDialog.close());
  ui.newCancel.addEventListener("click", () => ui.newDialog.close());
  ui.newDialog.addEventListener("close", () => showNewError(""));
  ui.newDialog.addEventListener("click", (event) => {
    if (event.target === ui.newDialog) ui.newDialog.close();
  });

  ui.detailClose.addEventListener("click", () => ui.jobDialog.close());
  ui.jobDialog.addEventListener("click", (event) => {
    if (event.target === ui.jobDialog) ui.jobDialog.close();
  });
  ui.jobDialog.addEventListener("close", () => {
    state.selectedId = null;
    state.reportForDetail = null;
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  });
  ui.detailBody.addEventListener("click", onDetailBodyClick);
  ui.detailBody.addEventListener("input", onDetailBodyInput);

  // Threat Intel settings dialog
  ui.tiBtn.addEventListener("click", openTIDialog);
  ui.tiClose.addEventListener("click", () => ui.tiDialog.close());
  ui.tiDoneBtn.addEventListener("click", () => ui.tiDialog.close());
  ui.tiDialog.addEventListener("click", (event) => {
    if (event.target === ui.tiDialog) ui.tiDialog.close();
  });
  ui.tiDialog.addEventListener("close", () => {
    showTIError("");
    showWLError("");
  });
  ui.tiForm.addEventListener("submit", saveTISettings);
  ui.vtKeyReveal.addEventListener("click", () => {
    const reveal = ui.vtKeyInput.type === "password";
    ui.vtKeyInput.type = reveal ? "text" : "password";
    ui.vtKeyReveal.textContent = reveal ? "Hide" : "Show";
    ui.vtKeyReveal.setAttribute("aria-pressed", reveal ? "true" : "false");
  });
  for (const tab of [document.getElementById("list-tab-whitelist"), document.getElementById("list-tab-blacklist")]) {
    if (tab) tab.addEventListener("click", () => setActiveList(tab.dataset.listTab));
  }
  ui.wlAddBtn.addEventListener("click", addListEntry);
  const onWlEnter = (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      addListEntry();
    }
  };
  ui.wlValueInput.addEventListener("keydown", onWlEnter);
  ui.wlNoteInput.addEventListener("keydown", onWlEnter);
  ui.wlSearchInput.addEventListener("input", () => {
    state.wlQuery = ui.wlSearchInput.value.trim().toLowerCase();
    renderLists();
  });
  ui.wlList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-wl-remove]");
    if (button) removeListEntry(button.dataset.wlRemove);
  });

  window.addEventListener("hashchange", () => {
    if (!state.token) return;
    const id = jobIdFromHash();
    if (!id) {
      if (ui.jobDialog.open) ui.jobDialog.close();
      return;
    }
    const job = findJob(id);
    if (job) openDetail(job, { hash: false });
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopPoll();
    else if (state.token && !ui.dashboardView.hidden) loadJobs({ silent: true });
  });
}

function init() {
  buildFilters();
  bindEvents();
  updateThemeButton();

  let saved = "";
  try {
    saved = sessionStorage.getItem(TOKEN_KEY) || "";
  } catch (err) {
    saved = "";
  }

  if (saved) {
    state.token = saved;
    resumeSession();
  } else {
    showConnect();
  }
}

init();
