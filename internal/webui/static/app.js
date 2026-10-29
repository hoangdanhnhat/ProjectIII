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
  showConnect(message);
}

function showConnect(message) {
  ui.dashboardView.hidden = true;
  ui.connectView.hidden = false;
  ui.newBtn.hidden = true;
  ui.newBtn.disabled = true;
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
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
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
