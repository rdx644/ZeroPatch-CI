const state = {
  findings: [],
  scannedWorkflow: "",
  sourceName: "workflow.yml",
  requestToken: 0,
  authenticated: false,
};
const $ = (selector) => document.querySelector(selector);
function setNotice(message = "", tone = "") {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice ${tone}`;
  notice.hidden = !message;
}
async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (response.ok) return response.json();
  const payload = await response.json().catch(() => ({}));
  const error = new Error(payload.detail || `Request failed (${response.status})`);
  error.status = response.status;
  throw error;
}
function setWorkflow(workflow, sourceName = "workflow.yml") {
  state.sourceName = sourceName;
  $("#workflow").value = workflow;
  $("#sourceName").textContent = sourceName;
  invalidateScan();
  setNotice();
}
function invalidateScan(message = "") {
  state.findings = [];
  state.scannedWorkflow = "";
  $("#stepScan").classList.remove("active");
  $("#stepPatch").classList.remove("active");
  $("#evidencePanel").hidden = true;
  $("#postureScore").textContent = "?";
  $("#criticalCount").textContent = "?";
  $("#highCount").textContent = "?";
  $("#controlCount").textContent = "5";
  $("#findingTotal").textContent = "0";
  $("#patchBtn").disabled = true;
  renderFindings([]);
  if (message) setNotice(message, "progress");
}
function severityColor(severity) {
  return severity === "critical"
    ? "#dc4d44"
    : severity === "high"
      ? "#ff9f58"
      : "#7aa8ff";
}
function setSignedOutState() {
  const link = $("#authLink");
  link.textContent = "Sign in with GitHub";
  link.href = "/auth/github/login";
  link.removeAttribute("aria-disabled");
}
function renderFindings(findings) {
  const host = $("#findings");
  host.replaceChildren();
  if (!findings.length) {
    host.className = "empty";
    host.textContent = "No policy violations matched this workflow. Your workflow is clear against the five controls checked.";
    return;
  }
  host.className = "finding-list";
  const template = $("#findingTemplate");
  findings.forEach((finding, index) => {
    const node = template.content.cloneNode(true);
    const article = node.querySelector("article");
    article.dataset.id = finding.id;
    article.style.setProperty("--entry-index", index);
    article.classList.toggle("disabled", !finding.fixable);
    const input = node.querySelector("input");
    input.disabled = !finding.fixable;
    input.addEventListener("change", togglePatchButton);
    node.querySelector(".finding-title > b").style.background = severityColor(
      finding.severity,
    );
    node.querySelector("h3").textContent = finding.title;
    node.querySelector("code").textContent = finding.rule_id;
    node.querySelector(".evidence").textContent =
      `L${finding.line}: ${finding.evidence}`;
    node.querySelector(".recommendation").textContent = finding.fixable
      ? finding.recommendation
      : "Human redesign required: this control is intentionally review-only.";
    node.querySelector(".priority").textContent = finding.ml_priority;
    node.querySelector(".anomaly").textContent = finding.anomaly_score;
    node.querySelector(".line").textContent =
      `${finding.confidence}% policy confidence`;
    host.append(node);
  });
}
function animateScanResults() {
  const metrics = [
    "#postureScore",
    "#criticalCount",
    "#highCount",
    "#controlCount",
    "#findingTotal",
  ];
  metrics.forEach((selector, index) => {
    const metric = $(selector);
    metric.classList.remove("metric-updated");
    // Restart the compact confirmation animation when a new scan completes.
    void metric.offsetWidth;
    metric.style.setProperty("--metric-delay", `${index * 45}ms`);
    metric.classList.add("metric-updated");
  });
}
function togglePatchButton() {
  $("#patchBtn").disabled = !document.querySelector(".finding input:checked");
}
async function scan() {
  const workflow = $("#workflow").value;
  if (!workflow.trim()) {
    setNotice("Paste a GitHub Actions workflow before scanning.", "error");
    $("#workflow").focus();
    return;
  }
  const token = ++state.requestToken;
  const button = $("#scanBtn");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = "Scanning";
  setNotice("Evaluating policy controls...", "progress");
  try {
    const result = await request("/api/scan", {
      method: "POST",
      body: JSON.stringify({ workflow, source_name: state.sourceName }),
    });
    if (token !== state.requestToken || $("#workflow").value !== workflow) return;
    state.scannedWorkflow = workflow;
    state.findings = result.findings;
    $("#postureScore").textContent = result.posture.score;
    $("#criticalCount").textContent = result.posture.critical;
    $("#highCount").textContent = result.posture.high;
    $("#controlCount").textContent = result.posture.covered_controls;
    $("#findingTotal").textContent = result.findings.length;
    $("#stepScan").classList.add("active");
    $("#stepPatch").classList.remove("active");
    $("#evidencePanel").hidden = true;
    $("#patchBtn").disabled = true;
    renderFindings(result.findings);
    animateScanResults();
    setNotice(
      `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} ready for review.`,
      "success",
    );
  } catch (error) {
    setNotice(error.message, "error");
  } finally {
    if (token === state.requestToken) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.textContent = "Scan workflow";
    }
  }
}
function renderEvidence(result) {
  $("#patchId").textContent = result.patch_id;
  $("#summary").textContent = result.summary;
  $("#agentMode").textContent = result.agent_mode;
  $("#patchedWorkflow").textContent = result.patched_workflow;
  const evidence = $("#evidence");
  evidence.replaceChildren();
  const passed = result.evidence.filter((check) => check.status === "passed").length;
  $("#evidenceStatus").textContent = `${passed}/${result.evidence.length} structural checks passed. Review the draft before opening a pull request.`;
  result.evidence.forEach((check, index) => {
    const article = document.createElement("article");
    article.style.setProperty("--entry-index", index);
    const badge = document.createElement("span");
    badge.className = `badge ${check.status}`;
    badge.textContent = check.status;
    const heading = document.createElement("h4");
    heading.textContent = check.name;
    const detail = document.createElement("p");
    detail.textContent = check.detail;
    article.append(badge, heading, detail);
    evidence.append(article);
  });
  $("#evidencePanel").hidden = false;
  $("#stepPatch").classList.add("active");
  $("#evidencePanel").scrollIntoView({ behavior: "smooth", block: "start" });
}
async function patch() {
  const workflow = $("#workflow").value;
  if (!state.scannedWorkflow || workflow !== state.scannedWorkflow) {
    invalidateScan("Workflow changed; run another scan before generating a patch.");
    return;
  }
  const findingIds = [
    ...document.querySelectorAll(".finding input:checked"),
  ].map((input) => input.closest("article").dataset.id);
  if (!findingIds.length) return;
  const button = $("#patchBtn");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = "Generating";
  setNotice(
    "Building a deterministic draft patch and validation evidence...",
    "progress",
  );
  try {
    const result = await request("/api/remediate", {
      method: "POST",
      body: JSON.stringify({
        workflow: state.scannedWorkflow,
        source_name: state.sourceName,
        finding_ids: findingIds,
        use_agent: $("#useAgent").checked,
      }),
    });
    if (state.scannedWorkflow !== workflow || $("#workflow").value !== workflow) return;
    renderEvidence(result);
    setNotice(
      "Draft patch generated. Human approval remains required.",
      "success",
    );
  } catch (error) {
    setNotice(error.message, "error");
  } finally {
    if (state.scannedWorkflow !== workflow) return;
    button.removeAttribute("aria-busy");
    button.textContent = "Generate draft patch";
    togglePatchButton();
  }
}
async function loadSample(scanAfterLoad = false) {
  setNotice("Loading demo workflow...", "progress");
  try {
    const sample = await request("/api/sample");
    setWorkflow(sample.workflow, sample.source_name);
    if (scanAfterLoad) await scan();
  } catch (error) {
    setNotice(error.message, "error");
  }
}

async function loadIdentity() {
  try {
    const identity = await request("/api/me");
    state.authenticated = identity.authenticated || !identity.auth_required;
    const link = $("#authLink");
    if (!identity.authenticated) {
      link.textContent = "Demo mode";
      link.removeAttribute("href");
      link.setAttribute("aria-disabled", "true");
      return state.authenticated;
    }
    link.textContent = `Signed in as ${identity.login}`;
    link.href = "#";
    link.addEventListener("click", async (event) => {
      event.preventDefault();
      await fetch("/auth/logout", { method: "POST" });
      window.location.assign("/");
    });
    return true;
  } catch (error) {
    state.authenticated = false;
    setSignedOutState();
    return false;
  }
}

$("#loadSample").addEventListener("click", () => loadSample(state.authenticated));
$("#scanBtn").addEventListener("click", scan);
$("#patchBtn").addEventListener("click", patch);
$("#workflow").addEventListener("input", () => {
  const scanButton = $("#scanBtn");
  const wasScanning = scanButton.getAttribute("aria-busy") === "true";
  state.requestToken += 1;
  if (state.scannedWorkflow) {
    invalidateScan("Workflow changed; run another scan before generating a patch.");
  }
  if (wasScanning) {
    scanButton.disabled = false;
    scanButton.removeAttribute("aria-busy");
    scanButton.textContent = "Scan workflow";
  }
});
function preferredTheme() {
  try {
    const savedTheme = localStorage.getItem("zeropatch-theme");
    if (savedTheme === "night" || savedTheme === "day") return savedTheme;
  } catch (_) {
    // Storage can be unavailable in private or locked-down contexts.
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "night" : "day";
}
function applyTheme(theme) {
  const night = theme === "night";
  document.body.classList.toggle("theme-night", night);
  const button = $("#themeToggle");
  button.setAttribute("aria-pressed", String(night));
  button.setAttribute("aria-label", night ? "Disable night shift" : "Enable night shift");
  button.textContent = night ? "Night shift: on" : "Night shift";
  document.querySelector('meta[name="theme-color"]').setAttribute("content", night ? "#07121d" : "#11251f");
  try {
    localStorage.setItem("zeropatch-theme", theme);
  } catch (_) {
    // The theme still works for this session when storage is unavailable.
  }
}
applyTheme(preferredTheme());
$("#themeToggle").addEventListener("click", () => {
  applyTheme(document.body.classList.contains("theme-night") ? "day" : "night");
});
window.addEventListener("DOMContentLoaded", async () => {
  const signedIn = await loadIdentity();
  await loadSample(signedIn);
  if (!signedIn) setNotice("Sign in with GitHub to scan or generate a draft patch.", "progress");
});
