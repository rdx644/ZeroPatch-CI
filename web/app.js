const state = {
  findings: [],
  scannedWorkflow: "",
  sourceName: "workflow.yml",
  requestToken: 0,
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
  throw new Error(payload.detail || `Request failed (${response.status})`);
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
function renderFindings(findings) {
  const host = $("#findings");
  host.replaceChildren();
  if (!findings.length) {
    host.className = "empty";
    host.textContent = "No policy violations matched this workflow.";
    return;
  }
  host.className = "finding-list";
  const template = $("#findingTemplate");
  findings.forEach((finding) => {
    const node = template.content.cloneNode(true);
    const article = node.querySelector("article");
    article.dataset.id = finding.id;
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
  result.evidence.forEach((check) => {
    const article = document.createElement("article");
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
$("#loadSample").addEventListener("click", async () => {
  setNotice("Loading demo workflow...", "progress");
  try {
    const sample = await request("/api/sample");
    setWorkflow(sample.workflow, sample.source_name);
    await scan();
  } catch (error) {
    setNotice(error.message, "error");
  }
});
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
