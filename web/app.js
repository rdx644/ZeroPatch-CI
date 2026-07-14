const state = { findings: [], workflow: "", sourceName: "workflow.yml" };
const $ = (selector) => document.querySelector(selector);

async function request(url, options = {}) {
  const response = await fetch(url, { headers: { "Content-Type": "application/json" }, ...options });
  if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
  return response.json();
}

function setWorkflow(workflow, sourceName = "workflow.yml") {
  state.workflow = workflow; state.sourceName = sourceName;
  $("#workflow").value = workflow; $("#sourceName").textContent = sourceName;
}

function severityColor(severity) { return severity === "critical" ? "#bf3826" : "#ff6f3c"; }

function renderFindings(findings) {
  const host = $("#findings"); host.replaceChildren();
  if (!findings.length) { host.className = "empty"; host.textContent = "No policy violations matched this workflow."; return; }
  host.className = "";
  const template = $("#findingTemplate");
  findings.forEach((finding) => {
    const node = template.content.cloneNode(true); const article = node.querySelector("article");
    article.dataset.id = finding.id; article.classList.toggle("disabled", !finding.fixable);
    const input = node.querySelector("input"); input.disabled = !finding.fixable; input.addEventListener("change", togglePatchButton);
    node.querySelector(".finding-title>b").style.background = severityColor(finding.severity);
    node.querySelector("h3").textContent = finding.title; node.querySelector("code").textContent = finding.rule_id;
    node.querySelector(".evidence").textContent = `L${finding.line}: ${finding.evidence}`;
    node.querySelector(".recommendation").textContent = finding.fixable ? finding.recommendation : "Human redesign required: ZeroPatch will not remove or rewrite artifact execution automatically.";
    node.querySelector(".priority").textContent = finding.ml_priority; node.querySelector(".anomaly").textContent = finding.anomaly_score;
    node.querySelector(".line").textContent = `${finding.confidence}% policy confidence`;
    host.append(node);
  });
}

function togglePatchButton() { $("#patchBtn").disabled = !document.querySelector(".finding input:checked"); }

async function scan() {
  const workflow = $("#workflow").value.trim(); if (!workflow) return;
  $("#scanBtn").disabled = true; $("#scanBtn").textContent = "Scanning…";
  try {
    const result = await request("/api/scan", { method: "POST", body: JSON.stringify({ workflow, source_name: state.sourceName }) });
    state.workflow = workflow; state.findings = result.findings;
    $("#postureScore").textContent = result.posture.score; $("#criticalCount").textContent = result.posture.critical;
    $("#highCount").textContent = result.posture.high; $("#controlCount").textContent = result.posture.covered_controls;
    $("#findingTotal").textContent = result.findings.length; $("#stepScan").classList.add("active");
    $("#evidencePanel").hidden = true; $("#patchBtn").disabled = true; renderFindings(result.findings);
  } catch (error) { alert(error.message); }
  finally { $("#scanBtn").disabled = false; $("#scanBtn").textContent = "Scan workflow ?"; }
}

function renderEvidence(result) {
  $("#patchId").textContent = result.patch_id; $("#summary").textContent = result.summary; $("#agentMode").textContent = result.agent_mode;
  $("#patchedWorkflow").textContent = result.patched_workflow;
  const evidence = $("#evidence"); evidence.replaceChildren();
  result.evidence.forEach((check) => {
    const article = document.createElement("article");
    const badge = document.createElement("span"); badge.className = `badge ${check.status}`; badge.textContent = check.status;
    const heading = document.createElement("h4"); heading.textContent = check.name;
    const detail = document.createElement("p"); detail.textContent = check.detail;
    article.append(badge, heading, detail); evidence.append(article);
  });
  $("#evidencePanel").hidden = false; $("#stepPatch").classList.add("active"); $("#evidencePanel").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function patch() {
  const finding_ids = [...document.querySelectorAll(".finding input:checked")].map((input) => input.closest("article").dataset.id);
  $("#patchBtn").disabled = true; $("#patchBtn").textContent = "Generating evidence…";
  try {
    const result = await request("/api/remediate", { method: "POST", body: JSON.stringify({ workflow: state.workflow, source_name: state.sourceName, finding_ids, use_agent: $("#useAgent").checked }) });
    renderEvidence(result);
  } catch (error) { alert(error.message); }
  finally { $("#patchBtn").textContent = "Generate draft patch ?"; togglePatchButton(); }
}

$("#loadSample").addEventListener("click", async () => { const sample = await request("/api/sample"); setWorkflow(sample.workflow, sample.source_name); scan(); });
$("#scanBtn").addEventListener("click", scan); $("#patchBtn").addEventListener("click", patch);
window.addEventListener("DOMContentLoaded", () => $("#loadSample").click());
