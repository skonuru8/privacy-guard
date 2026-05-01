import * as vscode from "vscode";
import { PackageResult } from "./packageScanner";
import { DiffResult } from "./diffScanner";

export class PrivacyGuardPanel {
  private _view?: vscode.WebviewView;

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;
    webviewView.webview.options = { enableScripts: true };
    this.showHome();

    webviewView.webview.onDidReceiveMessage((msg) => {
      switch (msg.command) {
        case "home":
          this.showHome();
          break;
        case "openSettings":
          vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "privacyGuard"
          );
          break;
        case "runCommand":
          vscode.commands.executeCommand(msg.cmd);
          break;
      }
    });
  }

  showLoading(message: string) {
    this.setHtml(/* html */ `
      <div class="loading-wrap">
        <div class="spinner"></div>
        <p>${esc(message)}</p>
      </div>`);
  }

  showError(error: string) {
    const isApiKey = error.toLowerCase().includes("api key");
    this.setHtml(/* html */ `
      <div class="center">
        <div style="font-size:28px;margin-bottom:12px">⚠️</div>
        <p class="muted" style="margin-bottom:16px">${esc(error)}</p>
        ${isApiKey ? `<button onclick="msg('openSettings')">Configure API Key</button>` : ""}
        <button class="ghost" onclick="msg('home')">← Back</button>
      </div>`);
  }

  showHome() {
    this.setHtml(/* html */ `
      <div style="text-align:center;padding:16px 0 20px">
        <div style="font-size:36px;margin-bottom:8px">🛡️</div>
        <h2>Privacy Guard</h2>
        <p class="muted" style="margin-bottom:20px">Catch privacy issues before they ship</p>
      </div>
      <div class="card-list">
        <div class="card" onclick="msg('runCommand','privacyGuard.checkStagedChanges')">
          <div class="card-icon">🔍</div>
          <div>
            <div class="card-title">Pre-Commit Check</div>
            <div class="muted">Scan staged changes for privacy issues</div>
          </div>
        </div>
        <div class="card" onclick="msg('runCommand','privacyGuard.scanPackages')">
          <div class="card-icon">📦</div>
          <div>
            <div class="card-title">Scan Dependencies</div>
            <div class="muted">Score packages for privacy risk</div>
          </div>
        </div>
      </div>
      <p class="muted" style="text-align:center;margin-top:20px;font-size:11px">
        <a href="#" onclick="msg('openSettings')">Configure API key →</a>
      </p>`);
  }

  showDiffResults(result: DiffResult) {
    const riskColor = { LOW: "#34d399", MEDIUM: "#fbbf24", HIGH: "#f87171" }[result.overall_risk];
    const issues = result.issues.length === 0
      ? `<div class="all-clear">🎉 No privacy issues found. Safe to commit.</div>`
      : result.issues.map((issue, i) => /* html */ `
          <div class="issue sev-${issue.severity.toLowerCase()}">
            <div class="issue-top">
              <span class="issue-file">${esc(issue.file)}</span>
              <span class="badge" style="background:${{ LOW: "#34d399", MEDIUM: "#fbbf24", HIGH: "#f87171" }[issue.severity]}">${issue.severity}</span>
            </div>
            ${issue.line_hint ? `<code>${esc(issue.line_hint)}</code>` : ""}
            <p>🔴 <strong>Issue:</strong> ${esc(issue.issue)}</p>
            <p>✅ <strong>Fix:</strong> ${esc(issue.fix)}</p>
            ${issue.regulation ? `<p class="reg">⚖️ ${esc(issue.regulation)}</p>` : ""}
          </div>`).join("");

    this.setHtml(/* html */ `
      <div class="top-bar">
        <button class="ghost" onclick="msg('home')">← Back</button>
        <strong>Pre-Commit Check</strong>
      </div>
      <div class="risk-banner" style="border-color:${riskColor}">
        <span class="muted">Overall Risk</span>
        <span style="color:${riskColor};font-weight:700">${result.overall_risk}</span>
      </div>
      <p class="muted" style="margin-bottom:12px">${esc(result.summary)}</p>
      ${issues}`);
  }

  showPackageResults(results: PackageResult[]) {
    const high = results.filter((r) => r.score === "HIGH_RISK");
    const caution = results.filter((r) => r.score === "CAUTION");
    const safe = results.filter((r) => r.score === "SAFE");
    const consenterraResults = results.filter((r) => r.privacyPolicyUrl || r.privacyReport);
    const llmRequest = results.find((r) => r.debugLlmRequest)?.debugLlmRequest;
    const llmResponse = results.find((r) => r.debugLlmResponse)?.debugLlmResponse;

    const colors = { HIGH_RISK: "#f87171", CAUTION: "#fbbf24", SAFE: "#34d399" };
    const labels = { HIGH_RISK: "HIGH RISK", CAUTION: "CAUTION", SAFE: "SAFE" };

    /** Map Consenterra letter grades to display colors */
    const gradeColors: Record<string, string> = {
      "A+": "#22c55e", "A": "#34d399", "A-": "#4ade80",
      "B+": "#86efac", "B": "#a3e635", "B-": "#bef264",
      "C+": "#fbbf24", "C": "#f59e0b", "C-": "#f97316",
      "D+": "#fb923c", "D": "#ef4444", "D-": "#dc2626",
      "F": "#b91c1c",
    };

    const renderConsenTerraReport = (r: PackageResult) => {
      const rpt = r.privacyReport;
      const reportData = rpt?.data ?? rpt;
      const grade = reportData?.grade ?? "N/A";
      const gColor = gradeColors[grade] ?? "#888";
      const score = reportData?.score != null ? `${reportData.score}/100` : "";
      const error = rpt?.error;
      const statusCode = rpt?.statusCode;
      const riskLevel = reportData?.risk_level;
      const summary = reportData?.summary;
      const clauses = reportData?.clauses ?? [];
      const riskBreakdown = reportData?.risk_breakdown;
      const riskBreakdownText = riskBreakdown
        ? Object.entries(riskBreakdown).map(([label, count]) => `${label}: ${count}`).join(", ")
        : "";

      return /* html */ `
        <div class="ct-report ${rpt ? "" : "ct-report-empty"}">
          <div class="ct-header">
            <div>
              <span class="ct-source">Consenterra Response</span>
              <div class="ct-package">${esc(r.name)} <span class="muted">${esc(r.version)}</span></div>
            </div>
            ${rpt ? `
              <div class="ct-grade" style="background:${gColor}20;color:${gColor};border:1px solid ${gColor}40">
                ${esc(grade)}
              </div>` : ""}
          </div>
          ${r.privacyPolicyUrl ? `
            <p class="privacy-url">
              🔗 <strong>Privacy URL:</strong>
              <a href="${esc(r.privacyPolicyUrl)}">${esc(r.privacyPolicyUrl)}</a>
            </p>` : ""}
          ${rpt && reportData ? `
            <div class="ct-metrics">
              ${statusCode ? `<span class="muted" style="font-size:11px">HTTP: <strong>${esc(String(statusCode))}</strong></span>` : ""}
              ${score ? `<span class="muted" style="font-size:11px">Score: <strong>${esc(score)}</strong></span>` : ""}
              ${riskLevel ? `<span class="muted" style="font-size:11px">Risk: <strong>${esc(riskLevel)}</strong></span>` : ""}
              ${reportData?.domain ? `<span class="muted" style="font-size:11px">Domain: <strong>${esc(reportData.domain)}</strong></span>` : ""}
            </div>
            ${error ? `<p class="ct-error">${esc(error)}</p>` : ""}
            ${summary ? `<p class="muted ct-summary">${esc(summary)}</p>` : ""}
            ${riskBreakdownText ? `<p class="muted ct-summary">Breakdown: ${esc(riskBreakdownText)}</p>` : ""}
            ${clauses.length > 0 ? `
              <div class="ct-clauses">
                ${clauses.slice(0, 5).map((c: any) => `
                  <div class="ct-clause">
                    <span class="ct-clause-tag">${esc(c.classification ?? c.category ?? c.type ?? "Clause")}</span>
                    <span class="muted" style="font-size:10px">${esc(c.plain_insight ?? c.summary ?? c.text ?? "")}</span>
                    ${c.fine_label ? `<span class="muted" style="font-size:10px">(${esc(c.fine_label)})</span>` : ""}
                  </div>`).join("")}
                ${clauses.length > 5 ? `<p class="muted" style="font-size:10px">+${clauses.length - 5} more clauses</p>` : ""}
              </div>` : ""}` : `
            <p class="muted" style="font-size:10px;font-style:italic;margin-top:2px">⏳ Privacy report unavailable</p>`}
          ${rpt ? `
            <div class="ct-raw">
              <div class="ct-raw-title">Raw Consenterra API Response</div>
              <pre>${esc(JSON.stringify(rpt, null, 2))}</pre>
            </div>` : ""}
        </div>`;
    };

    const renderPkg = (r: PackageResult) => /* html */ `
      <div class="pkg sev-${r.score.toLowerCase()}">
        <div class="issue-top">
          <span class="issue-file">${esc(r.name)}</span>
          <span class="muted" style="font-size:11px">${esc(r.version)}</span>
          <span class="badge" style="background:${colors[r.score]};color:#000">${labels[r.score]}</span>
        </div>
        <p class="muted">${esc(r.reason)}</p>
        ${r.regulation ? `<p class="reg">⚖️ ${esc(r.regulation)}</p>` : ""}
        ${r.alternative ? `<p style="color:#34d399;font-size:11px">💡 Try: <strong>${esc(r.alternative)}</strong></p>` : ""}
      </div>`;

    const section = (label: string, emoji: string, items: PackageResult[]) =>
      items.length === 0 ? "" : /* html */ `
        <div class="group-label">${emoji} ${label} (${items.length})</div>
        ${items.map(renderPkg).join("")}`;

    this.setHtml(/* html */ `
      <div class="top-bar">
        <button class="ghost" onclick="msg('home')">← Back</button>
        <strong>Dependency Scan</strong>
      </div>
      <div class="summary-row">
        <span class="chip high">${high.length} High Risk</span>
        <span class="chip caution">${caution.length} Caution</span>
        <span class="chip safe">${safe.length} Safe</span>
      </div>
      ${llmResponse ? /* html */ `
        <details class="debug-section">
          <summary>LLM Response</summary>
          <pre>${esc(llmResponse)}</pre>
        </details>` : ""}
      ${llmRequest ? /* html */ `
        <details class="debug-section">
          <summary>LLM Request</summary>
          <pre>${esc(llmRequest)}</pre>
        </details>` : ""}
      ${consenterraResults.length > 0 ? /* html */ `
        <div class="ct-section">
          <div class="ct-section-title">Consenterra Responses (${consenterraResults.length})</div>
          ${consenterraResults.map(renderConsenTerraReport).join("")}
        </div>` : ""}
      ${section("High Risk", "🚨", high)}
      ${section("Caution", "⚠️", caution)}
      ${section("Safe", "✅", safe)}`);
  }

  private showHome_bound = this.showHome.bind(this);

  private setHtml(body: string) {
    if (!this._view) return;
    this._view.webview.html = `<!DOCTYPE html>
<html>
<head>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: 13px;
    color: var(--vscode-foreground);
    background: var(--vscode-sideBar-background);
    padding: 12px;
    line-height: 1.5;
  }
  h2 { font-size: 16px; }
  a { color: var(--vscode-textLink-foreground); cursor: pointer; }
  .muted { color: var(--vscode-descriptionForeground); font-size: 12px; }
  button {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none; border-radius: 4px;
    padding: 5px 12px; cursor: pointer; font-size: 12px; margin: 4px 2px;
  }
  button:hover { background: var(--vscode-button-hoverBackground); }
  button.ghost { background: transparent; border: 1px solid var(--vscode-widget-border); color: var(--vscode-foreground); }
  .card-list { display: flex; flex-direction: column; gap: 8px; }
  .card {
    display: flex; align-items: center; gap: 12px;
    background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-widget-border, #444);
    border-radius: 6px; padding: 12px; cursor: pointer;
  }
  .card:hover { border-color: var(--vscode-focusBorder); }
  .card-icon { font-size: 22px; }
  .card-title { font-weight: 600; margin-bottom: 2px; }
  .loading-wrap { text-align: center; padding: 48px 16px; }
  .spinner {
    width: 28px; height: 28px; margin: 0 auto 14px;
    border: 3px solid var(--vscode-widget-border, #444);
    border-top-color: var(--vscode-focusBorder);
    border-radius: 50%; animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .center { text-align: center; padding: 32px 12px; }
  .top-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
  .risk-banner {
    display: flex; justify-content: space-between; align-items: center;
    border: 1px solid; border-radius: 6px; padding: 8px 12px; margin-bottom: 8px;
  }
  .issue, .pkg {
    background: var(--vscode-editor-background);
    border-radius: 6px; padding: 10px; margin-bottom: 7px;
    border-left: 3px solid #555;
  }
  .issue.sev-high, .pkg.sev-high_risk { border-left-color: #f87171; }
  .issue.sev-medium, .pkg.sev-caution { border-left-color: #fbbf24; }
  .issue.sev-low, .pkg.sev-safe { border-left-color: #34d399; }
  .issue-top { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; flex-wrap: wrap; }
  .issue-file { font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; }
  .badge { padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 700; color: #000; }
  code {
    display: block; font-family: var(--vscode-editor-font-family);
    font-size: 11px; background: rgba(0,0,0,0.25);
    padding: 4px 6px; border-radius: 3px; margin-bottom: 6px;
    white-space: pre-wrap; word-break: break-all;
  }
  p { font-size: 12px; margin-bottom: 4px; }
  .reg { color: #a78bfa; font-size: 11px; }
  .privacy-url {
    font-size: 11px; margin-top: 4px; overflow-wrap: anywhere;
  }
  .privacy-url a { color: var(--vscode-textLink-foreground); }
  .all-clear { text-align: center; padding: 28px; color: #34d399; }
  .summary-row { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .chip { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .chip.high { background: rgba(248,113,113,0.15); color: #f87171; }
  .chip.caution { background: rgba(251,191,36,0.15); color: #fbbf24; }
  .chip.safe { background: rgba(52,211,153,0.15); color: #34d399; }
  .debug-section {
    margin: 0 0 12px; padding: 8px;
    border: 1px solid var(--vscode-widget-border, #444);
    border-radius: 6px;
    background: var(--vscode-editor-background);
  }
  .debug-section summary {
    cursor: pointer; font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .debug-section pre {
    margin-top: 8px; padding: 8px;
    max-height: 260px; overflow: auto;
    font-family: var(--vscode-editor-font-family);
    font-size: 10px; line-height: 1.4;
    white-space: pre-wrap; word-break: break-word;
    background: rgba(0,0,0,0.22);
    border-radius: 4px;
  }
  .group-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.6; margin: 10px 0 5px; }
  .ct-section {
    margin: 12px 0 14px; padding: 9px;
    border: 1px solid var(--vscode-focusBorder);
    border-radius: 6px;
    background: color-mix(in srgb, var(--vscode-focusBorder) 10%, transparent);
  }
  .ct-section-title {
    font-size: 11px; font-weight: 800; text-transform: uppercase;
    letter-spacing: 0.5px; margin-bottom: 7px;
    color: var(--vscode-focusBorder);
  }
  .ct-report {
    margin-top: 7px; padding: 8px; border-radius: 5px;
    background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-widget-border, rgba(255,255,255,0.10));
  }
  .ct-report-empty { opacity: 0.78; }
  .ct-header {
    display: flex; align-items: center; justify-content: space-between;
    gap: 8px; margin-bottom: 4px;
  }
  .ct-source { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; }
  .ct-package { font-weight: 700; margin-top: 1px; overflow-wrap: anywhere; }
  .ct-metrics { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .ct-error {
    color: #f87171; font-size: 10px; margin: 4px 0;
  }
  .ct-summary { font-size: 10px; margin: 4px 0; }
  .ct-grade {
    font-size: 14px; font-weight: 800; padding: 2px 8px;
    border-radius: 4px; line-height: 1.3;
  }
  .ct-clauses { margin-top: 4px; }
  .ct-clause {
    display: flex; align-items: baseline; gap: 6px;
    padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .ct-clause:last-child { border-bottom: none; }
  .ct-clause-tag {
    font-size: 9px; font-weight: 700; text-transform: uppercase;
    padding: 1px 5px; border-radius: 3px;
    background: rgba(255,255,255,0.08); white-space: nowrap;
  }
  .ct-raw { margin-top: 8px; }
  .ct-raw-title {
    margin-bottom: 4px; font-size: 10px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.75;
  }
  .ct-raw pre {
    padding: 7px; max-height: 260px; overflow: auto;
    white-space: pre-wrap; word-break: break-word;
    font-family: var(--vscode-editor-font-family); font-size: 10px;
    background: rgba(0,0,0,0.22); border-radius: 4px;
  }
</style>
</head>
<body>
${body}
<script>
  const vscode = acquireVsCodeApi();
  function msg(command, cmd) { vscode.postMessage({ command, cmd }); }
</script>
</body>
</html>`;
  }
}

function esc(str: string): string {
  return (str ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
