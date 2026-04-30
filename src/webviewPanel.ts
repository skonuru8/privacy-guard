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
            "privacyGuard.apiKey"
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

    const colors = { HIGH_RISK: "#f87171", CAUTION: "#fbbf24", SAFE: "#34d399" };
    const labels = { HIGH_RISK: "HIGH RISK", CAUTION: "CAUTION", SAFE: "SAFE" };

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
  .all-clear { text-align: center; padding: 28px; color: #34d399; }
  .summary-row { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .chip { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .chip.high { background: rgba(248,113,113,0.15); color: #f87171; }
  .chip.caution { background: rgba(251,191,36,0.15); color: #fbbf24; }
  .chip.safe { background: rgba(52,211,153,0.15); color: #34d399; }
  .group-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.6; margin: 10px 0 5px; }
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
