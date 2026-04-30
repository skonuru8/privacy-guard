import * as vscode from "vscode";
import { PrivacyGuardPanel } from "./webviewPanel";
import { checkStagedChanges } from "./diffScanner";
import { scanPackages } from "./packageScanner";

let panel: PrivacyGuardPanel;

function getApiKey(): string {
  const key = vscode.workspace
    .getConfiguration("privacyGuard")
    .get<string>("apiKey", "");
  if (!key) {
    throw new Error(
      "No API key set. Open Settings and configure privacyGuard.apiKey."
    );
  }
  return key;
}

export function activate(context: vscode.ExtensionContext) {
  panel = new PrivacyGuardPanel();

  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("privacyGuard.panel", {
      resolveWebviewView(view) {
        panel.resolveWebviewView(view);
      },
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      "privacyGuard.checkStagedChanges",
      async () => {
        try {
          const key = getApiKey();
          panel.showLoading("Checking staged changes for privacy issues...");
          const result = await checkStagedChanges(key);
          panel.showDiffResults(result);
        } catch (err: any) {
          panel.showError(err.message);
        }
      }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("privacyGuard.scanPackages", async () => {
      try {
        const key = getApiKey();
        panel.showLoading("Scoring dependencies for privacy risk...");
        const results = await scanPackages(key);
        panel.showPackageResults(results);
      } catch (err: any) {
        panel.showError(err.message);
      }
    })
  );
}

export function deactivate() {}
