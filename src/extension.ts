import * as vscode from "vscode";
import * as path from "path";
import { PrivacyGuardPanel } from "./webviewPanel";
import { checkStagedChanges } from "./diffScanner";
import { scanPackages } from "./packageScanner";
import { installHook, isHookInstalled, uninstallHook } from "./hookInstaller";

/** Singleton panel instance — one sidebar panel for the lifetime of the extension. */
let panel: PrivacyGuardPanel;

/**
 * Returns the root path of the first open workspace folder.
 * @throws If no workspace is currently open in VS Code
 */
function getWorkspaceRoot(): string {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) throw new Error("No workspace open");
  return folders[0].uri.fsPath;
}

/**
 * Tries to install the git pre-commit hook silently on extension activation.
 * Shows a one-time info message if the hook is newly installed.
 * Skips silently if the workspace is not ready or the hook is already present.
 *
 * @param runnerPath - Absolute path to hookRunner.js inside the extension bundle
 */
function tryInstallHook(runnerPath: string) {
  try {
    const root = getWorkspaceRoot();
    if (isHookInstalled(root)) return;
    const result = installHook(root, runnerPath);
    if (result.installed) {
      vscode.window.showInformationMessage(
        "Privacy Guard: Pre-commit hook installed. Your commits will be scanned automatically."
      );
    }
  } catch {
    // Workspace not ready yet — silently skip, user can install manually
  }
}

/**
 * Extension activation entry point called by VS Code when the extension loads.
 * Registers all commands, the sidebar webview provider, and installs the git hook.
 *
 * @param context - VS Code extension context used to register disposables
 */
export function activate(context: vscode.ExtensionContext) {
  panel = new PrivacyGuardPanel();
  const runnerPath = path.join(context.extensionPath, "hookRunner.js");

  tryInstallHook(runnerPath);

  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("privacyGuard.panel", {
      resolveWebviewView(view) {
        panel.resolveWebviewView(view);
      },
    })
  );

  /**
   * Command: run a privacy check on currently staged git changes.
   * AI provider and key are read from VS Code settings inside checkStagedChanges().
   */
  context.subscriptions.push(
    vscode.commands.registerCommand("privacyGuard.checkStagedChanges", async () => {
      try {
        panel.showLoading("Checking staged changes for privacy issues...");
        const result = await checkStagedChanges();
        panel.showDiffResults(result);
      } catch (err: any) {
        panel.showError(err.message);
      }
    })
  );

  /**
   * Command: score all npm dependencies in package.json for privacy risk.
   * AI provider and key are read from VS Code settings inside scanPackages().
   */
  context.subscriptions.push(
    vscode.commands.registerCommand("privacyGuard.scanPackages", async () => {
      try {
        panel.showLoading("Scoring dependencies for privacy risk...");
        const results = await scanPackages();
        panel.showPackageResults(results);
      } catch (err: any) {
        panel.showError(err.message);
      }
    })
  );

  /**
   * Command: manually install the pre-commit git hook into the current repo.
   * Useful if auto-install on activation was skipped (e.g. no .git at startup).
   */
  context.subscriptions.push(
    vscode.commands.registerCommand("privacyGuard.installHook", () => {
      try {
        const root = getWorkspaceRoot();
        const result = installHook(root, runnerPath);
        if (result.installed) {
          vscode.window.showInformationMessage(`Privacy Guard: ${result.message}`);
        } else {
          vscode.window.showWarningMessage(`Privacy Guard: ${result.message}`);
        }
      } catch (err: any) {
        vscode.window.showErrorMessage(`Privacy Guard: ${err.message}`);
      }
    })
  );

  /**
   * Command: remove the pre-commit git hook from the current repo.
   * Only removes hooks that were originally installed by Privacy Guard.
   */
  context.subscriptions.push(
    vscode.commands.registerCommand("privacyGuard.uninstallHook", () => {
      try {
        const root = getWorkspaceRoot();
        uninstallHook(root);
        vscode.window.showInformationMessage("Privacy Guard: Pre-commit hook removed.");
      } catch (err: any) {
        vscode.window.showErrorMessage(`Privacy Guard: ${err.message}`);
      }
    })
  );
}

/** Called by VS Code when the extension is deactivated or VS Code closes. */
export function deactivate() {}
