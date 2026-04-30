import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

// This script is written into .git/hooks/pre-commit and runs on every commit.
// It calls our Node runner (hookRunner.js) which does the actual privacy check.
const HOOK_SCRIPT = (runnerPath: string) => `#!/bin/sh
# Privacy Guard pre-commit hook
# Installed by the Privacy Guard VS Code extension

node "${runnerPath}" --hook
exit_code=$?

if [ $exit_code -ne 0 ]; then
  echo ""
  echo "❌ Privacy Guard blocked this commit. Fix the issues above or run:"
  echo "   git commit --no-verify   (to bypass)"
  echo ""
fi

exit $exit_code
`;

export function installHook(
  workspaceRoot: string,
  runnerPath: string
): { installed: boolean; message: string } {
  const hookDir = path.join(workspaceRoot, ".git", "hooks");
  const hookPath = path.join(hookDir, "pre-commit");

  if (!fs.existsSync(path.join(workspaceRoot, ".git"))) {
    return { installed: false, message: "No .git directory found — is this a git repo?" };
  }

  if (!fs.existsSync(hookDir)) {
    fs.mkdirSync(hookDir, { recursive: true });
  }

  // Don't overwrite a hook we didn't install
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf8");
    if (!existing.includes("Privacy Guard")) {
      return {
        installed: false,
        message: "A pre-commit hook already exists and was not installed by Privacy Guard. Edit it manually to call Privacy Guard.",
      };
    }
  }

  fs.writeFileSync(hookPath, HOOK_SCRIPT(runnerPath), { mode: 0o755 });
  return { installed: true, message: "Pre-commit hook installed successfully." };
}

export function isHookInstalled(workspaceRoot: string): boolean {
  const hookPath = path.join(workspaceRoot, ".git", "hooks", "pre-commit");
  if (!fs.existsSync(hookPath)) return false;
  return fs.readFileSync(hookPath, "utf8").includes("Privacy Guard");
}

export function uninstallHook(workspaceRoot: string): void {
  const hookPath = path.join(workspaceRoot, ".git", "hooks", "pre-commit");
  if (fs.existsSync(hookPath)) {
    fs.unlinkSync(hookPath);
  }
}
