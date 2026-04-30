import * as vscode from "vscode";
import * as cp from "child_process";
import { callClaude } from "./claude";

const SYSTEM_PROMPT = `You are a privacy engineer reviewing code changes before they are committed.

Analyze the diff for privacy concerns:
- PII collection (names, emails, phone numbers, location, IDs)
- Sensitive data being logged (passwords, tokens, health, financial data)
- New third-party API calls that may share user data
- Missing consent checks before collecting data
- Data stored without expiry or necessity
- Insecure transmission of personal data

Respond ONLY with raw JSON — no markdown, no explanation:
{
  "overall_risk": "LOW" | "MEDIUM" | "HIGH",
  "summary": "one sentence assessment",
  "issues": [
    {
      "file": "filename",
      "line_hint": "relevant code snippet",
      "severity": "LOW" | "MEDIUM" | "HIGH",
      "issue": "what the privacy problem is",
      "fix": "concrete suggestion to fix it",
      "regulation": "e.g. GDPR Article 5 / CCPA Section 1798.100 / null"
    }
  ]
}`;

export interface DiffIssue {
  file: string;
  line_hint: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  issue: string;
  fix: string;
  regulation: string | null;
}

export interface DiffResult {
  overall_risk: "LOW" | "MEDIUM" | "HIGH";
  summary: string;
  issues: DiffIssue[];
}

function runGit(args: string, cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    cp.exec(`git ${args}`, { cwd }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(stderr || err.message));
      } else {
        resolve(stdout);
      }
    });
  });
}

export async function checkStagedChanges(apiKey: string): Promise<DiffResult> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    throw new Error("No workspace open");
  }

  const cwd = workspaceFolders[0].uri.fsPath;

  // Try staged first, fall back to all uncommitted changes
  let diff = await runGit("diff --cached", cwd);
  if (!diff.trim()) {
    diff = await runGit("diff HEAD", cwd);
  }
  if (!diff.trim()) {
    throw new Error("No changes found. Stage your changes with git add first.");
  }

  // Trim to avoid token limits
  const trimmed =
    diff.length > 8000 ? diff.slice(0, 8000) + "\n...(truncated)" : diff;

  const response = await callClaude(
    apiKey,
    SYSTEM_PROMPT,
    `Review this git diff for privacy concerns:\n\n${trimmed}`
  );

  const cleaned = response.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned) as DiffResult;
}
