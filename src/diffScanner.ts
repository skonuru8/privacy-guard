import * as vscode from "vscode";
import * as cp from "child_process";
import { callAI, getAIConfig } from "./aiClient";

/**
 * System prompt that instructs the AI to behave as a privacy engineer
 * and return a strictly structured JSON response for diff analysis.
 */
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

/** A single privacy issue found within a diff hunk. */
export interface DiffIssue {
  file: string;
  line_hint: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  issue: string;
  fix: string;
  regulation: string | null;
}

/** The full result returned after analyzing a git diff. */
export interface DiffResult {
  overall_risk: "LOW" | "MEDIUM" | "HIGH";
  summary: string;
  issues: DiffIssue[];
}

/**
 * Runs a git command in the given working directory and returns stdout.
 * Rejects with the stderr message if the command fails.
 *
 * @param args - Arguments to pass after `git` (e.g. "diff --cached")
 * @param cwd  - Absolute path to the repository root
 */
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

/**
 * Gets the staged diff from the current workspace.
 * Falls back to `git diff HEAD` if nothing is staged yet.
 * Trims the diff to 8000 characters to stay within model token limits.
 *
 * @param cwd - Absolute path to the repository root
 * @returns The trimmed diff string
 * @throws If no changes are found in the repo at all
 */
async function getStagedDiff(cwd: string): Promise<string> {
  let diff = await runGit("diff --cached", cwd);
  if (!diff.trim()) {
    diff = await runGit("diff HEAD", cwd);
  }
  if (!diff.trim()) {
    throw new Error("No changes found. Stage your changes with git add first.");
  }
  return diff.length > 8000 ? diff.slice(0, 8000) + "\n...(truncated)" : diff;
}

/**
 * Analyzes the current workspace's staged git changes for privacy issues.
 * Reads the AI provider and key from VS Code settings, fetches the diff,
 * sends it to the configured AI model, and returns structured results.
 *
 * @returns A DiffResult with overall risk level and a list of specific issues
 * @throws If the workspace has no git changes or the API call fails
 */
export async function checkStagedChanges(): Promise<DiffResult> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    throw new Error("No workspace open");
  }

  const { provider, apiKey } = getAIConfig();
  const cwd = workspaceFolders[0].uri.fsPath;
  const diff = await getStagedDiff(cwd);

  const response = await callAI(
    provider,
    apiKey,
    SYSTEM_PROMPT,
    `Review this git diff for privacy concerns:\n\n${diff}`
  );

  const cleaned = response.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned) as DiffResult;
}
