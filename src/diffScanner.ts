/**
 * diffScanner.ts
 *
 * Analyzes staged git changes for privacy issues using a 5-layer pipeline:
 *
 *   1. Triage       — skip binaries, lockfiles, minified files (free)
 *   2. Cache        — skip files whose diff is unchanged since last scan (free)
 *   3. NLP+Entropy  — catch secrets/PII locally, filter example values via entropy (free)
 *   4. Path risk    — classify file as HIGH/MEDIUM/LOW risk by path name
 *   5. LLM decision — send to LLM only when it can add value:
 *                       .md/.txt doc files → NLP only, never LLM
 *                       NLP HIGH           → block, no LLM
 *                       NLP MEDIUM         → LLM confirms/escalates
 *                       NLP LOW + HIGH-risk path → LLM (auth, payment, user)
 *                       NLP LOW + LOW-risk path  → skip LLM (utils, tests)
 *                       NLP LOW + MEDIUM-risk    → LLM
 */

import * as vscode from "vscode";
import * as cp from "child_process";
import { callAI, getAIConfig } from "./aiClient";
import { shouldSkipFile, isDocFile, shouldSendToLLM, runNlp, aggregateResults } from "./nlpScanner";
import { hashDiff, getCached, setCached } from "./fileCache";

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

/** The full result returned after analyzing staged changes. */
export interface DiffResult {
  overall_risk: "LOW" | "MEDIUM" | "HIGH";
  summary: string;
  issues: DiffIssue[];
  filesScanned?: number;
  llmCallsMade?: number;
}

/**
 * Runs a git command in the given working directory and returns stdout.
 *
 * @param args - Arguments to pass after `git`
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
 * Returns list of staged file paths (added/modified/renamed/copied only).
 * Falls back to git diff HEAD if nothing is staged.
 *
 * @param cwd - Absolute path to the repository root
 * @throws If no changed files are found
 */
async function getStagedFileNames(cwd: string): Promise<string[]> {
  let output = await runGit("diff --cached --name-only --diff-filter=ACMRT", cwd);
  if (!output.trim()) {
    output = await runGit("diff HEAD --name-only --diff-filter=ACMRT", cwd);
  }
  if (!output.trim()) {
    throw new Error("No changes found. Stage your changes with git add first.");
  }
  return output.trim().split("\n").filter(Boolean);
}

/**
 * Returns the staged diff for a single file, truncated to 6000 chars.
 * Per-file limit ensures every file gets a complete focused analysis.
 *
 * @param filePath - Relative file path within the repository
 * @param cwd      - Absolute path to the repository root
 */
async function getFileDiff(filePath: string, cwd: string): Promise<string> {
  let diff = await runGit(`diff --cached -- "${filePath}"`, cwd);
  if (!diff.trim()) {
    diff = await runGit(`diff HEAD -- "${filePath}"`, cwd);
  }
  const MAX = 6000;
  return diff.length > MAX ? diff.slice(0, MAX) + "\n...(truncated)" : diff;
}

/**
 * Sends a single file's diff to the LLM for deep privacy analysis.
 * Returns LOW-risk empty result if diff is empty.
 *
 * @param filePath - File path for issue attribution
 * @param diff     - Raw diff content
 * @param provider - AI provider identifier
 * @param apiKey   - API key for the provider
 */
async function analyzeWithLLM(
  filePath: string,
  diff: string,
  provider: string,
  apiKey: string
): Promise<DiffResult> {
  if (!diff.trim()) {
    return { overall_risk: "LOW", summary: "Empty diff.", issues: [] };
  }

  const response = await callAI(
    provider as any,
    apiKey,
    SYSTEM_PROMPT,
    `Review this diff for file "${filePath}":\n\n${diff}`
  );

  const cleaned = response.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned) as DiffResult;
}

/**
 * Main entry point. Runs the full 5-layer pipeline per file,
 * then aggregates all results into a single DiffResult.
 *
 * @returns Aggregated DiffResult with overall risk, all issues, and scan stats
 * @throws If no workspace is open or no staged changes exist
 */
export async function checkStagedChanges(): Promise<DiffResult> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    throw new Error("No workspace open");
  }

  const cwd = workspaceFolders[0].uri.fsPath;
  const { provider, apiKey } = getAIConfig();

  const allFiles = await getStagedFileNames(cwd);

  // Layer 1: triage
  const scannableFiles = allFiles.filter((f) => !shouldSkipFile(f));
  if (scannableFiles.length === 0) {
    return {
      overall_risk: "LOW",
      summary: "All changed files are non-code assets (images, lockfiles, etc). Nothing to scan.",
      issues: [],
      filesScanned: 0,
      llmCallsMade: 0,
    };
  }

  const perFileResults: Array<{ file: string; result: DiffResult }> = [];
  let llmCallsMade = 0;

  for (const filePath of scannableFiles) {
    const diff = await getFileDiff(filePath, cwd);
    if (!diff.trim()) continue;

    // Layer 2: cache
    const diffHash = hashDiff(diff);
    const cached = getCached(cwd, diffHash);
    if (cached) {
      perFileResults.push({ file: filePath, result: cached });
      continue;
    }

    // Layer 3: NLP + entropy (doc files only run secret rules)
    const nlpResult = runNlp(filePath, diff, isDocFile(filePath));

    // Layer 4 + 5: decide whether LLM is needed
    if (!shouldSendToLLM(filePath, nlpResult)) {
      // NLP result is the final answer — no LLM call
      setCached(cwd, diffHash, nlpResult);
      perFileResults.push({ file: filePath, result: nlpResult });
      continue;
    }

    // LLM call — for MEDIUM NLP hits, high-risk paths, and ambiguous files
    try {
      const llmResult = await analyzeWithLLM(filePath, diff, provider, apiKey);
      llmCallsMade++;

      // Merge NLP and LLM issues — deduplicate by issue text
      const seenIssues = new Set(nlpResult.issues.map((i) => i.issue));
      const newLlmIssues = llmResult.issues.filter((i) => !seenIssues.has(i.issue));

      const merged: DiffResult = {
        ...llmResult,
        issues: [...nlpResult.issues, ...newLlmIssues],
      };
      const hasHigh   = merged.issues.some((i) => i.severity === "HIGH");
      const hasMedium = merged.issues.some((i) => i.severity === "MEDIUM");
      merged.overall_risk = hasHigh ? "HIGH" : hasMedium ? "MEDIUM" : "LOW";

      setCached(cwd, diffHash, merged);
      perFileResults.push({ file: filePath, result: merged });
    } catch {
      // LLM failed — use NLP result only, never block on tool failure
      perFileResults.push({ file: filePath, result: nlpResult });
    }
  }

  const aggregated = aggregateResults(perFileResults);
  return {
    ...aggregated,
    filesScanned: scannableFiles.length,
    llmCallsMade,
  };
}