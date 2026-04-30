#!/usr/bin/env node
/**
 * Privacy Guard Hook Runner
 * Called by .git/hooks/pre-commit on every git commit.
 * Reads the API key from VS Code settings, checks the staged diff,
 * prints results to the terminal, and exits 1 if HIGH risk issues found.
 */

"use strict";

const https = require("https");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// ── Resolve API key ──────────────────────────────────────────────────────────
// Try env var first (CI/CD), then VS Code global settings file
function getApiKey() {
  if (process.env.PRIVACY_GUARD_API_KEY) {
    return process.env.PRIVACY_GUARD_API_KEY;
  }

  // VS Code stores settings in OS-specific paths
  const settingsPaths = [
    path.join(os.homedir(), ".config/Code/User/settings.json"),               // Linux
    path.join(os.homedir(), "Library/Application Support/Code/User/settings.json"), // macOS
    path.join(os.homedir(), "AppData/Roaming/Code/User/settings.json"),        // Windows
    path.join(os.homedir(), ".config/Code - Insiders/User/settings.json"),     // Insiders Linux
  ];

  for (const p of settingsPaths) {
    if (fs.existsSync(p)) {
      try {
        const settings = JSON.parse(fs.readFileSync(p, "utf8"));
        if (settings["privacyGuard.apiKey"]) {
          return settings["privacyGuard.apiKey"];
        }
      } catch {
        // malformed settings, try next
      }
    }
  }

  return null;
}

// ── Get staged diff ──────────────────────────────────────────────────────────
function getStagedDiff() {
  try {
    const diff = execSync("git diff --cached", { encoding: "utf8" });
    return diff.trim();
  } catch {
    return "";
  }
}

// ── Call Claude API ──────────────────────────────────────────────────────────
function callClaude(apiKey, diff) {
  const SYSTEM = `You are a privacy engineer doing a pre-commit review.
Analyze the diff for: PII collection, sensitive data logging, third-party data sharing, missing consent, insecure transmission.
Respond ONLY with raw JSON:
{
  "overall_risk": "LOW"|"MEDIUM"|"HIGH",
  "summary": "one sentence",
  "issues": [
    {
      "file": "filename",
      "severity": "LOW"|"MEDIUM"|"HIGH",
      "issue": "what the problem is",
      "fix": "concrete fix",
      "regulation": "GDPR Article X or null"
    }
  ]
}`;

  const body = JSON.stringify({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1500,
    system: SYSTEM,
    messages: [{ role: "user", content: `Review this diff:\n\n${diff}` }],
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.anthropic.com",
        path: "/v1/messages",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) return reject(new Error(parsed.error.message));
            const text = parsed.content[0].text.replace(/```json|```/g, "").trim();
            resolve(JSON.parse(text));
          } catch (e) {
            reject(new Error("Failed to parse API response"));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ── Pretty print results ─────────────────────────────────────────────────────
function printResults(result) {
  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const RED = "\x1b[31m";
  const YELLOW = "\x1b[33m";
  const GREEN = "\x1b[32m";
  const DIM = "\x1b[2m";
  const CYAN = "\x1b[36m";

  const riskColor = { LOW: GREEN, MEDIUM: YELLOW, HIGH: RED }[result.overall_risk];

  console.log(`\n${BOLD}🛡️  Privacy Guard Pre-Commit Check${RESET}`);
  console.log(`${"─".repeat(44)}`);
  console.log(`${BOLD}Overall Risk:${RESET} ${riskColor}${result.overall_risk}${RESET}`);
  console.log(`${DIM}${result.summary}${RESET}\n`);

  if (!result.issues || result.issues.length === 0) {
    console.log(`${GREEN}✅ No privacy issues found. Proceeding with commit.${RESET}\n`);
    return;
  }

  result.issues.forEach((issue, i) => {
    const color = { LOW: GREEN, MEDIUM: YELLOW, HIGH: RED }[issue.severity];
    console.log(`${BOLD}Issue ${i + 1}${RESET} — ${CYAN}${issue.file}${RESET} [${color}${issue.severity}${RESET}]`);
    console.log(`  ${RED}Problem:${RESET} ${issue.issue}`);
    console.log(`  ${GREEN}Fix:${RESET}     ${issue.fix}`);
    if (issue.regulation) {
      console.log(`  ${DIM}⚖️  ${issue.regulation}${RESET}`);
    }
    console.log();
  });
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const apiKey = getApiKey();

  if (!apiKey) {
    console.warn(
      "\n⚠️  Privacy Guard: No API key found.\n" +
      "   Set privacyGuard.apiKey in VS Code settings, or set PRIVACY_GUARD_API_KEY env var.\n" +
      "   Skipping privacy check.\n"
    );
    process.exit(0); // Don't block commit if not configured
  }

  const diff = getStagedDiff();
  if (!diff) {
    console.log("\n🛡️  Privacy Guard: No staged changes to check.\n");
    process.exit(0);
  }

  const trimmed = diff.length > 8000 ? diff.slice(0, 8000) + "\n...(truncated)" : diff;

  try {
    process.stdout.write("\n🛡️  Privacy Guard: Scanning staged changes...");
    const result = await callClaude(apiKey, trimmed);
    process.stdout.write(" done\n");
    printResults(result);

    // Block commit only on HIGH risk
    if (result.overall_risk === "HIGH") {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.warn(`\n⚠️  Privacy Guard check failed: ${err.message}\n   Skipping — commit will proceed.\n`);
    process.exit(0); // Never block on tool failure
  }
}

main();
