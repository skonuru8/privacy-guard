#!/usr/bin/env node
/**
 * hookRunner.js
 *
 * Standalone Node script called by .git/hooks/pre-commit on every git commit.
 * Mirrors the 5-layer pipeline in diffScanner.ts:
 *
 *   1. Triage       — skip binaries, lockfiles, minified files
 *   2. Cache        — skip files unchanged since last scan
 *   3. NLP+Entropy  — catch secrets/PII locally, filter example values
 *   4. Path risk    — classify file risk by path name
 *   5. LLM decision — send to LLM only when it adds value
 *
 * Doc files (.md, .txt) → NLP + entropy only, never LLM
 * NLP HIGH              → block, no LLM
 * NLP MEDIUM            → LLM
 * NLP LOW + high-risk path → LLM
 * NLP LOW + low-risk path  → skip LLM
 *
 * Exits 1 (blocking commit) only on HIGH overall risk.
 * Always exits 0 on tool/network failure — never blocks unintentionally.
 */

"use strict";

const https   = require("https");
const { execSync } = require("child_process");
const fs      = require("fs");
const path    = require("path");
const os      = require("os");
const crypto  = require("crypto");

// ── Config ────────────────────────────────────────────────────────────────────

function getAIConfig() {
  if (process.env.PRIVACY_GUARD_API_KEY) {
    return {
      provider: process.env.PRIVACY_GUARD_PROVIDER || "anthropic",
      apiKey:   process.env.PRIVACY_GUARD_API_KEY,
      openRouterModel: process.env.PRIVACY_GUARD_OPENROUTER_MODEL || "mistralai/mistral-7b-instruct",
    };
  }

  const settingsPaths = [
    path.join(os.homedir(), ".config/Code/User/settings.json"),
    path.join(os.homedir(), "Library/Application Support/Code/User/settings.json"),
    path.join(os.homedir(), "AppData/Roaming/Code/User/settings.json"),
    path.join(os.homedir(), ".config/Code - Insiders/User/settings.json"),
  ];

  for (const p of settingsPaths) {
    if (fs.existsSync(p)) {
      try {
        const s = JSON.parse(fs.readFileSync(p, "utf8"));
        const provider = s["privacyGuard.provider"] || "anthropic";
        const keyMap = {
          anthropic:  s["privacyGuard.anthropicApiKey"]  || "",
          openai:     s["privacyGuard.openaiApiKey"]     || "",
          openrouter: s["privacyGuard.openrouterApiKey"] || "",
        };
        const apiKey = keyMap[provider] || "";
        if (apiKey) {
          return { provider, apiKey,
            openRouterModel: s["privacyGuard.openRouterModel"] || "mistralai/mistral-7b-instruct" };
        }
      } catch { /* malformed — try next */ }
    }
  }
  return { provider: null, apiKey: null, openRouterModel: null };
}

// ── Triage ────────────────────────────────────────────────────────────────────

const SKIP_EXTENSIONS = new Set([
  ".lock", ".sum", ".mod",
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
  ".svg", ".woff", ".woff2", ".ttf", ".eot",
  ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
  ".map", ".snap", ".bin", ".exe", ".dll",
]);
const SKIP_FILENAMES = [
  /^package-lock\.json$/, /^yarn\.lock$/, /^pnpm-lock\.yaml$/,
  /^composer\.lock$/, /^Gemfile\.lock$/, /^Cargo\.lock$/,
];

function shouldSkipFile(filePath) {
  const lower    = filePath.toLowerCase();
  const basename = lower.split("/").pop() || lower;
  for (const ext of SKIP_EXTENSIONS) { if (lower.endsWith(ext)) return true; }
  if (lower.includes(".min.")) return true;
  for (const pat of SKIP_FILENAMES) { if (pat.test(basename)) return true; }
  return false;
}

/** Returns true if file is documentation — never sent to LLM */
function isDocFile(filePath) {
  const lower = filePath.toLowerCase();
  return [".md", ".mdx", ".txt", ".rst", ".adoc", ".wiki"].some(ext => lower.endsWith(ext));
}

// ── Path risk ─────────────────────────────────────────────────────────────────

const HIGH_RISK_PATHS = [
  /auth/, /login/, /logout/, /signup/, /register/,
  /user/, /account/, /profile/, /identity/,
  /payment/, /billing/, /checkout/, /stripe/, /paypal/,
  /admin/, /session/, /token/, /oauth/, /jwt/, /credential/,
  /password/, /secret/, /key/, /cert/,
  /config/, /env/, /setting/, /\.env/,
  /privacy/, /consent/, /gdpr/,
];
const LOW_RISK_PATHS = [
  /util/, /helper/, /constant/, /format/, /transform/,
  /style/, /css/, /theme/, /icon/, /asset/, /image/,
  /test/, /spec/, /__test__/, /\.test\./, /\.spec\./,
  /fixture/, /mock/, /stub/, /fake/,
  /migration/, /seed/, /changelog/, /license/, /readme/,
  /\.stories\./, /storybook/, /node_modules/,
  /test.fixture/, /test-fixture/,   // test fixture dirs — examples, not real code
  /hookrunner/,                     // extension infra, not application code
  /webpack\.config/, /jest\.config/, /babel\.config/, /vite\.config/, /rollup\.config/,
  /nlpscanner/, /diffscanner/, /filecache/, /aiclient/, /hookinstaller/, // extension source
];

function getPathRisk(filePath) {
  const lower = filePath.toLowerCase();
  if (HIGH_RISK_PATHS.some(p => p.test(lower))) return "HIGH";
  if (LOW_RISK_PATHS.some(p => p.test(lower)))  return "LOW";
  return "MEDIUM";
}

function shouldSendToLLM(filePath, nlpResult) {
  if (isDocFile(filePath))                return false; // never
  if (nlpResult.overall_risk === "HIGH")  return false; // already blocking
  if (nlpResult.overall_risk === "MEDIUM") return true; // confirm/escalate
  const risk = getPathRisk(filePath);
  if (risk === "HIGH") return true;
  if (risk === "LOW")  return false;
  return true; // MEDIUM path — safe default
}

// ── Cache ─────────────────────────────────────────────────────────────────────

const CACHE_FILE = path.join(process.cwd(), ".git", "privacy-guard-cache.json");

function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const p = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8"));
      if (p.version === 1) return p;
    }
  } catch { /* ignore */ }
  return { version: 1, entries: {} };
}

function saveCache(store) {
  try { fs.writeFileSync(CACHE_FILE, JSON.stringify(store, null, 2)); } catch { /* ignore */ }
}

function hashDiff(diff) {
  return crypto.createHash("sha256").update(diff).digest("hex");
}

function getCached(hash) {
  return loadCache().entries[hash] || null;
}

function setCached(hash, result) {
  if (result.overall_risk === "LOW") return;
  const store = loadCache();
  store.entries[hash] = result;
  saveCache(store);
}

// ── Entropy ───────────────────────────────────────────────────────────────────

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((h, count) => {
    const p = count / str.length;
    return h - p * Math.log2(p);
  }, 0);
}

const EXAMPLE_ALLOWLIST = [
  "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "sk-invalidkey", "sk-abc123",
  "your-key-here", "your_api_key", "your-api-key", "INSERT_KEY", "INSERT_YOUR",
  "YOUR_KEY", "YOUR_API", "PLACEHOLDER", "EXAMPLE", "test-key", "fake-key",
  "dummy-key", "sample-key", "xxxx", "1234567890",
];

function isExampleValue(line) {
  const upper = line.toUpperCase();
  return EXAMPLE_ALLOWLIST.some(ex => upper.includes(ex.toUpperCase()));
}

// ── NLP rules ─────────────────────────────────────────────────────────────────

const NLP_RULES = [
  { id: "sk-key", pattern: /['"]?(sk-[a-zA-Z0-9\-_]{16,})['"]?/, severity: "HIGH",
    issue: "Hardcoded API key (OpenAI/Stripe pattern) found in source code.",
    fix: "Move to environment variable.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.2 },
  { id: "aws-key", pattern: /AKIA[0-9A-Z]{16}/, severity: "HIGH",
    issue: "Hardcoded AWS Access Key ID found in source code.",
    fix: "Use IAM roles or environment variables. Rotate the key immediately.", regulation: "GDPR Article 32",
    checkEntropy: false },
  { id: "private-key", pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "HIGH",
    issue: "Private key embedded in source code.",
    fix: "Remove immediately. Store in a secrets manager.", regulation: "GDPR Article 32",
    checkEntropy: false },
  { id: "credentials-in-url", pattern: /:\/\/[^:'"@\s]{1,64}:[^@'":\s]{1,64}@[a-zA-Z0-9.\-]+/, severity: "HIGH",
    issue: "Credentials embedded in a connection URL.",
    fix: "Use environment variables for credentials.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 2.5 },
  { id: "github-token", pattern: /['"]?(ghp|gho|ghu|ghs|github_pat)_[a-zA-Z0-9]{20,}['"]?/, severity: "HIGH",
    issue: "Hardcoded GitHub token found in source code.",
    fix: "Revoke and use environment variables.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.5 },
  { id: "pii-in-log-field", skipOnDocs: true, pattern: /console\.(log|warn|error|info|debug)\s*\([^)]*\b(email|password|passwd|token|secret|ssn|dob|phone|credit.?card|cvv)\b/i, severity: "HIGH",
    issue: "Sensitive field logged to console.",
    fix: "Remove or redact the sensitive field before logging.", regulation: "GDPR Article 5(1)(f)",
    checkEntropy: false },
  { id: "pii-in-log-user-field", skipOnDocs: true, pattern: /console\.(log|warn|error|info|debug)\s*\([^)]*\buser\.(email|password|phone|address|ssn|dob|creditCard)\b/i, severity: "HIGH",
    issue: "User PII field logged directly to console.",
    fix: "Remove or replace with a non-identifying value such as user.id.", regulation: "GDPR Article 5(1)(f)",
    checkEntropy: false },
  { id: "pii-in-log-template", skipOnDocs: true, pattern: /console\.(log|warn|error|info|debug)\s*\(`[^`]*\$\{[^}]*(email|password|phone|ssn|token)[^}]*\}/i, severity: "HIGH",
    issue: "PII field interpolated in a template literal passed to console.log.",
    fix: "Remove or redact the sensitive field before logging.", regulation: "GDPR Article 5(1)(f)",
    checkEntropy: false },
  { id: "password-unhashed", skipOnDocs: true, pattern: /password\s*:\s*(?:req|request|ctx|context)[\.\[]['"]?(?:body|params|query)[\.\[]['"]?(?:password|passwd)/i, severity: "HIGH",
    issue: "Raw password from request stored directly — not hashed.",
    fix: "Hash with bcrypt or argon2 before storing: await bcrypt.hash(password, 12)", regulation: "GDPR Article 32",
    checkEntropy: false },
  { id: "geolocation-no-consent", skipOnDocs: true, pattern: /navigator\.geolocation\.(getCurrentPosition|watchPosition)/, severity: "MEDIUM",
    issue: "Geolocation accessed — no visible consent check in this diff.",
    fix: "Request user consent before accessing location.", regulation: "GDPR Article 7",
    checkEntropy: false },
  { id: "http-fetch", skipOnDocs: true, pattern: /fetch\s*\(\s*['"`]http:\/\//i, severity: "MEDIUM",
    issue: "Data sent over unencrypted HTTP.",
    fix: "Change http:// to https://.", regulation: "GDPR Article 32",
    checkEntropy: false },
  { id: "http-axios", skipOnDocs: true, pattern: /axios\.(get|post|put|patch|delete)\s*\(\s*['"`]http:\/\//i, severity: "MEDIUM",
    issue: "Axios request sent over unencrypted HTTP.",
    fix: "Change http:// to https://.", regulation: "GDPR Article 32",
    checkEntropy: false },
  { id: "google-analytics", skipOnDocs: true, pattern: /analytics\.google\.com|gtag\s*\(|ga\s*\(\s*['"]send['"]/, severity: "MEDIUM",
    issue: "Google Analytics call detected — sends user data to a third party.",
    fix: "Ensure consent gate exists. Consider Plausible as a privacy-preserving alternative.", regulation: "GDPR Article 6",
    checkEntropy: false },
  { id: "mixpanel", skipOnDocs: true, pattern: /api\.mixpanel\.com|mixpanel\.(track|identify|people)/, severity: "MEDIUM",
    issue: "Mixpanel tracking call detected.",
    fix: "Ensure consent is obtained before tracking.", regulation: "GDPR Article 6",
    checkEntropy: false },
  { id: "amplitude", skipOnDocs: true, pattern: /api\.amplitude\.com|amplitude\.(getInstance|logEvent)/, severity: "MEDIUM",
    issue: "Amplitude analytics call detected.",
    fix: "Ensure consent is obtained before tracking.", regulation: "GDPR Article 6",
    checkEntropy: false },
  { id: "segment", skipOnDocs: true, pattern: /segment\.io|analytics\.identify\s*\(|analytics\.track\s*\(/, severity: "MEDIUM",
    issue: "Segment analytics call detected.",
    fix: "Ensure consent is obtained. Review Segment destinations.", regulation: "GDPR Article 6",
    checkEntropy: false },
];

function runNlp(filePath, diffContent, docFile = false) {
  const addedLines = diffContent.split("\n")
    .filter(l => l.startsWith("+") && !l.startsWith("+++"))
    .join("\n");

  const issues = [];
  const seenIds = new Set();

  for (const rule of NLP_RULES) {
    if (seenIds.has(rule.id)) continue;
    if (docFile && rule.skipOnDocs) continue;
    if (!rule.pattern.test(addedLines)) continue;

    const matchLine = addedLines.split("\n").find(l => rule.pattern.test(l)) || "";
    const lineText  = matchLine.replace(/^\+/, "").trim();

    if (isExampleValue(lineText)) continue;

    if (rule.checkEntropy && rule.minEntropy !== undefined) {
      const m = lineText.match(rule.pattern);
      const candidate = m ? (m[0] || "").replace(/['"]/g, "").trim() : "";
      if (candidate && shannonEntropy(candidate) < rule.minEntropy) continue;
    }

    seenIds.add(rule.id);
    issues.push({
      file: filePath,
      line_hint: lineText.slice(0, 120),
      severity: rule.severity,
      issue: rule.issue,
      fix: rule.fix,
      regulation: rule.regulation,
    });
  }

  const hasHigh   = issues.some(i => i.severity === "HIGH");
  const hasMedium = issues.some(i => i.severity === "MEDIUM");
  return {
    overall_risk: hasHigh ? "HIGH" : hasMedium ? "MEDIUM" : "LOW",
    summary: issues.length === 0 ? "No issues detected by local scan." : `${issues.length} issue(s) found by local scan.`,
    issues,
  };
}

// ── Git helpers ───────────────────────────────────────────────────────────────

function getStagedFileNames() {
  try {
    let out = execSync("git diff --cached --name-only --diff-filter=ACMRT", { encoding: "utf8" }).trim();
    if (!out) out = execSync("git diff HEAD --name-only --diff-filter=ACMRT", { encoding: "utf8" }).trim();
    return out ? out.split("\n").filter(Boolean) : [];
  } catch { return []; }
}

function getFileDiff(filePath) {
  try {
    let diff = execSync(`git diff --cached -- "${filePath}"`, { encoding: "utf8" });
    if (!diff.trim()) diff = execSync(`git diff HEAD -- "${filePath}"`, { encoding: "utf8" });
    return diff.length > 6000 ? diff.slice(0, 6000) + "\n...(truncated)" : diff;
  } catch { return ""; }
}

// ── LLM ───────────────────────────────────────────────────────────────────────

const SYSTEM = `You are a privacy engineer doing a pre-commit review.
Analyze the diff for: PII collection, sensitive data logging, third-party data sharing, missing consent, insecure transmission.
Respond ONLY with raw JSON:
{
  "overall_risk": "LOW"|"MEDIUM"|"HIGH",
  "summary": "one sentence",
  "issues": [{ "file": "filename", "line_hint": "snippet", "severity": "LOW"|"MEDIUM"|"HIGH", "issue": "problem", "fix": "fix", "regulation": "GDPR Article X or null" }]
}`;

function callAnthropic(apiKey, filePath, diff) {
  const body = JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1500, system: SYSTEM,
    messages: [{ role: "user", content: `Review this diff for file "${filePath}":\n\n${diff}` }] });
  return httpsPost({ hostname: "api.anthropic.com", path: "/v1/messages",
    headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01" } }, body,
    p => { if (p.error) throw new Error(p.error.message); return p.content[0].text; });
}

function callOpenAI(apiKey, filePath, diff) {
  const body = JSON.stringify({ model: "gpt-4o", max_tokens: 1500,
    messages: [{ role: "system", content: SYSTEM }, { role: "user", content: `Review this diff for file "${filePath}":\n\n${diff}` }] });
  return httpsPost({ hostname: "api.openai.com", path: "/v1/chat/completions",
    headers: { Authorization: `Bearer ${apiKey}` } }, body,
    p => { if (p.error) throw new Error(p.error.message); return p.choices[0].message.content; });
}

function callOpenRouter(apiKey, model, filePath, diff) {
  const body = JSON.stringify({ model, max_tokens: 1500,
    messages: [{ role: "system", content: SYSTEM }, { role: "user", content: `Review this diff for file "${filePath}":\n\n${diff}` }] });
  return httpsPost({ hostname: "openrouter.ai", path: "/api/v1/chat/completions",
    headers: { Authorization: `Bearer ${apiKey}`, "HTTP-Referer": "https://github.com/consenterra/privacy-guard", "X-Title": "Privacy Guard" } },
    body, p => { if (p.error) throw new Error(p.error.message); return p.choices[0].message.content; });
}

function callLLM(provider, apiKey, openRouterModel, filePath, diff) {
  switch (provider) {
    case "openai":     return callOpenAI(apiKey, filePath, diff);
    case "openrouter": return callOpenRouter(apiKey, openRouterModel, filePath, diff);
    default:           return callAnthropic(apiKey, filePath, diff);
  }
}

function httpsPost(opts, body, extractText) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: opts.hostname, path: opts.path, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), ...opts.headers } },
      res => {
        let data = "";
        res.on("data", c => (data += c));
        res.on("end", () => {
          try { resolve(extractText(JSON.parse(data))); }
          catch (e) { reject(new Error("Failed to parse API response: " + e.message)); }
        });
      });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

function aggregateResults(perFileResults) {
  const riskRank = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  let highest = "LOW";
  const allIssues = [];
  for (const { result } of perFileResults) {
    if (riskRank[result.overall_risk] > riskRank[highest]) highest = result.overall_risk;
    allIssues.push(...result.issues);
  }
  const highCount = allIssues.filter(i => i.severity === "HIGH").length;
  const medCount  = allIssues.filter(i => i.severity === "MEDIUM").length;
  return {
    overall_risk: highest,
    summary: allIssues.length === 0
      ? `No privacy issues found across ${perFileResults.length} scanned file(s).`
      : `Found ${allIssues.length} issue(s) — ${highCount} high, ${medCount} medium.`,
    issues: allIssues,
  };
}

// ── Print ─────────────────────────────────────────────────────────────────────

function printResults(result, stats) {
  const R = "\x1b[0m", B = "\x1b[1m", RED = "\x1b[31m",
        YEL = "\x1b[33m", GRN = "\x1b[32m", DIM = "\x1b[2m", CYN = "\x1b[36m";
  const riskColor = { LOW: GRN, MEDIUM: YEL, HIGH: RED };
  console.log(`\n${B}Privacy Guard Pre-Commit Check${R}`);
  console.log("─".repeat(40));
  console.log(`${B}Risk:${R} ${riskColor[result.overall_risk]}${result.overall_risk}${R}`);
  console.log(`${DIM}${result.summary}${R}`);
  if (stats) console.log(`${DIM}Files: ${stats.filesScanned} | LLM calls: ${stats.llmCalls} | Cache hits: ${stats.cacheHits}${R}\n`);
  else console.log();
  if (!result.issues || result.issues.length === 0) {
    console.log(`${GRN}No privacy issues found. Safe to commit.${R}\n`);
    return;
  }
  result.issues.forEach((issue, i) => {
    const c = riskColor[issue.severity];
    console.log(`${B}Issue ${i + 1}${R} — ${CYN}${issue.file}${R} [${c}${issue.severity}${R}]`);
    console.log(`  ${RED}Problem:${R} ${issue.issue}`);
    console.log(`  ${GRN}Fix:${R}     ${issue.fix}`);
    if (issue.regulation) console.log(`  ${DIM}${issue.regulation}${R}`);
    console.log();
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const { provider, apiKey, openRouterModel } = getAIConfig();
  if (!apiKey) {
    console.warn("\nPrivacy Guard: No API key found. Skipping check.\n");
    process.exit(0);
  }

  const allFiles  = getStagedFileNames();
  const scannable = allFiles.filter(f => !shouldSkipFile(f));

  if (scannable.length === 0) {
    console.log("\nPrivacy Guard: No scannable files. Safe.\n");
    process.exit(0);
  }

  process.stdout.write(`\nPrivacy Guard [${provider}]: Scanning ${scannable.length} file(s)...`);

  const perFileResults = [];
  let llmCalls  = 0;
  let cacheHits = 0;

  for (const filePath of scannable) {
    const diff = getFileDiff(filePath);
    if (!diff.trim()) continue;

    const hash = hashDiff(diff);

    // Cache
    const cached = getCached(hash);
    if (cached) {
      cacheHits++;
      perFileResults.push({ file: filePath, result: cached });
      continue;
    }

    // NLP + entropy (doc files only run secret rules)
    const nlpResult = runNlp(filePath, diff, isDocFile(filePath));

    // LLM decision
    if (!shouldSendToLLM(filePath, nlpResult)) {
      setCached(hash, nlpResult);
      perFileResults.push({ file: filePath, result: nlpResult });
      continue;
    }

    // LLM call
    try {
      const raw = await callLLM(provider, apiKey, openRouterModel, filePath, diff);
      const llmResult = JSON.parse(raw.replace(/```json|```/g, "").trim());
      llmCalls++;

      const seenIssues = new Set(nlpResult.issues.map(i => i.issue));
      const newLlmIssues = llmResult.issues.filter(i => !seenIssues.has(i.issue));

      const merged = {
        ...llmResult,
        issues: [...nlpResult.issues, ...newLlmIssues],
      };
      const hasHigh   = merged.issues.some(i => i.severity === "HIGH");
      const hasMedium = merged.issues.some(i => i.severity === "MEDIUM");
      merged.overall_risk = hasHigh ? "HIGH" : hasMedium ? "MEDIUM" : "LOW";

      setCached(hash, merged);
      perFileResults.push({ file: filePath, result: merged });
    } catch {
      perFileResults.push({ file: filePath, result: nlpResult });
    }
  }

  process.stdout.write(" done\n");

  const final = aggregateResults(perFileResults);
  printResults(final, { filesScanned: scannable.length, llmCalls, cacheHits });
  process.exit(final.overall_risk === "HIGH" ? 1 : 0);
}

main().catch(err => {
  console.warn(`\nPrivacy Guard check failed: ${err.message}\nSkipping — commit will proceed.\n`);
  process.exit(0);
});