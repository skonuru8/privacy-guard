/**
 * nlpScanner.ts
 *
 * Local pre-filter that runs before any LLM call.
 * Uses regex rules + Shannon entropy scoring + path risk classification
 * to decide what needs the LLM and what can be resolved locally.
 *
 * Decision logic per file:
 *   isDocFile   → NLP + entropy only, NEVER send to LLM
 *   NLP HIGH    → block, no LLM needed
 *   NLP MEDIUM  → send to LLM to confirm or escalate
 *   NLP LOW + HIGH-risk path (auth, payment, user) → send to LLM
 *   NLP LOW + LOW-risk path (utils, tests, styles)  → skip LLM
 *   NLP LOW + MEDIUM-risk path (everything else)    → send to LLM
 */

import { DiffIssue, DiffResult } from "./diffScanner";

interface NlpRule {
  id: string;
  pattern: RegExp;
  issue: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  fix: string;
  regulation: string | null;
  /** If true, run Shannon entropy check on the matched string before flagging */
  checkEntropy?: boolean;
  /** Minimum entropy to flag — strings below this are likely examples/docs */
  minEntropy?: number;
  /** If true, only run this rule on doc files — skip on code files (and vice versa) */
  skipOnDocs?: boolean;
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

/**
 * Computes Shannon entropy of a string.
 * Real secrets (random chars) score > 3.5.
 * Readable example values ("sk-invalidkeyTHATWILLFAIL") score < 3.0.
 *
 * @param str - The string to score
 */
function shannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  return Object.values(freq).reduce((h, count) => {
    const p = count / str.length;
    return h - p * Math.log2(p);
  }, 0);
}

/**
 * Extracts the matched secret string from a line for entropy scoring.
 * Returns the longest token-like substring that isn't a common word.
 */
function extractSecretCandidate(line: string, pattern: RegExp): string {
  const m = line.match(pattern);
  if (!m) return "";
  // Use the full match — trim surrounding quotes
  return (m[0] || "").replace(/['"]/g, "").trim();
}

// ── Known example / placeholder values (allowlist) ───────────────────────────

/**
 * Known documentation example values that should never be flagged.
 * These appear in AWS docs, Stripe docs, README files etc.
 */
const EXAMPLE_ALLOWLIST = [
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI",
  "sk-invalidkey",
  "sk-abc123",
  "your-key-here",
  "your_api_key",
  "your-api-key",
  "INSERT_KEY",
  "INSERT_YOUR",
  "YOUR_KEY",
  "YOUR_API",
  "PLACEHOLDER",
  "EXAMPLE",
  "test-key",
  "fake-key",
  "dummy-key",
  "sample-key",
  "xxxx",
  "1234567890",
];

/**
 * Returns true if the matched line appears to be a documentation example
 * rather than a real credential.
 */
function isExampleValue(matchedLine: string): boolean {
  const upper = matchedLine.toUpperCase();
  return EXAMPLE_ALLOWLIST.some((ex) => upper.includes(ex.toUpperCase()));
}

// ── NLP rules ─────────────────────────────────────────────────────────────────

const RULES: NlpRule[] = [

  // ── Secrets ─────────────────────────────────────────────────────────────────
  {
    id: "sk-key",
    pattern: /['"]?(sk-[a-zA-Z0-9\-_]{16,})['"]?/,
    issue: "Hardcoded API key (OpenAI/Stripe pattern) found in source code.",
    severity: "HIGH",
    fix: "Move to environment variable and add to .gitignore.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.2,
  },
  {
    id: "aws-key",
    pattern: /AKIA[0-9A-Z]{16}/,
    issue: "Hardcoded AWS Access Key ID found in source code.",
    severity: "HIGH",
    fix: "Use IAM roles or environment variables. Rotate the exposed key immediately.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false, // AKIA prefix is always exact — no entropy check needed
  },
  {
    id: "private-key",
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    issue: "Private key embedded directly in source code.",
    severity: "HIGH",
    fix: "Remove immediately. Store in a secrets manager or environment variable.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
  },
  {
    id: "credentials-in-url",
    pattern: /:\/\/[^:'"@\s]{1,64}:[^@'":\s]{1,64}@[a-zA-Z0-9.\-]+/,
    issue: "Credentials embedded in a connection URL (user:password@host pattern).",
    severity: "HIGH",
    fix: "Use environment variables for database/service credentials.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 2.5,
  },
  {
    id: "github-token",
    pattern: /['"]?(ghp|gho|ghu|ghs|github_pat)_[a-zA-Z0-9]{20,}['"]?/,
    issue: "Hardcoded GitHub token found in source code.",
    severity: "HIGH",
    fix: "Revoke the token immediately and use environment variables.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.5,
  },

  // ── PII in logs ──────────────────────────────────────────────────────────────
  {
    id: "pii-in-log-field",
    skipOnDocs: true,
    pattern: /console\.(log|warn|error|info|debug)\s*\([^)]*\b(email|password|passwd|token|secret|ssn|dob|phone|credit.?card|cvv)\b/i,
    issue: "Sensitive field logged to console — PII or credentials may appear in log files.",
    severity: "HIGH",
    fix: "Remove the log or redact the sensitive field before logging.",
    regulation: "GDPR Article 5(1)(f) — integrity and confidentiality",
    checkEntropy: false,
  },
  {
    id: "pii-in-log-user-field",
    skipOnDocs: true,
    pattern: /console\.(log|warn|error|info|debug)\s*\([^)]*\buser\.(email|password|phone|address|ssn|dob|creditCard)\b/i,
    issue: "User PII field logged directly to console.",
    severity: "HIGH",
    fix: "Remove or replace with a non-identifying value such as user.id.",
    regulation: "GDPR Article 5(1)(f) — integrity and confidentiality",
    checkEntropy: false,
  },
  {
    id: "pii-in-log-template",
    skipOnDocs: true,
    pattern: /console\.(log|warn|error|info|debug)\s*\(`[^`]*\$\{[^}]*(email|password|phone|ssn|token)[^}]*\}/i,
    issue: "PII field interpolated in a template literal passed to console.log.",
    severity: "HIGH",
    fix: "Remove or redact the sensitive field before logging.",
    regulation: "GDPR Article 5(1)(f) — integrity and confidentiality",
    checkEntropy: false,
  },

  // ── Password storage ──────────────────────────────────────────────────────────
  {
    id: "password-unhashed",
    skipOnDocs: true,
    pattern: /password\s*:\s*(?:req|request|ctx|context)[\.\[]['"]?(?:body|params|query)[\.\[]['"]?(?:password|passwd)/i,
    issue: "Raw password from request stored directly — not hashed.",
    severity: "HIGH",
    fix: "Hash with bcrypt or argon2 before storing: await bcrypt.hash(password, 12)",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
  },

  // ── Geolocation without consent ───────────────────────────────────────────────
  {
    id: "geolocation-no-consent",
    skipOnDocs: true,
    pattern: /navigator\.geolocation\.(getCurrentPosition|watchPosition)/,
    issue: "Geolocation accessed — no visible consent check in this diff.",
    severity: "MEDIUM",
    fix: "Request user consent before accessing location. Add a consent gate before this call.",
    regulation: "GDPR Article 7 — conditions for consent",
    checkEntropy: false,
  },

  // ── Insecure transmission ─────────────────────────────────────────────────────
  {
    id: "http-fetch",
    skipOnDocs: true,
    pattern: /fetch\s*\(\s*['"`]http:\/\//i,
    issue: "Data sent over unencrypted HTTP — should use HTTPS.",
    severity: "MEDIUM",
    fix: "Change http:// to https:// to encrypt data in transit.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
  },
  {
    id: "http-axios",
    skipOnDocs: true,
    pattern: /axios\.(get|post|put|patch|delete)\s*\(\s*['"`]http:\/\//i,
    issue: "Axios request sent over unencrypted HTTP.",
    severity: "MEDIUM",
    fix: "Change http:// to https:// to encrypt data in transit.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
  },

  // ── Third-party trackers ──────────────────────────────────────────────────────
  {
    id: "google-analytics",
    skipOnDocs: true,
    pattern: /analytics\.google\.com|gtag\s*\(|ga\s*\(\s*['"]send['"]/,
    issue: "Google Analytics call detected — sends user data to a third party.",
    severity: "MEDIUM",
    fix: "Ensure a consent gate exists before this call. Consider Plausible as a privacy-preserving alternative.",
    regulation: "GDPR Article 6 — lawfulness of processing",
    checkEntropy: false,
  },
  {
    id: "mixpanel",
    skipOnDocs: true,
    pattern: /api\.mixpanel\.com|mixpanel\.(track|identify|people)/,
    issue: "Mixpanel tracking call detected — sends user data to a third party.",
    severity: "MEDIUM",
    fix: "Ensure consent is obtained before tracking. Document in your privacy policy.",
    regulation: "GDPR Article 6 — lawfulness of processing",
    checkEntropy: false,
  },
  {
    id: "amplitude",
    skipOnDocs: true,
    pattern: /api\.amplitude\.com|amplitude\.(getInstance|logEvent)/,
    issue: "Amplitude analytics call detected — sends user data to a third party.",
    severity: "MEDIUM",
    fix: "Ensure consent is obtained before tracking. Document in your privacy policy.",
    regulation: "GDPR Article 6 — lawfulness of processing",
    checkEntropy: false,
  },
  {
    id: "segment",
    skipOnDocs: true,
    pattern: /segment\.io|analytics\.identify\s*\(|analytics\.track\s*\(/,
    issue: "Segment analytics call detected — aggregates and forwards user data.",
    severity: "MEDIUM",
    fix: "Ensure consent is obtained before tracking. Review Segment destinations.",
    regulation: "GDPR Article 6 — lawfulness of processing",
    checkEntropy: false,
  },
];

// ── File type helpers ─────────────────────────────────────────────────────────

/**
 * Extensions that are always skipped — binaries, assets, lockfiles, generated files.
 */
const SKIP_EXTENSIONS = new Set([
  ".lock", ".sum", ".mod",
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
  ".svg", ".woff", ".woff2", ".ttf", ".eot",
  ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
  ".map", ".snap", ".bin", ".exe", ".dll",
]);

const SKIP_FILENAME_PATTERNS = [
  /^package-lock\.json$/, /^yarn\.lock$/, /^pnpm-lock\.yaml$/,
  /^composer\.lock$/, /^Gemfile\.lock$/, /^Cargo\.lock$/,
];

/**
 * Returns true if the file should be skipped entirely — no NLP, no LLM.
 *
 * @param filePath - Relative file path from git diff --name-only
 */
export function shouldSkipFile(filePath: string): boolean {
  const lower    = filePath.toLowerCase();
  const basename = lower.split("/").pop() || lower;

  for (const ext of SKIP_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  if (lower.includes(".min.")) return true;
  for (const pat of SKIP_FILENAME_PATTERNS) {
    if (pat.test(basename)) return true;
  }
  return false;
}

/**
 * Returns true if the file is a documentation/markup file.
 * Doc files get NLP + entropy only — never sent to LLM.
 * They can still contain real secrets (runbooks, wikis with pasted keys).
 *
 * @param filePath - Relative file path
 */
export function isDocFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return [".md", ".mdx", ".txt", ".rst", ".adoc", ".wiki"].some(
    (ext) => lower.endsWith(ext)
  );
}

// ── Path risk classification ──────────────────────────────────────────────────

/**
 * High-risk path patterns — files that commonly handle auth, PII, payments.
 * NLP-clean files matching these paths are still sent to LLM.
 */
const HIGH_RISK_PATH_PATTERNS = [
  /auth/, /login/, /logout/, /signup/, /register/,
  /user/, /account/, /profile/, /identity/,
  /payment/, /billing/, /checkout/, /stripe/, /paypal/,
  /admin/, /dashboard/,
  /session/, /token/, /oauth/, /jwt/, /credential/,
  /password/, /secret/, /key/, /cert/,
  /config/, /env/, /setting/, /\.env/,
  /privacy/, /consent/, /gdpr/,
];

/**
 * Low-risk path patterns — utilities, tests, styles, fixtures.
 * NLP-clean files matching these paths skip the LLM.
 */
const LOW_RISK_PATH_PATTERNS = [
  /util/, /helper/, /constant/, /format/, /transform/,
  /style/, /css/, /theme/, /icon/, /asset/, /image/,
  /test/, /spec/, /__test__/, /\.test\./, /\.spec\./,
  /fixture/, /mock/, /stub/, /fake/,
  /migration/, /seed/,
  /changelog/, /license/, /readme/, /contributing/,
  /\.stories\./, /storybook/,
  /node_modules/,
  /test.fixture/, /test-fixture/,
  /hookrunner/,
  /webpack\.config/, /jest\.config/, /babel\.config/, /vite\.config/,
  /test.fixture/, /test-fixture/,  // fixture dirs are examples, not real code
  /hookrunner/,                    // extension infra, not application code
  /webpack\.config/, /jest\.config/, /babel\.config/, /vite\.config/, /rollup\.config/,
];

/**
 * Classifies a file path as HIGH, MEDIUM, or LOW risk.
 * Used to decide whether NLP-clean code files need LLM analysis.
 *
 * @param filePath - Relative file path
 */
export function getPathRisk(filePath: string): "HIGH" | "MEDIUM" | "LOW" {
  const lower = filePath.toLowerCase();
  if (HIGH_RISK_PATH_PATTERNS.some((p) => p.test(lower))) return "HIGH";
  if (LOW_RISK_PATH_PATTERNS.some((p) => p.test(lower)))  return "LOW";
  return "MEDIUM";
}

/**
 * Decides whether a file should be sent to the LLM based on:
 * - Whether it's a doc file (never)
 * - NLP result severity
 * - Path risk classification
 *
 * @param filePath  - Relative file path
 * @param nlpResult - Result from runNlp()
 */
export function shouldSendToLLM(filePath: string, nlpResult: DiffResult): boolean {
  // Doc files — NLP + entropy only, never LLM
  if (isDocFile(filePath)) return false;

  // NLP already found HIGH — no point asking LLM, already blocking
  if (nlpResult.overall_risk === "HIGH") return false;

  // NLP found MEDIUM — LLM confirms or escalates to HIGH
  if (nlpResult.overall_risk === "MEDIUM") return true;

  // NLP clean — use path risk to decide
  const pathRisk = getPathRisk(filePath);
  if (pathRisk === "HIGH")   return true;  // auth/payment/user — subtle issues possible
  if (pathRisk === "LOW")    return false; // utils/tests/styles — trust NLP
  return true;                             // everything else — better safe
}

// ── Core NLP scanner ──────────────────────────────────────────────────────────

/**
 * Runs all NLP rules against a single file's diff.
 * Only tests added lines (+lines) — removes are not flagged.
 * Applies entropy scoring to secret patterns to filter out example values.
 *
 * @param filePath    - File path for issue attribution
 * @param diffContent - Raw diff text for this file
 */
export function runNlp(filePath: string, diffContent: string, docFile = false): DiffResult {
  const addedLines = diffContent
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .join("\n");

  const issues: DiffIssue[] = [];
  const seenIds = new Set<string>(); // one issue per rule per file

  for (const rule of RULES) {
    if (seenIds.has(rule.id)) continue;
    // Skip code-only rules when scanning doc files
    if (docFile && rule.skipOnDocs) continue;
    if (!rule.pattern.test(addedLines)) continue;

    // Find the specific matching line for the hint
    const matchingLine = addedLines
      .split("\n")
      .find((l) => rule.pattern.test(l)) || "";

    const lineText = matchingLine.replace(/^\+/, "").trim();

    // Skip known documentation example values
    if (isExampleValue(lineText)) continue;

    // Entropy check for secret patterns
    if (rule.checkEntropy && rule.minEntropy !== undefined) {
      const candidate = extractSecretCandidate(lineText, rule.pattern);
      if (candidate && shannonEntropy(candidate) < rule.minEntropy) {
        // Low entropy = likely a fake/example value — skip
        continue;
      }
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

  const hasHigh   = issues.some((i) => i.severity === "HIGH");
  const hasMedium = issues.some((i) => i.severity === "MEDIUM");

  return {
    overall_risk: hasHigh ? "HIGH" : hasMedium ? "MEDIUM" : "LOW",
    summary:
      issues.length === 0
        ? "No issues detected by local scan."
        : `${issues.length} issue(s) found by local pattern scan.`,
    issues,
  };
}

// ── Aggregator ────────────────────────────────────────────────────────────────

/**
 * Merges per-file results into a single DiffResult.
 * Overall risk = highest risk found across all files.
 *
 * @param results - Array of { file, result } pairs
 */
export function aggregateResults(
  results: Array<{ file: string; result: DiffResult }>
): DiffResult {
  const riskRank = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  let highest: "LOW" | "MEDIUM" | "HIGH" = "LOW";
  const allIssues: DiffIssue[] = [];

  for (const { result } of results) {
    if (riskRank[result.overall_risk] > riskRank[highest]) {
      highest = result.overall_risk;
    }
    allIssues.push(...result.issues);
  }

  const highCount = allIssues.filter((i) => i.severity === "HIGH").length;
  const medCount  = allIssues.filter((i) => i.severity === "MEDIUM").length;
  const fileCount = results.length;

  return {
    overall_risk: highest,
    summary:
      allIssues.length === 0
        ? `No privacy issues found across ${fileCount} scanned file(s).`
        : `Found ${allIssues.length} issue(s) across ${fileCount} file(s) — ${highCount} high, ${medCount} medium.`,
    issues: allIssues,
  };
}