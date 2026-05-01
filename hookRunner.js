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
  // API key examples
  "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "sk-invalidkey", "sk-abc123",
  "your-key-here", "your_api_key", "your-api-key", "INSERT_KEY", "INSERT_YOUR",
  "YOUR_KEY", "YOUR_API", "PLACEHOLDER", "EXAMPLE", "test-key", "fake-key",
  "dummy-key", "sample-key", "xxxx", "1234567890",
  // PII placeholders / reserved test values
  "@EXAMPLE.COM", "@EXAMPLE.ORG", "@TEST.COM", "@LOCALHOST", "USER@EXAMPLE",
  "FOO@BAR", "JOHN.DOE@", "JANE.DOE@",
  "555-0100", "555-0199", "555-1234", "(555)",
  "000-00-0000", "123-45-6789",
];

function isExampleValue(line) {
  const upper = line.toUpperCase();
  return EXAMPLE_ALLOWLIST.some(ex => upper.includes(ex.toUpperCase()));
}

// ── NLP rules ─────────────────────────────────────────────────────────────────

const NLP_RULES = [
  { id: "sk-key", pattern: /['"]?(sk-[a-zA-Z0-9\-_]{16,})['"]?/, severity: "HIGH",
    issue: "Hardcoded API key (OpenAI/Stripe/Anthropic pattern) found in source code.",
    fix: "Move to environment variable.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.2, category: "CREDENTIALS", redactable: true },
  { id: "aws-key", pattern: /\b(AKIA|AGPA|AIDA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b/, severity: "HIGH",
    issue: "Hardcoded AWS access key ID found in source code.",
    fix: "Use IAM roles or environment variables. Rotate the key immediately.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "private-key", pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "HIGH",
    issue: "Private key embedded in source code.",
    fix: "Remove immediately. Store in a secrets manager.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "credentials-in-url", pattern: /:\/\/[^:'"@\s]{1,64}:[^@'":\s]{1,64}@[a-zA-Z0-9.\-]+/, severity: "HIGH",
    issue: "Credentials embedded in a connection URL.",
    fix: "Use environment variables for credentials.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 2.5, category: "CREDENTIALS", redactable: true },
  { id: "github-token", pattern: /['"]?(ghp|gho|ghu|ghs|github_pat)_[a-zA-Z0-9]{20,}['"]?/, severity: "HIGH",
    issue: "Hardcoded GitHub token found in source code.",
    fix: "Revoke and use environment variables.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.5, category: "CREDENTIALS", redactable: true },
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

  // ── Ported from privacy-filter (patterns.js). See nlpScanner.ts for rationale
  // on severity adjustments and dropped rules. Keep these two files in sync.

  // PII (values)
  { id: "pii-email", pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/, severity: "MEDIUM",
    issue: "Hardcoded email address — may be PII.",
    fix: "Replace with a placeholder (user@example.com) or load from config.", regulation: "GDPR Article 5(1)(c)",
    checkEntropy: false, category: "PII", redactable: true },
  { id: "pii-phone-us", pattern: /(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/, severity: "MEDIUM",
    issue: "US-format phone number found in source code.",
    fix: "Remove or replace with reserved test number (e.g. 555-0100).", regulation: "GDPR Article 5(1)(c)",
    checkEntropy: false, category: "PII", redactable: true },
  { id: "pii-ssn", pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/, severity: "HIGH",
    issue: "Possible Social Security Number found in source.",
    fix: "Never hardcode SSNs. Use tokenized synthetic values.", regulation: "GDPR Article 9 / CCPA 1798.140",
    checkEntropy: false, category: "PII", redactable: true },
  { id: "pii-dob", pattern: /\b(dob|date.of.birth|birth.?date)\s*[:=]\s*["']?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/i, severity: "HIGH",
    issue: "Date-of-birth value assigned in source code.",
    fix: "Use anonymised synthetic test data.", regulation: "GDPR Article 9",
    checkEntropy: false, category: "PII", redactable: true },
  { id: "pii-passport", pattern: /\b(passport|national.?id|id.?number)\s*[:=]\s*["']?[A-Z0-9]{6,12}/i, severity: "HIGH",
    issue: "Passport or national ID number assigned in source.",
    fix: "Identity document numbers must never appear in source.", regulation: "GDPR Article 9",
    checkEntropy: false, category: "PII", redactable: true },
  { id: "pii-gps", pattern: /[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)/, severity: "LOW",
    issue: "GPS coordinates appear in source.",
    fix: "Move to config or env if these represent a real address.", regulation: "GDPR Article 5(1)(c)",
    checkEntropy: false, category: "PII", redactable: false },
  { id: "pii-address", pattern: /\b\d{1,5}\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)*\s+(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Pkwy|Hwy)\b/, severity: "MEDIUM",
    issue: "Street-address-shaped string found in source.",
    fix: "Replace street addresses with synthetic test data.", regulation: "GDPR Article 5(1)(c)",
    checkEntropy: false, category: "PII", redactable: true },

  // Credentials (additions)
  { id: "cred-generic-secret", pattern: /\b(password|passwd|secret|api_?key|auth_?token|access_?token|client_?secret)\s*[:=]\s*["'][^\s"']{4,}/i, severity: "HIGH",
    issue: "Generic secret or password assigned to a literal string.",
    fix: "Move to environment variables or a secrets manager.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 2.8, category: "CREDENTIALS", redactable: true },
  { id: "cred-azure", pattern: /[?&]sig=[A-Za-z0-9%+/=]{20,}|Ocp-Apim-Subscription-Key:\s*[A-Za-z0-9]{32}/, severity: "HIGH",
    issue: "Azure SAS or subscription key found in source.",
    fix: "Rotate via Azure portal and use Managed Identity or Key Vault.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "cred-aws-secret", pattern: /aws_?secret_?access_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/i, severity: "HIGH",
    issue: "AWS secret access key assigned in source.",
    fix: "Revoke immediately in IAM and rotate.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.5, category: "CREDENTIALS", redactable: true },
  { id: "cred-gcp", pattern: /AIza[A-Za-z0-9\-_]{35}/, severity: "HIGH",
    issue: "Google Cloud / Firebase API key found in source.",
    fix: "Restrict the key in GCP console and move to Secret Manager.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "cred-jwt", pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*/, severity: "HIGH",
    issue: "Hardcoded JWT token found in source.",
    fix: "JWTs are revocable credentials — never hardcode them.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "cred-ssh-key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: "HIGH",
    issue: "SSH private key block found in source.",
    fix: "SSH private keys belong in ~/.ssh, not in source.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "CREDENTIALS", redactable: true },
  { id: "cred-bearer", pattern: /\bAuthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\-_.~+/=]{20,}/i, severity: "HIGH",
    issue: "Bearer token hardcoded in source.",
    fix: "Inject Authorization headers at runtime from env.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.0, category: "CREDENTIALS", redactable: true },
  { id: "cred-encryption-key", pattern: /\b(encryption_?key|aes_?key|secret_?key|iv|initialization_?vector)\s*[:=]\s*["'][A-Fa-f0-9]{16,}/i, severity: "HIGH",
    issue: "Encryption key or IV assigned to a literal value.",
    fix: "Encryption keys must be managed by KMS/HSM.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.5, category: "CREDENTIALS", redactable: true },

  // Network
  { id: "net-private-ip", pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/, severity: "MEDIUM",
    issue: "RFC 1918 private IP address hardcoded — exposes internal topology.",
    fix: "Use hostnames or environment configuration.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "NETWORK", redactable: true },
  { id: "net-localhost-port", pattern: /\b(127\.0\.0\.1|localhost):\d{4,5}\b/, severity: "LOW",
    issue: "localhost / 127.0.0.1 with port — fine in dev, risky in prod builds.",
    fix: "Move dev URLs into config.", regulation: null,
    checkEntropy: false, category: "NETWORK", redactable: false },
  { id: "net-internal-url", pattern: /https?:\/\/(internal|intra|corp|dev|staging|admin|vpn|private)\.[a-zA-Z0-9.\-]+/i, severity: "MEDIUM",
    issue: "Internal/non-public hostname found in source — reveals infrastructure.",
    fix: "Move internal URLs to environment configuration.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "NETWORK", redactable: true },
  { id: "net-webhook-url", pattern: /https?:\/\/[^\s"']+\/webhook\/[A-Za-z0-9\-_]{10,}/i, severity: "MEDIUM",
    issue: "Webhook URL with token in path — token is an effective credential.",
    fix: "Move webhook tokens to environment variables.", regulation: "GDPR Article 32",
    checkEntropy: true, minEntropy: 3.0, category: "NETWORK", redactable: true },

  // Business / IP
  { id: "biz-todo-sensitive", skipOnDocs: true, pattern: /\b(TODO|FIXME|HACK|XXX)\b.*\b(password|secret|key|credential|ssn|credit.?card|internal|confidential)/i, severity: "MEDIUM",
    issue: "TODO/FIXME comment references sensitive material.",
    fix: "Resolve before sharing the file.", regulation: null,
    checkEntropy: false, category: "BUSINESS", redactable: false },
  { id: "biz-commented-cred", skipOnDocs: true, pattern: /\/\/.*\b(password|api.?key|secret|token)\s*[:=]\s*["']?\S+/i, severity: "HIGH",
    issue: "Commented-out credential or key — still a leak.",
    fix: "Delete the line entirely.", regulation: "GDPR Article 32",
    checkEntropy: false, category: "BUSINESS", redactable: true },
  { id: "biz-contract-number", pattern: /\b(contract|purchase.?order|PO|invoice)\b\s*#?\s*[A-Z0-9\-]{5,}/i, severity: "MEDIUM",
    issue: "Contract / PO / invoice number found in source.",
    fix: "Business document IDs are confidential.", regulation: null,
    checkEntropy: false, category: "BUSINESS", redactable: true },
  { id: "ip-algo-comment", pattern: /\/\/\s*(proprietary|trade.?secret|confidential|do not (share|distribute|copy))/i, severity: "MEDIUM",
    issue: "Comment marks code as proprietary/confidential.",
    fix: "Do not send to third-party LLMs without legal review.", regulation: null,
    checkEntropy: false, category: "IP", redactable: false },
  { id: "ip-license-key", pattern: /\b(license.?key|serial.?key|activation.?code)\s*[:=]\s*["']?[A-Z0-9\-]{10,}/i, severity: "HIGH",
    issue: "License or serial key assigned in source.",
    fix: "License keys are transferable credentials.", regulation: null,
    checkEntropy: true, minEntropy: 2.8, category: "IP", redactable: true },

  // PHI
  { id: "phi-mrn", pattern: /\b(mrn|medical.?record.?number|patient.?id)\s*[:=]\s*["']?\d{5,}/i, severity: "HIGH",
    issue: "Medical record number assigned in source — HIPAA-regulated PHI.",
    fix: "Use anonymised synthetic data in tests.", regulation: "HIPAA 45 CFR 164.514",
    checkEntropy: false, category: "PHI", redactable: true },
  { id: "phi-diagnosis", pattern: /\b(diagnosis|icd.?10|icd.?9|condition)\s*[:=]\s*["'][A-Z]\d{2,}/i, severity: "HIGH",
    issue: "ICD diagnosis code assigned in source — may constitute PHI.",
    fix: "Remove or anonymise.", regulation: "HIPAA 45 CFR 164.514",
    checkEntropy: false, category: "PHI", redactable: true },
  { id: "phi-npi", pattern: /\bNPI\s*[:=]\s*["']?\d{10}\b/i, severity: "HIGH",
    issue: "National Provider Identifier (NPI) assigned in source.",
    fix: "Use synthetic NPI values in tests.", regulation: "HIPAA 45 CFR 164.514",
    checkEntropy: false, category: "PHI", redactable: true },
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

// ── Outbound prompt redaction ─────────────────────────────────────────────────
//
// Mirrors redactSensitive() in src/nlpScanner.ts — keep the two in sync.
// Scrubs sensitive values from the diff before sending it to a third-party LLM.
// Mode is controlled by the PRIVACY_GUARD_OUTBOUND_FILTER env var (redact|block|warn|off);
// defaults to "redact". The hook can't read VS Code settings so it uses env vars.

function isSafeEnvRef(line) {
  return /process\.env\.|os\.getenv\(|os\.environ|ENV\[|getenv\(|config\.|secrets\.|vault\./.test(line);
}

function redactSensitive(text) {
  if (!text) return { redacted: text, findings: [], hasHigh: false };

  const findings = [];
  const lines = text.split("\n");

  for (const rule of NLP_RULES) {
    if (!rule.redactable) continue;
    const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g";
    const globalPattern = new RegExp(rule.pattern.source, flags);

    for (const line of lines) {
      if (isSafeEnvRef(line)) continue;
      if (isExampleValue(line)) continue;

      let m;
      globalPattern.lastIndex = 0;
      while ((m = globalPattern.exec(line)) !== null) {
        const matched = m[0];
        if (rule.checkEntropy && rule.minEntropy !== undefined) {
          const candidate = matched.replace(/['"]/g, "").trim();
          if (candidate && shannonEntropy(candidate) < rule.minEntropy) {
            if (matched.length === 0) globalPattern.lastIndex++;
            continue;
          }
        }
        findings.push({ ruleId: rule.id, severity: rule.severity, matchedText: matched });
        if (matched.length === 0) globalPattern.lastIndex++;
      }
    }
  }

  // Specific rules first, then generic — see nlpScanner.ts for rationale.
  const GENERIC_RULES = new Set(["cred-generic-secret"]);
  const isGeneric = (id) => GENERIC_RULES.has(id);
  const sorted = [...findings].sort((a, b) => {
    const aGen = isGeneric(a.ruleId);
    const bGen = isGeneric(b.ruleId);
    if (aGen !== bGen) return aGen ? 1 : -1;
    return b.matchedText.length - a.matchedText.length;
  });

  let redacted = text;
  const seen = new Set();
  for (const f of sorted) {
    if (seen.has(f.matchedText)) continue;
    if (!redacted.includes(f.matchedText)) continue;
    redacted = redacted.split(f.matchedText).join(`[REDACTED:${f.ruleId}]`);
    seen.add(f.matchedText);
  }

  return { redacted, findings, hasHigh: findings.some(f => f.severity === "HIGH") };
}

function applyOutboundFilter(diff) {
  const mode = (process.env.PRIVACY_GUARD_OUTBOUND_FILTER || "redact").toLowerCase();
  if (mode === "off") return diff;

  const result = redactSensitive(diff);
  if (result.findings.length === 0) return diff;

  const ruleSummary = [...new Set(result.findings.map(f => f.ruleId))].join(", ");

  if (mode === "block" && result.hasHigh) {
    // Caller catches and falls back to NLP-only result — never block the commit on filter alone
    const err = new Error(
      `Privacy Guard refused to send prompt: ${result.findings.length} sensitive value(s) (${ruleSummary}). ` +
      `Set PRIVACY_GUARD_OUTBOUND_FILTER=redact to send a scrubbed version.`
    );
    err.outboundBlocked = true;
    throw err;
  }
  if (mode === "warn") {
    process.stderr.write(
      `Privacy Guard: outbound prompt contains ${result.findings.length} sensitive value(s) (${ruleSummary}) — sent unchanged (warn mode).\n`
    );
    return diff;
  }
  // redact (default), or block-with-no-HIGH
  process.stderr.write(
    `Privacy Guard: redacted ${result.findings.length} value(s) from outbound prompt (${ruleSummary}).\n`
  );
  return result.redacted;
}

function callLLM(provider, apiKey, openRouterModel, filePath, diff) {
  // Self-defense: scrub the diff before it leaves the machine.
  const safeDiff = applyOutboundFilter(diff);
  switch (provider) {
    case "openai":     return callOpenAI(apiKey, filePath, safeDiff);
    case "openrouter": return callOpenRouter(apiKey, openRouterModel, filePath, safeDiff);
    default:           return callAnthropic(apiKey, filePath, safeDiff);
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