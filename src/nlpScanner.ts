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

// Type-only import — avoids a runtime circular dependency now that
// aiClient.ts imports redactSensitive() from this file.
import type { DiffIssue, DiffResult } from "./diffScanner";

export interface NlpRule {
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
  /**
   * Loose category tag used by the outbound redactor to label tokens.
   * Optional — existing rules without one default to "GENERAL".
   */
  category?: "PII" | "CREDENTIALS" | "NETWORK" | "BUSINESS" | "IP" | "PHI" | "GENERAL";
  /**
   * If true, this rule is used by redactSensitive() to scrub sensitive values
   * from prompts before they leave the machine. Only mark VALUE-bearing rules
   * (e.g. an actual API key, an email address). Code-shape rules like
   * "console.log contains email field" should leave this off — there's nothing
   * to redact, the issue is the call itself.
   */
  redactable?: boolean;
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
  // API key examples
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
  // PII placeholders / reserved test values
  "@EXAMPLE.COM",
  "@EXAMPLE.ORG",
  "@TEST.COM",
  "@LOCALHOST",
  "USER@EXAMPLE",
  "FOO@BAR",
  "JOHN.DOE@",
  "JANE.DOE@",
  "555-0100",
  "555-0199",     // 555-0100..0199 is the IANA-reserved fake range
  "555-1234",
  "(555)",
  "000-00-0000",  // SSN placeholder
  "123-45-6789",  // common SSN example
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
    issue: "Hardcoded API key (OpenAI/Stripe/Anthropic pattern) found in source code.",
    severity: "HIGH",
    fix: "Move to environment variable and add to .gitignore.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.2,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "aws-key",
    // Widened from /AKIA[0-9A-Z]{16}/ — covers all AWS key prefix variants
    // (long-term keys, role keys, EC2 instance profile keys, etc.)
    pattern: /\b(AKIA|AGPA|AIDA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b/,
    issue: "Hardcoded AWS access key ID found in source code.",
    severity: "HIGH",
    fix: "Use IAM roles or environment variables. Rotate the exposed key immediately.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false, // AKIA-style prefixes are exact — no entropy check needed
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "private-key",
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    issue: "Private key embedded directly in source code.",
    severity: "HIGH",
    fix: "Remove immediately. Store in a secrets manager or environment variable.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "CREDENTIALS",
    redactable: true,
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
    category: "CREDENTIALS",
    redactable: true,
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
    category: "CREDENTIALS",
    redactable: true,
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

  // ─────────────────────────────────────────────────────────────────────────────
  // Rules below ported from the standalone privacy-filter module (patterns.js).
  // Adjustments from the original:
  //   - PII-EMAIL/PHONE downgraded HIGH → MEDIUM (HIGH would block every commit
  //     containing a test email; MEDIUM still flags but doesn't block).
  //   - PII-GPS downgraded MEDIUM → LOW (matches almost any lat/lng-shaped pair).
  //   - Three rules dropped as too noisy for an editor context:
  //       NET-PORT-HARDCODED  (matches 5432/3306/27017 anywhere — versions, math)
  //       BIZ-INTERNAL-CODENAME (matches every project: "name" in JSON)
  //       IP-COPYRIGHT (fires on every OSS file header)
  //   - All carry category + redactable flags so the outbound prompt filter
  //     can use the value-bearing ones to scrub LLM input.
  // ─────────────────────────────────────────────────────────────────────────────

  // ── PII (values) ────────────────────────────────────────────────────────────
  {
    id: "pii-email",
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
    issue: "Hardcoded email address — may be PII if it identifies a real person.",
    severity: "MEDIUM",
    fix: "Replace with a placeholder (user@example.com) or load from config/env.",
    regulation: "GDPR Article 5(1)(c) — data minimisation",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },
  {
    id: "pii-phone-us",
    pattern: /(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/,
    issue: "US-format phone number found in source code.",
    severity: "MEDIUM",
    fix: "Remove or replace with a reserved test number (e.g. 555-0100).",
    regulation: "GDPR Article 5(1)(c) — data minimisation",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },
  {
    id: "pii-ssn",
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/,
    issue: "Possible Social Security Number found in source code.",
    severity: "HIGH",
    fix: "Never hardcode SSNs. Use tokenized or masked synthetic values.",
    regulation: "GDPR Article 9 — special-category data / CCPA Section 1798.140",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },
  {
    id: "pii-dob",
    pattern: /\b(dob|date.of.birth|birth.?date)\s*[:=]\s*["']?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/i,
    issue: "Date-of-birth value assigned in source code.",
    severity: "HIGH",
    fix: "Avoid hardcoding DOB. Use anonymised synthetic test data.",
    regulation: "GDPR Article 9 — special-category data",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },
  {
    id: "pii-passport",
    pattern: /\b(passport|national.?id|id.?number)\s*[:=]\s*["']?[A-Z0-9]{6,12}/i,
    issue: "Passport or national ID number assigned in source code.",
    severity: "HIGH",
    fix: "Identity document numbers must never appear in source code.",
    regulation: "GDPR Article 9 — special-category data",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },
  {
    id: "pii-gps",
    // GPS coords pattern is naturally noisy — kept at LOW severity, informational only
    pattern: /[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)/,
    issue: "GPS coordinates appear in source — may reveal physical location.",
    severity: "LOW",
    fix: "Move to config or environment if these represent a real address.",
    regulation: "GDPR Article 5(1)(c) — data minimisation",
    checkEntropy: false,
    category: "PII",
    redactable: false, // too generic — would mangle legitimate numeric pairs in code
  },
  {
    id: "pii-address",
    pattern: /\b\d{1,5}\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)*\s+(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Pkwy|Hwy)\b/,
    issue: "Street-address-shaped string found in source code.",
    severity: "MEDIUM",
    fix: "Replace street addresses with synthetic test data.",
    regulation: "GDPR Article 5(1)(c) — data minimisation",
    checkEntropy: false,
    category: "PII",
    redactable: true,
  },

  // ── Credentials (additions beyond the existing secret rules) ────────────────
  {
    id: "cred-generic-secret",
    pattern: /\b(password|passwd|secret|api_?key|auth_?token|access_?token|client_?secret)\s*[:=]\s*["'][^\s"']{4,}/i,
    issue: "Generic secret or password assigned to a literal string.",
    severity: "HIGH",
    fix: "Move all secrets to environment variables or a secrets manager.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 2.8,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-azure",
    pattern: /[?&]sig=[A-Za-z0-9%+/=]{20,}|Ocp-Apim-Subscription-Key:\s*[A-Za-z0-9]{32}/,
    issue: "Azure SAS or subscription key found in source.",
    severity: "HIGH",
    fix: "Rotate via Azure portal and use Managed Identity or Key Vault.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-aws-secret",
    pattern: /aws_?secret_?access_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/i,
    issue: "AWS secret access key assigned in source.",
    severity: "HIGH",
    fix: "Revoke immediately in IAM and rotate. Never commit AWS secret keys.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.5,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-gcp",
    pattern: /AIza[A-Za-z0-9\-_]{35}/,
    issue: "Google Cloud / Firebase API key found in source.",
    severity: "HIGH",
    fix: "Restrict the key in GCP console and move to Secret Manager.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false, // AIza prefix is exact and length-fixed
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-jwt",
    pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*/,
    issue: "Hardcoded JWT token found in source.",
    severity: "HIGH",
    fix: "JWTs are revocable credentials — never hardcode them.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-ssh-key",
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    issue: "SSH private key block found in source.",
    severity: "HIGH",
    fix: "SSH private keys belong in ~/.ssh, never in source code.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-bearer",
    pattern: /\bAuthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\-_.~+/=]{20,}/i,
    issue: "Bearer token hardcoded in source.",
    severity: "HIGH",
    fix: "Inject Authorization headers at runtime from env, not from string literals.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.0,
    category: "CREDENTIALS",
    redactable: true,
  },
  {
    id: "cred-encryption-key",
    pattern: /\b(encryption_?key|aes_?key|secret_?key|iv|initialization_?vector)\s*[:=]\s*["'][A-Fa-f0-9]{16,}/i,
    issue: "Encryption key or IV assigned to a literal value.",
    severity: "HIGH",
    fix: "Encryption keys must be managed by a KMS/HSM, not embedded in code.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.5,
    category: "CREDENTIALS",
    redactable: true,
  },

  // ── Network (internal infrastructure exposure) ──────────────────────────────
  {
    id: "net-private-ip",
    pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
    issue: "RFC 1918 private IP address hardcoded — exposes internal network topology.",
    severity: "MEDIUM",
    fix: "Use hostnames or environment configuration instead of literal IPs.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "NETWORK",
    redactable: true,
  },
  {
    id: "net-localhost-port",
    pattern: /\b(127\.0\.0\.1|localhost):\d{4,5}\b/,
    issue: "localhost / 127.0.0.1 with a port — fine in dev, risky if shipped to prod.",
    severity: "LOW",
    fix: "Move dev URLs into config so they are absent from production builds.",
    regulation: null,
    checkEntropy: false,
    category: "NETWORK",
    redactable: false, // localhost URLs are usually fine to share in prompts
  },
  {
    id: "net-internal-url",
    pattern: /https?:\/\/(internal|intra|corp|dev|staging|admin|vpn|private)\.[a-zA-Z0-9.\-]+/i,
    issue: "Internal or non-public hostname found in source — reveals infrastructure.",
    severity: "MEDIUM",
    fix: "Move internal URLs to environment configuration.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "NETWORK",
    redactable: true,
  },
  {
    id: "net-webhook-url",
    pattern: /https?:\/\/[^\s"']+\/webhook\/[A-Za-z0-9\-_]{10,}/i,
    issue: "Webhook URL with a token in the path — the token is an effective credential.",
    severity: "MEDIUM",
    fix: "Move webhook tokens to environment variables.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: true,
    minEntropy: 3.0,
    category: "NETWORK",
    redactable: true,
  },

  // ── Business / IP ───────────────────────────────────────────────────────────
  {
    id: "biz-todo-sensitive",
    skipOnDocs: true,
    pattern: /\b(TODO|FIXME|HACK|XXX)\b.*\b(password|secret|key|credential|ssn|credit.?card|internal|confidential)/i,
    issue: "TODO/FIXME comment references sensitive material — unfinished security work.",
    severity: "MEDIUM",
    fix: "Resolve before sharing the file with reviewers or LLMs.",
    regulation: null,
    checkEntropy: false,
    category: "BUSINESS",
    redactable: false,
  },
  {
    id: "biz-commented-cred",
    skipOnDocs: true,
    pattern: /\/\/.*\b(password|api.?key|secret|token)\s*[:=]\s*["']?\S+/i,
    issue: "Commented-out credential or key — still a leak when the file is shared.",
    severity: "HIGH",
    fix: "Delete the line entirely — commenting it out is not enough.",
    regulation: "GDPR Article 32 — security of processing",
    checkEntropy: false,
    category: "BUSINESS",
    redactable: true,
  },
  {
    id: "biz-contract-number",
    // Trailing \b on the keyword group — original patterns.js anchored only the
    // start, which made the bare "PO" alternative match POSTGRES, REPORT, etc.
    pattern: /\b(contract|purchase.?order|PO|invoice)\b\s*#?\s*[A-Z0-9\-]{5,}/i,
    issue: "Contract / PO / invoice number found in source code.",
    severity: "MEDIUM",
    fix: "Business document IDs are confidential — remove from code context.",
    regulation: null,
    checkEntropy: false,
    category: "BUSINESS",
    redactable: true,
  },
  {
    id: "ip-algo-comment",
    pattern: /\/\/\s*(proprietary|trade.?secret|confidential|do not (share|distribute|copy))/i,
    issue: "Comment marks this code as proprietary or confidential.",
    severity: "MEDIUM",
    fix: "Code marked proprietary should not be sent to third-party LLMs without legal review.",
    regulation: null,
    checkEntropy: false,
    category: "IP",
    redactable: false, // the comment IS the signal — redacting it hides the warning
  },
  {
    id: "ip-license-key",
    pattern: /\b(license.?key|serial.?key|activation.?code)\s*[:=]\s*["']?[A-Z0-9\-]{10,}/i,
    issue: "License or serial key assigned in source.",
    severity: "HIGH",
    fix: "License keys are transferable credentials — remove from source.",
    regulation: null,
    checkEntropy: true,
    minEntropy: 2.8,
    category: "IP",
    redactable: true,
  },

  // ── PHI (HIPAA) ─────────────────────────────────────────────────────────────
  {
    id: "phi-mrn",
    pattern: /\b(mrn|medical.?record.?number|patient.?id)\s*[:=]\s*["']?\d{5,}/i,
    issue: "Medical record number assigned in source — HIPAA-regulated PHI.",
    severity: "HIGH",
    fix: "Never hardcode MRNs. Use anonymised synthetic data in tests.",
    regulation: "HIPAA 45 CFR 164.514 — de-identification of PHI",
    checkEntropy: false,
    category: "PHI",
    redactable: true,
  },
  {
    id: "phi-diagnosis",
    pattern: /\b(diagnosis|icd.?10|icd.?9|condition)\s*[:=]\s*["'][A-Z]\d{2,}/i,
    issue: "ICD diagnosis code assigned in source — may constitute PHI.",
    severity: "HIGH",
    fix: "Remove or anonymise. Diagnosis codes attached to identifiable records are PHI.",
    regulation: "HIPAA 45 CFR 164.514 — de-identification of PHI",
    checkEntropy: false,
    category: "PHI",
    redactable: true,
  },
  {
    id: "phi-npi",
    pattern: /\bNPI\s*[:=]\s*["']?\d{10}\b/i,
    issue: "National Provider Identifier (NPI) assigned in source.",
    severity: "HIGH",
    fix: "Use synthetic NPI values in tests, never real provider identifiers.",
    regulation: "HIPAA 45 CFR 164.514 — de-identification of PHI",
    checkEntropy: false,
    category: "PHI",
    redactable: true,
  },
];

// Re-export for use by other modules (notably aiClient.ts → outbound redactor).
export { RULES };

// ── Outbound prompt redaction ─────────────────────────────────────────────────
//
// Used by aiClient.ts (and hookRunner.js's mirror) to scrub sensitive values
// from prompts BEFORE they are sent to a third-party LLM. The scanner above
// detects issues in code; the redactor below prevents the detection process
// itself from leaking those same values to the analyzer.
//
// Only rules with `redactable: true` participate. Code-shape rules (e.g.
// "console.log contains an email field") are excluded — there's nothing to
// redact in the value sense, the issue is the call site.

/**
 * Returns true if the line is referencing a secret via a safe access pattern
 * (env var, config object, secrets manager). These should never be redacted —
 * `process.env.OPENAI_API_KEY` is not a leaked key, it's the correct fix.
 */
function isSafeEnvRef(line: string): boolean {
  return /process\.env\.|os\.getenv\(|os\.environ|ENV\[|getenv\(|config\.|secrets\.|vault\./.test(
    line
  );
}

/** A single match found by the outbound redactor. */
export interface RedactionFinding {
  ruleId: string;
  category: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  matchedText: string;
}

export interface RedactionResult {
  /** Original text with sensitive matches replaced by [REDACTED:RULE-ID] tokens. */
  redacted: string;
  /** All matches that were redacted. */
  findings: RedactionFinding[];
  /** True if any finding had HIGH severity — caller may choose to block instead. */
  hasHigh: boolean;
}

/**
 * Scans arbitrary text (typically an LLM prompt) for sensitive values and
 * returns a redacted version with [REDACTED:RULE-ID] tokens substituted.
 *
 * Replacement strategy: longest match first, so that nested/overlapping
 * matches don't get clobbered by shorter substitutions. Lines that look
 * like env-var or config references are passed through unchanged.
 *
 * This is intentionally separate from runNlp() — that function is line-and-
 * diff-aware, while this one operates on raw prompt text. Sharing the same
 * RULES array keeps the two views consistent without duplicating regex.
 */
export function redactSensitive(text: string): RedactionResult {
  if (!text) return { redacted: text, findings: [], hasHigh: false };

  const findings: RedactionFinding[] = [];
  const lines = text.split("\n");

  for (const rule of RULES) {
    if (!rule.redactable) continue;

    // Build a global version of the rule's pattern so we can iterate every match.
    // The original rule patterns omit the `g` flag because the diff scanner
    // only needs a single boolean test per line.
    const flags = rule.pattern.flags.includes("g")
      ? rule.pattern.flags
      : rule.pattern.flags + "g";
    const globalPattern = new RegExp(rule.pattern.source, flags);

    for (const line of lines) {
      if (isSafeEnvRef(line)) continue;
      if (isExampleValue(line)) continue;

      let m: RegExpExecArray | null;
      globalPattern.lastIndex = 0;
      while ((m = globalPattern.exec(line)) !== null) {
        const matchedText = m[0];

        // Entropy filter — skip obvious non-secrets so we don't redact
        // legitimate substrings (e.g. "test_key" matching the generic-secret rule).
        if (rule.checkEntropy && rule.minEntropy !== undefined) {
          const candidate = matchedText.replace(/['"]/g, "").trim();
          if (candidate && shannonEntropy(candidate) < rule.minEntropy) {
            if (matchedText.length === 0) globalPattern.lastIndex++;
            continue;
          }
        }

        findings.push({
          ruleId: rule.id,
          category: rule.category ?? "GENERAL",
          severity: rule.severity,
          matchedText,
        });

        // Guard against zero-width matches looping forever
        if (matchedText.length === 0) globalPattern.lastIndex++;
      }
    }
  }

  // Apply substitutions in two tiers:
  //   1. Specific rules first (sk-key, cred-jwt, cred-gcp, pii-ssn, etc.) — so that
  //      a broad catch-all like cred-generic-secret doesn't gobble up an overlapping
  //      match before its specific rule can label it.
  //   2. Generic rules second, over whatever text remains.
  // Within each tier, longer matches go first so nested matches don't get clobbered.
  const GENERIC_RULES = new Set(["cred-generic-secret"]);
  const isGeneric = (id: string) => GENERIC_RULES.has(id);

  const sorted = [...findings].sort((a, b) => {
    const aGen = isGeneric(a.ruleId);
    const bGen = isGeneric(b.ruleId);
    if (aGen !== bGen) return aGen ? 1 : -1;          // specific before generic
    return b.matchedText.length - a.matchedText.length; // then longest first
  });

  let redacted = text;
  const alreadyReplaced = new Set<string>();
  for (const f of sorted) {
    if (alreadyReplaced.has(f.matchedText)) continue;
    // Skip if the matched text no longer exists in the (partially redacted) string.
    // This happens when a more specific rule already replaced an overlapping span.
    if (!redacted.includes(f.matchedText)) continue;
    // Literal split/join (not regex) — the matched text may contain regex
    // metacharacters that would otherwise need escaping.
    redacted = redacted.split(f.matchedText).join(`[REDACTED:${f.ruleId}]`);
    alreadyReplaced.add(f.matchedText);
  }

  return {
    redacted,
    findings,
    hasHigh: findings.some((f) => f.severity === "HIGH"),
  };
}

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
  /test.fixture/, /test-fixture/,   // test fixture dirs — examples, not real code
  /hookrunner/,                     // extension infra, not application code
  /webpack\.config/, /jest\.config/, /babel\.config/, /vite\.config/, /rollup\.config/,
  /nlpscanner/, /diffscanner/, /filecache/, /aiclient/, /hookinstaller/, // extension source
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