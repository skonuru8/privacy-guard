/**
 * patterns.js — Privacy/security detection patterns grouped by risk category.
 *
 * Each entry:
 *   id       : unique rule ID
 *   label    : human-readable name
 *   regex    : RegExp (global flag required for line-level matching)
 *   severity : 'HIGH' | 'MEDIUM' | 'LOW'
 *   note     : remediation hint shown in the report
 */

const CATEGORIES = {
  // ─────────────────────────────────────────────────────────────────────────
  // 1. PII — Personal Identifiable Information
  // ─────────────────────────────────────────────────────────────────────────
  PII: [
    {
      id: "PII-EMAIL",
      label: "Email address",
      regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
      severity: "HIGH",
      note: "Replace with a placeholder (e.g. user@example.com) or load from env.",
    },
    {
      id: "PII-PHONE-US",
      label: "US phone number",
      regex: /(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g,
      severity: "HIGH",
      note: "Remove or replace with a test number (e.g. 555-0100).",
    },
    {
      id: "PII-SSN",
      label: "Social Security Number",
      regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
      severity: "HIGH",
      note: "Never hardcode SSNs. Use tokenized/masked values.",
    },
    {
      id: "PII-DOB",
      label: "Date of birth pattern",
      regex: /\b(dob|date.of.birth|birth.?date)\s*[:=]\s*["']?\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/gi,
      severity: "MEDIUM",
      note: "Avoid hardcoding DOB. Use anonymized/synthetic test data.",
    },
    {
      id: "PII-PASSPORT",
      label: "Passport / national ID number",
      regex: /\b(passport|national.?id|id.?number)\s*[:=]\s*["']?[A-Z0-9]{6,12}/gi,
      severity: "HIGH",
      note: "Never store identity document numbers in source code.",
    },
    {
      id: "PII-GPS",
      label: "GPS coordinates",
      regex: /[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)/g,
      severity: "MEDIUM",
      note: "Hardcoded coordinates can reveal physical location. Use config or env.",
    },
    {
      id: "PII-ADDRESS",
      label: "Street address pattern",
      regex: /\b\d{1,5}\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)*\s+(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Pkwy|Hwy)\b/g,
      severity: "MEDIUM",
      note: "Replace street addresses with synthetic test data.",
    },
  ],

  // ─────────────────────────────────────────────────────────────────────────
  // 2. CREDENTIALS — API keys, secrets, tokens, keys
  // ─────────────────────────────────────────────────────────────────────────
  CREDENTIALS: [
    {
      id: "CRED-GENERIC-SECRET",
      label: "Generic secret / password assignment",
      regex: /\b(password|passwd|secret|api_?key|auth_?token|access_?token|client_?secret)\s*[:=]\s*["'][^\s"']{4,}/gi,
      severity: "HIGH",
      note: "Move all secrets to environment variables or a secrets manager.",
    },
    {
      id: "CRED-OPENAI",
      label: "OpenAI API key",
      regex: /sk-[A-Za-z0-9]{20,}/g,
      severity: "HIGH",
      note: "Revoke this key immediately and rotate via platform.openai.com.",
    },
    {
      id: "CRED-ANTHROPIC",
      label: "Anthropic API key",
      regex: /sk-ant-[A-Za-z0-9\-_]{20,}/g,
      severity: "HIGH",
      note: "Revoke via console.anthropic.com and use process.env instead.",
    },
    {
      id: "CRED-AZURE",
      label: "Azure SAS / subscription key",
      regex: /[?&]sig=[A-Za-z0-9%+/=]{20,}|Ocp-Apim-Subscription-Key:\s*[A-Za-z0-9]{32}/g,
      severity: "HIGH",
      note: "Rotate via Azure portal and use Managed Identity or Key Vault.",
    },
    {
      id: "CRED-AWS-KEY",
      label: "AWS access key ID",
      regex: /\b(AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
      severity: "HIGH",
      note: "Revoke in IAM console immediately. Use IAM roles or AWS Secrets Manager.",
    },
    {
      id: "CRED-AWS-SECRET",
      label: "AWS secret access key",
      regex: /aws_?secret_?access_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi,
      severity: "HIGH",
      note: "Revoke and rotate. Never commit AWS secrets.",
    },
    {
      id: "CRED-GCP",
      label: "GCP / Firebase API key",
      regex: /AIza[A-Za-z0-9\-_]{35}/g,
      severity: "HIGH",
      note: "Restrict key in GCP console and move to Secret Manager.",
    },
    {
      id: "CRED-GITHUB-PAT",
      label: "GitHub personal access token",
      regex: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/g,
      severity: "HIGH",
      note: "Revoke at github.com/settings/tokens immediately.",
    },
    {
      id: "CRED-JWT",
      label: "JWT token (hardcoded)",
      regex: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*/g,
      severity: "HIGH",
      note: "Never hardcode JWTs. Tokens are revocable credentials.",
    },
    {
      id: "CRED-PRIVATE-KEY",
      label: "PEM private key block",
      regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PRIVATE KEY|CERTIFICATE)?PRIVATE KEY-----/g,
      severity: "HIGH",
      note: "Private keys must never appear in source. Use a secrets vault.",
    },
    {
      id: "CRED-SSH-KEY",
      label: "SSH private key block",
      regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
      severity: "HIGH",
      note: "SSH private keys must stay in ~/.ssh, never in source code.",
    },
    {
      id: "CRED-BEARER",
      label: "Bearer token in code",
      regex: /\bAuthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\-_.~+/=]{20,}/gi,
      severity: "HIGH",
      note: "Inject auth headers at runtime from env, not from hardcoded strings.",
    },
    {
      id: "CRED-CONN-STRING",
      label: "Database / connection string with credentials",
      regex: /(mongodb(\+srv)?|postgres|postgresql|mysql|mssql|redis):\/\/[^:@\s]+:[^@\s]+@[^\s"']+/gi,
      severity: "HIGH",
      note: "Move DB URIs with passwords to environment variables.",
    },
    {
      id: "CRED-ENCRYPTION-KEY",
      label: "Hardcoded encryption key / IV",
      regex: /\b(encryption_?key|aes_?key|secret_?key|iv|initialization_?vector)\s*[:=]\s*["'][A-Fa-f0-9]{16,}/gi,
      severity: "HIGH",
      note: "Encryption keys must be managed by a KMS/HSM, not embedded in code.",
    },
  ],

  // ─────────────────────────────────────────────────────────────────────────
  // 3. NETWORK — Internal endpoints, IPs, hostnames
  // ─────────────────────────────────────────────────────────────────────────
  NETWORK: [
    {
      id: "NET-PRIVATE-IP",
      label: "Private IP address (RFC 1918)",
      regex: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
      severity: "MEDIUM",
      note: "Internal IPs expose your network topology. Use hostnames or config.",
    },
    {
      id: "NET-LOCALHOST-PORT",
      label: "Localhost/127.0.0.1 with non-standard port",
      regex: /\b127\.0\.0\.1:\d{4,5}|localhost:\d{4,5}\b/g,
      severity: "LOW",
      note: "Dev addresses are fine locally but must not reach prod or LLM context.",
    },
    {
      id: "NET-INTERNAL-URL",
      label: "Internal / non-public hostname",
      regex: /https?:\/\/(internal|intra|corp|dev|staging|admin|vpn|private)\.[a-zA-Z0-9.\-]+/gi,
      severity: "MEDIUM",
      note: "Internal URLs reveal infrastructure. Use environment config instead.",
    },
    {
      id: "NET-PORT-HARDCODED",
      label: "Hardcoded sensitive service port",
      // Covers DB and admin ports: 3306 MySQL, 5432 Postgres, 6379 Redis, 27017 Mongo, 9200 ES
      regex: /\b(3306|5432|6379|27017|9200|8443|9300|11211)\b/g,
      severity: "LOW",
      note: "Service ports hint at backend stack. Prefer config over literals.",
    },
    {
      id: "NET-WEBHOOK-URL",
      label: "Webhook URL with token in path",
      regex: /https?:\/\/[^\s"']+\/webhook\/[A-Za-z0-9\-_]{10,}/gi,
      severity: "MEDIUM",
      note: "Webhook tokens in URLs are credentials. Move to env vars.",
    },
  ],

  // ─────────────────────────────────────────────────────────────────────────
  // 4. BUSINESS — Internal logic, project names, contracts, pricing
  // ─────────────────────────────────────────────────────────────────────────
  BUSINESS: [
    {
      id: "BIZ-TODO-SENSITIVE",
      label: "TODO/FIXME with sensitive hint",
      regex: /\b(TODO|FIXME|HACK|XXX)\b.*\b(password|secret|key|credential|ssn|credit.?card|internal|confidential)/gi,
      severity: "MEDIUM",
      note: "Sensitive TODOs reveal unfinished security work. Resolve before sharing.",
    },
    {
      id: "BIZ-COMMENTED-CRED",
      label: "Commented-out credential or key",
      regex: /\/\/.*\b(password|api.?key|secret|token)\s*[:=]\s*["']?\S+/gi,
      severity: "HIGH",
      note: "Commented credentials are still leaks. Remove entirely, don't just comment.",
    },
    {
      id: "BIZ-INTERNAL-CODENAME",
      label: "Internal project codename hint",
      regex: /\b(project|codename|internal.?name)\s*[:=]\s*["'][A-Za-z0-9\-_]{3,}/gi,
      severity: "LOW",
      note: "Internal codenames may reveal unreleased product plans.",
    },
    {
      id: "BIZ-CONTRACT-NUMBER",
      label: "Contract / PO / invoice number",
      regex: /\b(contract|purchase.?order|PO|invoice).?#?\s*[A-Z0-9\-]{5,}/gi,
      severity: "MEDIUM",
      note: "Business document IDs are confidential. Remove from code context.",
    },
    {
      id: "BIZ-HARDCODED-PRICE",
      label: "Hardcoded price / revenue figure",
      regex: /\$\s?\d{1,3}(,\d{3})+(\.\d{2})?|\b\d+\s*(USD|EUR|GBP)\b/g,
      severity: "LOW",
      note: "Hardcoded pricing may expose confidential business data.",
    },
  ],

  // ─────────────────────────────────────────────────────────────────────────
  // 5. INTELLECTUAL PROPERTY — Algorithms, proprietary logic markers
  // ─────────────────────────────────────────────────────────────────────────
  INTELLECTUAL_PROPERTY: [
    {
      id: "IP-ALGO-COMMENT",
      label: "Proprietary algorithm comment",
      regex: /\/\/\s*(proprietary|trade.?secret|confidential|do not (share|distribute|copy))/gi,
      severity: "HIGH",
      note: "Marked proprietary code must not be pasted into public LLMs.",
    },
    {
      id: "IP-LICENSE-KEY",
      label: "License / serial key",
      regex: /\b(license.?key|serial.?key|activation.?code)\s*[:=]\s*["']?[A-Z0-9\-]{10,}/gi,
      severity: "HIGH",
      note: "License keys are transferable credentials. Remove from source.",
    },
    {
      id: "IP-COPYRIGHT",
      label: "Copyright notice with company name",
      regex: /Copyright\s+\(c\)\s+\d{4}.*All Rights Reserved/gi,
      severity: "LOW",
      note:
        "Copyrighted code should not be sent to third-party LLMs without legal review.",
    },
  ],

  // ─────────────────────────────────────────────────────────────────────────
  // 6. PHI — Protected Health Information (HIPAA)
  // ─────────────────────────────────────────────────────────────────────────
  PHI: [
    {
      id: "PHI-MRN",
      label: "Medical record number",
      regex: /\b(mrn|medical.?record.?number|patient.?id)\s*[:=]\s*["']?\d{5,}/gi,
      severity: "HIGH",
      note: "PHI identifiers are HIPAA-regulated. Never hardcode; use anonymized data.",
    },
    {
      id: "PHI-DIAGNOSIS",
      label: "Diagnosis / ICD code",
      regex: /\b(diagnosis|icd.?10|icd.?9|condition)\s*[:=]\s*["'][A-Z]\d{2,}/gi,
      severity: "HIGH",
      note: "Medical codes in code context may constitute PHI. Remove or anonymize.",
    },
    {
      id: "PHI-NPI",
      label: "NPI (National Provider Identifier)",
      regex: /\bNPI\s*[:=]\s*["']?\d{10}\b/gi,
      severity: "HIGH",
      note: "NPI numbers identify healthcare providers. Use synthetic values in tests.",
    },
  ],
};

module.exports = CATEGORIES;
