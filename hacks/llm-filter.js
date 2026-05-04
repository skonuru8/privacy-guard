/**
 * llm-filter.js
 *
 * A pre-send privacy filter for LLM inputs.
 * Use it two ways:
 *
 *  1. Programmatic (drop into your existing LLM call):
 *     ─────────────────────────────────────────────────
 *     const { checkInput } = require("./llm-filter");
 *
 *     async function askLLM(prompt) {
 *       const result = checkInput(prompt);
 *       if (!result.safe) {
 *         result.printAlert();
 *         return; // or throw, or send result.redacted instead
 *       }
 *       // safe to send
 *       return openai.chat.completions.create({ messages: [{ role:"user", content: prompt }] });
 *     }
 *
 *  2. Stdin pipe (use in shell scripts / editor integrations):
 *     ─────────────────────────────────────────────────────────
 *     echo "my prompt text" | node llm-filter.js
 *     cat myfile.py | node llm-filter.js --redact   # prints redacted text on stdout
 */

"use strict";

const CATEGORIES = require("./patterns");

// ── Severity helpers ──────────────────────────────────────────────────────────
const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// ── Core check function ───────────────────────────────────────────────────────

/**
 * checkInput(text, options?) → CheckResult
 *
 * options:
 *   severityThreshold : 'HIGH' | 'MEDIUM' | 'LOW'  (default: 'MEDIUM')
 *                       Findings at or above this level set safe=false.
 *
 * CheckResult:
 *   safe       : boolean  — true only if no findings meet the threshold
 *   blocked    : boolean  — alias for !safe (clearer in if-statements)
 *   findings   : Finding[]
 *   redacted   : string   — input text with matched values replaced by [REDACTED:<RULE_ID>]
 *   summary    : { high, medium, low, total }
 *   printAlert : () => void  — formatted console output
 */
function checkInput(text, options = {}) {
  const threshold = options.severityThreshold ?? "MEDIUM";
  const thresholdLevel = SEVERITY_ORDER[threshold.toUpperCase()] ?? 1;

  const findings = [];
  const lines = text.split("\n");

  for (const [category, rules] of Object.entries(CATEGORIES)) {
    for (const rule of rules) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        rule.regex.lastIndex = 0;
        let match;

        while ((match = rule.regex.exec(line)) !== null) {
          if (isSafeEnvRef(line)) continue;

          findings.push({
            category,
            ruleId: rule.id,
            label: rule.label,
            severity: rule.severity,
            line: i + 1,
            column: match.index + 1,
            snippet: line.trim().slice(0, 120),
            matchedText: match[0],
            note: rule.note,
          });

          if (match[0].length === 0) rule.regex.lastIndex++;
        }
      }
    }
  }

  // Build redacted version of the original text
  let redacted = text;
  // Process in reverse severity order so substitutions don't shift positions
  const toRedact = [...findings].sort(
    (a, b) => b.matchedText.length - a.matchedText.length   // longer matches first
  );
  for (const f of toRedact) {
    // Use a literal string replace (not regex) to avoid re-processing
    redacted = redacted.split(f.matchedText).join(`[REDACTED:${f.ruleId}]`);
  }

  const summary = {
    high:   findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low:    findings.filter((f) => f.severity === "LOW").length,
    total:  findings.length,
  };

  const blockingFindings = findings.filter(
    (f) => SEVERITY_ORDER[f.severity] <= thresholdLevel
  );
  const safe = blockingFindings.length === 0;

  return {
    safe,
    blocked: !safe,
    findings,
    redacted,
    summary,
    printAlert: () => printAlert({ safe, findings, summary, threshold }),
  };
}

// ── Console alert formatter ───────────────────────────────────────────────────

const USE_COLOR = process.stdout.isTTY && !process.argv.includes("--no-color");
const c = {
  reset:   USE_COLOR ? "\x1b[0m"  : "",
  bold:    USE_COLOR ? "\x1b[1m"  : "",
  dim:     USE_COLOR ? "\x1b[2m"  : "",
  red:     USE_COLOR ? "\x1b[31m" : "",
  yellow:  USE_COLOR ? "\x1b[33m" : "",
  cyan:    USE_COLOR ? "\x1b[36m" : "",
  green:   USE_COLOR ? "\x1b[32m" : "",
  magenta: USE_COLOR ? "\x1b[35m" : "",
  blue:    USE_COLOR ? "\x1b[34m" : "",
};

const SEV_COLOR = { HIGH: c.red + c.bold, MEDIUM: c.yellow, LOW: c.cyan };
const CAT_COLOR = {
  PII: c.magenta, CREDENTIALS: c.red, NETWORK: c.blue,
  BUSINESS: c.yellow, INTELLECTUAL_PROPERTY: c.cyan, PHI: c.magenta,
};

function printAlert({ safe, findings, summary, threshold }) {
  const bar = "─".repeat(66);

  if (safe) {
    console.error(`\n${c.green}${c.bold}✔ Privacy check passed${c.reset} — no findings at ${threshold}+ severity. Safe to send.\n`);
    return;
  }

  console.error(`\n${c.red}${c.bold}╔══ ⚠  PRIVACY GUARD — BLOCKED ══════════════════════════════════╗${c.reset}`);
  console.error(`${c.red}${c.bold}║  This input contains sensitive data and was NOT sent to the LLM. ║${c.reset}`);
  console.error(`${c.red}${c.bold}╚════════════════════════════════════════════════════════════════╝${c.reset}`);
  console.error(`\n  ${c.red}${c.bold}HIGH ${summary.high}${c.reset}   ${c.yellow}MEDIUM ${summary.medium}${c.reset}   ${c.cyan}LOW ${summary.low}${c.reset}   (threshold: ${threshold})\n`);

  // Group by category
  const byCategory = {};
  for (const f of findings) {
    (byCategory[f.category] = byCategory[f.category] || []).push(f);
  }

  for (const [cat, catFindings] of Object.entries(byCategory)) {
    const col = CAT_COLOR[cat] || c.cyan;
    console.error(`${col}${c.bold}▶ ${cat.replace(/_/g, " ")}${c.reset}`);

    for (const f of catFindings) {
      const sev = SEV_COLOR[f.severity] + f.severity.padEnd(6) + c.reset;
      console.error(`  ${sev}  [${f.ruleId}] ${f.label}  ${c.dim}line ${f.line}${c.reset}`);
      console.error(`         ${c.dim}${f.snippet}${c.reset}`);
      console.error(`         ${c.cyan}↳ ${f.note}${c.reset}`);
    }
    console.error();
  }

  console.error(`${c.dim}${bar}${c.reset}`);
  console.error(`  Options:`);
  console.error(`  ${c.yellow}1.${c.reset} Fix the issues above and retry.`);
  console.error(`  ${c.yellow}2.${c.reset} Use the ${c.bold}redacted${c.reset} text returned by checkInput() — sensitive`);
  console.error(`     values are replaced with [REDACTED:<RULE_ID>] tokens.`);
  console.error(`  ${c.yellow}3.${c.reset} Lower the threshold (not recommended for production).`);
  console.error(`${c.dim}${bar}${c.reset}\n`);
}

// ── Env-reference guard (same logic as scanner.js) ────────────────────────────
function isSafeEnvRef(line) {
  return /process\.env\.|os\.getenv\(|os\.environ|ENV\[|getenv\(|config\.|secrets\.|vault\./.test(line);
}

// ── Stdin / CLI mode ──────────────────────────────────────────────────────────
if (require.main === module) {
  const isRedactMode = process.argv.includes("--redact");
  const threshold = (() => {
    const i = process.argv.indexOf("--severity");
    return i !== -1 ? process.argv[i + 1].toUpperCase() : "MEDIUM";
  })();

  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { input += chunk; });
  process.stdin.on("end", () => {
    if (!input.trim()) {
      console.error("privacy-guard: no input received on stdin.");
      process.exit(0);
    }

    const result = checkInput(input, { severityThreshold: threshold });

    if (isRedactMode) {
      // In --redact mode: print the cleaned text to stdout so it can be piped
      process.stdout.write(result.redacted);
      // Print alert to stderr so the pipe isn't polluted
      if (result.blocked) result.printAlert();
      process.exit(0); // don't block — caller chose to use redacted output
    } else {
      result.printAlert();
      process.exit(result.safe ? 0 : 1);
    }
  });
}

module.exports = { checkInput };
