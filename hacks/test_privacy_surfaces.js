// test_privacy_surfaces.js
// Tests all surfaces where sensitive data can leak in an LLM-based app.
//
// Run: node test_privacy_surfaces.js
//
// Surfaces tested:
//   1. System prompt      — developer hardcodes sensitive data
//   2. User input         — user types sensitive info in the prompt
//   3. Tool result        — fetched/retrieved content contains PII
//   4. LLM answer         — model echoes sensitive data back in its reply
//   5. Tool arguments     — LLM constructs a sensitive URL or query
//   6. Environment/config — process.env accidentally serialized into a prompt

"use strict";

const { checkInput } = require("./llm-filter");

// ── Color helpers ─────────────────────────────────────────────────────────────
const C = {
  reset:  "\x1b[0m",  bold:   "\x1b[1m",  dim:    "\x1b[2m",
  red:    "\x1b[31m", green:  "\x1b[32m", yellow: "\x1b[33m",
  cyan:   "\x1b[36m", blue:   "\x1b[34m",
};

// ── Test runner ───────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

function runTest(surface, description, text, expectBlocked) {
  const result = checkInput(text);
  const wasBlocked = result.blocked;
  const ok = wasBlocked === expectBlocked;

  if (ok) {
    passed++;
    console.log(`${C.green}✔ PASS${C.reset}  [${surface}] ${description}`);
    if (wasBlocked) {
      const s = result.summary;
      console.log(
        `        Caught: ${C.red}HIGH ${s.high}${C.reset}  ` +
        `${C.yellow}MEDIUM ${s.medium}${C.reset}  ` +
        `${C.cyan}LOW ${s.low}${C.reset}`
      );
      // Show each finding on one line
      for (const f of result.findings) {
        console.log(`        ${C.dim}[${f.ruleId}] ${f.label} — line ${f.line_number || f.line}${C.reset}`);
      }
    }
  } else {
    failed++;
    const expected = expectBlocked ? "BLOCKED" : "SAFE";
    const got      = wasBlocked    ? "BLOCKED" : "SAFE";
    console.log(`${C.red}✖ FAIL${C.reset}  [${surface}] ${description}`);
    console.log(`        Expected: ${expected}  |  Got: ${got}`);
  }

  console.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 1 — SYSTEM PROMPT
// Developer accidentally hardcodes sensitive data in the system prompt.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 1: System Prompt ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "SYSTEM_PROMPT", "clean prompt — should pass",
  "You are a helpful research assistant. Answer questions about Indian classical music.",
  false
);

runTest(
  "SYSTEM_PROMPT", "hardcoded email in prompt — should block",
  "Admin contact: admin@company-internal.com. You are a research assistant.",
  true
);

runTest(
  "SYSTEM_PROMPT", "hardcoded API key in prompt — should block",
  "Use api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456' for auth. You are a research assistant.",
  true
);

runTest(
  "SYSTEM_PROMPT", "hardcoded DB connection string — should block",
  "DB = postgres://admin:hunter2@192.168.1.42:5432/prod. You are a research assistant.",
  true
);

runTest(
  "SYSTEM_PROMPT", "multiple leaks at once (name + email + key) — should block",
  "name_a = Alex, Email= Alex@email.com, api_key= sk-abcdefghijklmnopqrstuvwxyz123456. You are a research assistant.",
  true
);

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 2 — USER INPUT
// User types sensitive personal information in their question.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 2: User Input ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "USER_INPUT", "clean question — should pass",
  "How is tala used to organize rhythmic cycles in Hindustani music?",
  false
);

runTest(
  "USER_INPUT", "user includes their email — should block",
  "My email is john.doe@company.com. Can you explain raga Bhairav?",
  true
);

runTest(
  "USER_INPUT", "user includes SSN — should block",
  "My SSN is 123-45-6789. What is the difference between Carnatic and Hindustani music?",
  true
);

runTest(
  "USER_INPUT", "user includes phone number — should block",
  "Call me at (415) 555-2671 with the answer. Explain the concept of shruti.",
  true
);

runTest(
  "USER_INPUT", "user pastes a DB URL — should block",
  "Here is my connection string postgres://admin:pass123@db.internal.corp:5432/prod, check if it's correct.",
  true
);

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 3 — TOOL RESULT
// A fetched webpage or vector store result contains sensitive content
// before it gets appended back into the conversation.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 3: Tool Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "TOOL_RESULT", "clean tool result — should pass",
  "[score=0.91 | source=https://en.wikipedia.org/wiki/Tala]\nTala is the rhythmic cycle in Indian classical music...",
  false
);

runTest(
  "TOOL_RESULT", "webpage result contains an email — should block",
  "Contact our team at support@internal-corp.com for more details about the music archive.",
  true
);

runTest(
  "TOOL_RESULT", "vector chunk contains internal IP — should block",
  "[score=0.87 | source=https://internal.corp.com/docs]\nSee the server at 192.168.1.100 for the full dataset.",
  true
);

runTest(
  "TOOL_RESULT", "fetched page contains an API key — should block",
  "To access the API use the key sk-abcdefghijklmnopqrstuvwxyz123456 in your headers.",
  true
);

runTest(
  "TOOL_RESULT", "Wikipedia result — should pass",
  "Hindustani music\nHindustani classical music is the Hindustani or North Indian style of Indian classical music.",
  false
);

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 4 — LLM ANSWER
// The model echoes sensitive data back in its reply.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 4: LLM Answer ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "LLM_ANSWER", "clean answer — should pass",
  "Tala refers to the rhythmic cycle in Indian classical music. Sources: https://en.wikipedia.org/wiki/Tala_(music)",
  false
);

runTest(
  "LLM_ANSWER", "model echoes email from context — should block",
  "According to the document, please contact admin@company-internal.com for more information on ragas.",
  true
);

runTest(
  "LLM_ANSWER", "model echoes API key from context — should block",
  "The configuration uses api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456' as shown in the source.",
  true
);

runTest(
  "LLM_ANSWER", "model echoes DB credentials — should block",
  "The connection string provided was postgres://admin:hunter2@192.168.1.42:5432/prod.",
  true
);

runTest(
  "LLM_ANSWER", "model echoes PHI — should block",
  "Patient MRN: 0093421, diagnosis icd-10 = E11.9 was mentioned in the retrieved document.",
  true
);

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 5 — TOOL ARGUMENTS
// The LLM constructs a sensitive URL or query string from conversation context.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 5: Tool Arguments ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "TOOL_ARGS", "clean tool call — should pass",
  JSON.stringify({ url: "https://en.wikipedia.org/wiki/Hindustani_music" }),
  false
);

runTest(
  "TOOL_ARGS", "LLM constructs internal URL — should block",
  JSON.stringify({ url: "https://internal.corp.acme.com/api/v2/users" }),
  true
);

runTest(
  "TOOL_ARGS", "LLM constructs webhook URL with token — should block",
  JSON.stringify({ url: "https://hooks.example.com/webhook/aB3xK8mNpQ2rT5uW9z" }),
  true
);

runTest(
  "TOOL_ARGS", "LLM puts email in search query — should block",
  JSON.stringify({ query: "find records for john.doe@company-internal.com" }),
  true
);

runTest(
  "TOOL_ARGS", "LLM puts private IP in search — should block",
  JSON.stringify({ query: "logs from server 192.168.10.45 last 24 hours" }),
  true
);

// ─────────────────────────────────────────────────────────────────────────────
// SURFACE 6 — ENVIRONMENT / CONFIG
// process.env or a config object gets accidentally serialized into a prompt.
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}━━━ Surface 6: Environment / Config Serialization ━━━━━━━━━━━━━━━${C.reset}\n`);

runTest(
  "ENV_LEAK", "safe env reference in code — should pass",
  "const apiKey = process.env.OPENAI_API_KEY;",
  false
);

// Simulate what happens when someone does: prompt += JSON.stringify(process.env)
const simulatedEnvDump = JSON.stringify({
  OPENAI_API_KEY: "sk-abcdefghijklmnopqrstuvwxyz123456",
  DATABASE_URL:   "postgres://admin:hunter2@db.internal:5432/prod",
  NODE_ENV:       "production",
  PORT:           "3000",
});

runTest(
  "ENV_LEAK", "process.env serialized into prompt — should block",
  `Here is my config: ${simulatedEnvDump}. What should I change?`,
  true
);

runTest(
  "ENV_LEAK", "AWS keys in serialized config — should block",
  JSON.stringify({ AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE", AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }),
  true
);

runTest(
  "ENV_LEAK", "JWT accidentally included in config dump — should block",
  `Config: { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" }`,
  true
);

runTest(
  "ENV_LEAK", "SSH private key block in prompt — should block",
  "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----",
  true
);

// ─────────────────────────────────────────────────────────────────────────────
// Final summary
// ─────────────────────────────────────────────────────────────────────────────
const total = passed + failed;
console.log(`${C.bold}━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}`);
console.log(`  Total  : ${total}`);
console.log(`  ${C.green}Passed : ${passed}${C.reset}`);
if (failed > 0) {
  console.log(`  ${C.red}Failed : ${failed}${C.reset}`);
} else {
  console.log(`  ${C.green}Failed : 0 — all surfaces protected ✔${C.reset}`);
}
console.log();
