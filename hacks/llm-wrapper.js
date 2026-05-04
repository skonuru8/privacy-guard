/**
 * llm-wrapper.js
 *
 * Drop-in wrapper around any LLM call.
 * When leaks are detected, it pauses and asks the developer:
 *
 *   [1] Block — don't send anything
 *   [2] Send redacted — replace sensitive values with [REDACTED:...] tokens
 *   [3] Send anyway — bypass the filter (not recommended)
 *
 * Usage after npm install:
 *   const { sendToLLM } = require("privacy-guard");
 *   const reply = await sendToLLM(myPrompt);
 *
 * Usage with local copy:
 *   const { sendToLLM } = require("./llm-wrapper");
 *   const reply = await sendToLLM(myPrompt);
 */

"use strict";

const readline = require("readline");
const { checkInput } = require("./llm-filter");

// ── Replace this with your real LLM client call ───────────────────────────────
async function callLLM(prompt) {
  // Example using OpenAI — swap for Anthropic, Azure, Groq, etc.
  //
  // const OpenAI = require("openai");
  // const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  // const res = await client.chat.completions.create({
  //   model: "gpt-4o",
  //   messages: [{ role: "user", content: prompt }],
  // });
  // return res.choices[0].message.content;

  // Mock response for demonstration — remove this once you wire in your client
  console.log(`\n[LLM] Received prompt (${prompt.length} chars)\n`);
  return "This is the LLM response.";
}

// ── Ask the developer a question and wait for their keypress ──────────────────
function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// ── Main wrapper ──────────────────────────────────────────────────────────────
async function sendToLLM(prompt) {
  const result = checkInput(prompt);

  // No issues found — send immediately
  if (result.safe) {
    return callLLM(prompt);
  }

  // Leaks found — print the alert and ask the developer what to do
  result.printAlert();

  const s = result.summary;
  console.log(`\nFound ${s.high} HIGH  ${s.medium} MEDIUM  ${s.low} LOW\n`);
  console.log("What do you want to do?\n");
  console.log("  [1] Block       — do not send anything");
  console.log("  [2] Send redacted — replace leaked values with [REDACTED:...] tokens");
  console.log("  [3] Send anyway — bypass the filter (not recommended)\n");

  const choice = await ask("Enter 1, 2, or 3: ");

  switch (choice) {
    case "1":
      console.log("\nBlocked. Nothing was sent to the LLM.\n");
      return null;

    case "2":
      console.log("\nSending redacted version...\n");
      return callLLM(result.redacted);

    case "3":
      console.log("\n⚠  Bypassing filter. Sending original prompt.\n");
      return callLLM(prompt);

    default:
      console.log("\nInvalid choice. Blocking by default.\n");
      return null;
  }
}

module.exports = { sendToLLM };
