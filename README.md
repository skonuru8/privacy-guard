# Privacy Guard — VS Code Extension

AI-powered privacy analysis built into your development workflow. Catches privacy issues in your code changes and dependencies before they ship, with support for multiple AI providers.

> **Note:** This extension requires the latest version of VS Code and the latest LTS release of Node.js. Using older versions may result in unexpected behaviour or failed builds.

---

## Contributors

- Sri Lasya Siripurapu
- Kedar Naik
- Sri Sai Sarath Chandra Konuru

## Features

### 🔍 Pre-Commit Privacy Check

Automatically runs on every `git commit` via a git hook installed when you open the project. Also triggerable manually at any time.

Every commit runs through a 5-layer pipeline designed to scan every file completely while minimising API cost:

1. **Triage** — skips binaries, lockfiles, minified files, and generated assets instantly
2. **Cache** — skips files whose diff hasn't changed since the last scan (stored in `.git/privacy-guard-cache.json`)
3. **NLP + Entropy** — runs local regex patterns to catch high-confidence issues without an API call; uses Shannon entropy scoring to filter out example/documentation values
4. **Path risk classification** — classifies each file as HIGH, MEDIUM, or LOW risk based on its path name
5. **LLM** — only files that need deeper reasoning are sent to the AI model

**LLM call decision per file:**

| Condition | LLM called? |
|---|---|
| `.md`, `.txt`, `.rst` doc file | Never — NLP secrets-only scan |
| NLP finds HIGH (secret/hardcoded key) | No — already blocking |
| NLP finds MEDIUM (tracker/HTTP) | Yes — confirms or escalates |
| NLP clean + HIGH-risk path (`auth`, `payment`, `user`) | Yes — subtle issues possible |
| NLP clean + LOW-risk path (`utils`, `tests`, `fixtures`) | No — trust NLP |
| NLP clean + everything else | Yes — safe default |

**What the NLP layer catches without an API call:**

The local rule set covers six categories — credentials, PII, network, business/IP, PHI, and code-shape patterns. A representative sample below; the complete list lives in `src/nlpScanner.ts`.

| Category | Examples | Severity |
|---|---|---|
| **Credentials** | OpenAI / Stripe / Anthropic keys (`sk-...`), AWS access keys (all six IAM prefixes), GCP / Firebase keys (`AIza...`), GitHub tokens (`ghp_...`, `github_pat_...`), JWTs, SSH/PEM private keys, Azure SAS tokens, bearer tokens, encryption keys, generic `password=`/`secret=` assignments, credentials in connection URLs | HIGH |
| **PII** | Hardcoded SSNs, dates of birth, passport / national-ID numbers | HIGH |
| **PII** | Email addresses, US phone numbers, street addresses | MEDIUM |
| **PII** | GPS coordinates | LOW |
| **Network** | Internal hostnames (`*.corp.*`, `*.staging.*`), webhook URLs with tokens in the path | MEDIUM |
| **Network** | RFC 1918 private IPs (10/8, 172.16/12, 192.168/16) | MEDIUM |
| **Network** | localhost / 127.0.0.1 with port | LOW |
| **Business / IP** | Commented-out credentials, license / serial keys | HIGH |
| **Business / IP** | Sensitive `TODO`/`FIXME` comments, contract / PO / invoice numbers, `// proprietary` / `// trade secret` markers | MEDIUM |
| **PHI (HIPAA)** | Medical record numbers, ICD-10 diagnosis codes, NPI numbers | HIGH |
| **Code-shape (logging / transport)** | PII fields in `console.log` (email, password, ssn, token), template literals logging `${user.email}`, raw password from `req.body` stored without hashing | HIGH |
| **Code-shape (logging / transport)** | Geolocation accessed without a consent check, `fetch()` / `axios` calls over `http://`, Google Analytics / Mixpanel / Amplitude / Segment calls | MEDIUM |

The Shannon-entropy filter and the example-value allowlist together suppress common false positives — `user@example.com`, `555-0100`, `123-45-6789`, `sk-invalidkey...`, `AKIAIOSFODNN7EXAMPLE`, and similar reserved test values pass through unflagged.

**What gets flagged:**
- PII collected, logged, or hardcoded (names, emails, phone numbers, addresses, SSNs, dates of birth, passport / national-ID numbers, GPS coordinates)
- Sensitive data in logs or error messages (passwords, tokens, health data, financial data)
- Hardcoded secrets and API keys (OpenAI, Anthropic, AWS, GCP, Azure, GitHub, JWTs, SSH/PEM private keys)
- Internal infrastructure exposure (private IPs, internal hostnames, webhook tokens)
- PHI under HIPAA (medical record numbers, ICD diagnosis codes, NPIs)
- Intellectual-property leakage (commented-out credentials, license keys, code marked proprietary or confidential)
- Third-party API calls that share user data without consent
- Missing consent checks before data collection
- Insecure data transmission (HTTP instead of HTTPS)
- Relevant GDPR article, CCPA section, or HIPAA citation for each issue

Each issue is given a severity of `LOW`, `MEDIUM`, or `HIGH`. The commit is blocked only if the overall risk is `HIGH`. If the API is unreachable or the check fails for any reason, the commit always proceeds.

**How to trigger:**
- Automatically on every `git commit` (hook installed on extension activation)
- Source Control panel toolbar → Privacy Guard icon
- `Ctrl+Shift+P` → `Privacy Guard: Check Staged Changes`

**Example terminal output:**
```
Privacy Guard [openrouter]: Scanning 8 file(s)... done
────────────────────────────────────────
Risk: HIGH
Found 2 issue(s) — 1 high, 1 medium.
Files: 8 | LLM calls: 1 | Cache hits: 3

Issue 1 — auth.js [HIGH]
  Problem: console.log(user.password) exposes credentials in logs
  Fix:     Remove the log or replace with a redacted placeholder
  GDPR Article 5(1)(f) — integrity and confidentiality

❌ Privacy Guard blocked this commit. Fix the issues above or run:
   git commit --no-verify   (to bypass)
```

> **Note:** If you intentionally commit files that contain example privacy violations (such as test fixtures), use `git commit --no-verify` to bypass the hook. The scanner correctly identifies these as issues — bypassing is the right approach for known-bad example files.

---

### 🛡 Self-Defense — Outbound Prompt Filter

Privacy Guard sends file diffs to a third-party LLM as part of its analysis pipeline. Without the outbound filter, a diff containing a real OpenAI key, AWS secret, or customer email would be transmitted in plaintext to Anthropic, OpenAI, or whichever OpenRouter model you've selected — defeating the purpose of running the check at all.

The outbound filter closes that hole. Every prompt the extension is about to send is scrubbed first using the same rule set that scans your code, so the analyzer sees `[REDACTED:sk-key]` instead of the actual key. The structure of the diff is preserved well enough for the LLM to still reason about it ("there's a credential on line 14 — is the surrounding code handling it correctly?") without the secret ever leaving the machine.

Only value-bearing rules participate (rules tagged `redactable: true` in `nlpScanner.ts`). Code-shape rules like "console.log contains an email field" are excluded — there's nothing to redact, the issue is the call site itself.

**Modes** — set via `privacyGuard.outboundFilterMode`:

| Mode | Behavior |
|---|---|
| `redact` (default) | Sensitive matches are replaced with `[REDACTED:RULE-ID]` tokens. The (scrubbed) prompt is sent. A status notification lists what was scrubbed. |
| `block` | If a HIGH-severity match is found, the LLM call is refused entirely; the file's NLP-only result is used as the final verdict. Lower-severity matches are still redacted. |
| `warn` | The original prompt is sent unchanged, but a warning notification lists what just left the machine. Useful when you want full LLM fidelity and accept the tradeoff. |
| `off` | No filtering at all. Pre-existing behavior. |

**Safe references are never redacted.** Lines accessing values via `process.env.*`, `os.getenv(...)`, `config.*`, `secrets.*`, or `vault.*` pass through untouched — the *correct* way to handle a secret should never be flagged as the leak.

**Standalone hook (`hookRunner.js`)** has the same protection. Because it runs without VS Code, it reads its mode from the `PRIVACY_GUARD_OUTBOUND_FILTER` environment variable instead of VS Code settings (default: `redact`). Filter activity is logged to stderr so it doesn't pollute the hook's normal output.

**Example** — a diff containing this code:
```js
const apiKey = "sk-x7Kp9mQ2vN4tR8wL3jH6yD1bF5gZ0cVaB";
const dbUrl  = "postgres://admin:hunter2@db.internal:5432/prod";
const email  = "alice@company.com";
const safe   = process.env.OPENAI_API_KEY;
```

…is transformed before sending to:
```js
const apiKey = [REDACTED:sk-key];
const dbUrl  = "postgres[REDACTED:credentials-in-url]:5432/prod";
const email  = "[REDACTED:pii-email]";
const safe   = process.env.OPENAI_API_KEY;
```

---

### 📦 Dependency Privacy Scanner

Reads your `package.json` and scores every dependency (both `dependencies` and `devDependencies`) for privacy risk.

Each package receives:
- A risk score: `SAFE`, `CAUTION`, or `HIGH_RISK`
- A plain-English reason explaining the score
- The relevant GDPR article or CCPA section where applicable
- A suggested alternative package where one exists

**How to trigger:**
- Privacy Guard sidebar panel → "Scan Dependencies"
- `Ctrl+Shift+P` → `Privacy Guard: Scan Dependencies`

---

### 🪝 Git Hook Management

The pre-commit hook is installed automatically when the extension activates and a `.git` directory is detected. It will not overwrite any existing hook that Privacy Guard did not create.

**Important:** When you update to a new version of the extension, you must reinstall the hook manually — the old hook path points to the previous version's files.

```
Ctrl+Shift+P → Privacy Guard: Uninstall Pre-Commit Hook
Ctrl+Shift+P → Privacy Guard: Install Pre-Commit Hook
```

Verify the hook is pointing to the correct version:
```bash
cat .git/hooks/pre-commit
# Should show consenterra.privacy-guard-0.2.0 (not 0.1.0)
```

Additional hook commands:

| Command | Description |
|---|---|
| `Privacy Guard: Install Pre-Commit Hook` | Installs the hook into `.git/hooks/pre-commit` |
| `Privacy Guard: Uninstall Pre-Commit Hook` | Removes the hook (only if installed by Privacy Guard) |

The hook runs as a standalone Node script (`hookRunner.js`) — it does not require VS Code to be open. The scan results cache is stored in `.git/privacy-guard-cache.json` and is never committed.

---

## Installation

### Install from VSIX (recommended for team distribution)

1. Download `privacy-guard-x.x.x.vsix`
2. In VS Code: `Ctrl+Shift+P` → `Extensions: Install from VSIX`
3. Select the downloaded file
4. Open your project folder — the hook installs automatically on activation
5. Configure your API key (see Configuration below)

**After installing a new version**, always reinstall the hook:
```
Ctrl+Shift+P → Privacy Guard: Uninstall Pre-Commit Hook
Ctrl+Shift+P → Privacy Guard: Install Pre-Commit Hook
```

### Install from source

```bash
git clone https://github.com/skonuru8/privacy-guard
cd privacy-guard
npm install
code .
```

Press `F5` to launch an Extension Development Host. Configure your API key in that window.

---

## Configuration

All settings are under `privacyGuard.*` in VS Code Settings (`Ctrl+Shift+P` → `Preferences: Open Settings`).

| Setting | Type | Default | Description |
|---|---|---|---|
| `privacyGuard.provider` | `string` | `anthropic` | AI provider: `anthropic`, `openai`, or `openrouter` |
| `privacyGuard.anthropicApiKey` | `string` | — | Anthropic API key — [console.anthropic.com](https://console.anthropic.com) |
| `privacyGuard.openaiApiKey` | `string` | — | OpenAI API key — [platform.openai.com](https://platform.openai.com/api-keys) |
| `privacyGuard.openrouterApiKey` | `string` | — | OpenRouter API key — [openrouter.ai/keys](https://openrouter.ai/keys) |
| `privacyGuard.anthropicModel` | `string` | `claude-sonnet-4-20250514` | Model ID when using Anthropic. See [docs.anthropic.com/en/docs/about-claude/models](https://docs.anthropic.com/en/docs/about-claude/models) for available models. |
| `privacyGuard.openaiModel` | `string` | `gpt-4o` | Model ID when using OpenAI. See [platform.openai.com/docs/models](https://platform.openai.com/docs/models) for available models. |
| `privacyGuard.openRouterModel` | `string` | `mistralai/mistral-7b-instruct` | Model slug when using OpenRouter. See [openrouter.ai/models](https://openrouter.ai/models). |
| `privacyGuard.outboundFilterMode` | `string` | `redact` | Self-defense for outbound LLM prompts. One of `redact`, `block`, `warn`, `off`. See the Self-Defense section above. |

All three key fields can be filled simultaneously. Switching the `provider` dropdown picks up the correct key automatically.

### Supported Providers

**Anthropic** (default) — uses `claude-sonnet-4-20250514` by default; override with `privacyGuard.anthropicModel`
```
privacyGuard.provider        →  anthropic
privacyGuard.anthropicApiKey →  sk-ant-...
```

**OpenAI** — uses `gpt-4o` by default; override with `privacyGuard.openaiModel`
```
privacyGuard.provider     →  openai
privacyGuard.openaiApiKey →  sk-...
```

**OpenRouter** — routes to any model on [openrouter.ai/models](https://openrouter.ai/models)
```
privacyGuard.provider          →  openrouter
privacyGuard.openrouterApiKey  →  sk-or-...
privacyGuard.openRouterModel   →  deepseek/deepseek-r1-0528
```

Useful OpenRouter model slugs:

| Model | Slug |
|---|---|
| DeepSeek R1 | `deepseek/deepseek-r1-0528` |
| Mistral 7B (free tier) | `mistralai/mistral-7b-instruct` |
| Llama 3.1 70B | `meta-llama/llama-3.1-70b-instruct` |
| GPT-4o via OpenRouter | `openai/gpt-4o` |
| Gemini Flash 1.5 | `google/gemini-flash-1.5` |

### CI/CD Configuration

```bash
export PRIVACY_GUARD_PROVIDER=openrouter
export PRIVACY_GUARD_API_KEY=sk-or-...
export PRIVACY_GUARD_OPENROUTER_MODEL=deepseek/deepseek-r1-0528

# Optional: control the outbound prompt filter (default: redact)
export PRIVACY_GUARD_OUTBOUND_FILTER=redact   # redact | block | warn | off
```

---

## Project Structure

```
privacy-guard/
├── src/
│   ├── extension.ts        — entry point, registers all commands and the sidebar
│   ├── aiClient.ts         — multi-provider AI client (Anthropic, OpenAI, OpenRouter)
│   ├── diffScanner.ts      — 5-layer pipeline orchestrator
│   ├── nlpScanner.ts       — local regex + entropy + path risk classification
│   ├── fileCache.ts        — sha256 diff cache stored in .git/privacy-guard-cache.json
│   ├── packageScanner.ts   — reads package.json and scores dependencies
│   ├── hookInstaller.ts    — installs/uninstalls the git pre-commit hook
│   ├── webviewPanel.ts     — sidebar UI rendered as an HTML webview
│   └── test/
│       ├── __mocks__/
│       │   └── vscode.ts   — VS Code API stub for Jest
│       ├── nlpScanner.test.ts
│       ├── diffScanner.test.ts
│       ├── fileCache.test.ts
│       ├── packageScanner.test.ts
│       └── hookInstaller.test.ts
├── test-fixtures/
│   ├── hookRunner.fixture.test.js   — integration tests for the standalone hook
│   └── packageScanner.fixture.test.js
├── hookRunner.js           — standalone Node script called by the git hook at commit time
├── jest.config.js          — Jest configuration (ts-jest, vscode mock, test globs)
├── package.json            — extension manifest, commands, and settings schema
└── tsconfig.json
```

---

## Contributing

### Adding a new NLP rule

Each rule must be added in **two places** — `src/nlpScanner.ts` (used by the VS Code extension) and `hookRunner.js` (used by the standalone git hook). Keep both copies identical.

A rule object has these fields:

| Field | Required | Description |
|---|---|---|
| `id` | ✓ | Unique rule identifier; appears in `[REDACTED:RULE-ID]` tokens |
| `pattern` | ✓ | `RegExp` matched against added (`+`) lines of each diff |
| `severity` | ✓ | `LOW` / `MEDIUM` / `HIGH` — only HIGH blocks a commit |
| `issue` | ✓ | One-line explanation shown to the developer |
| `fix` | ✓ | Concrete remediation suggestion |
| `regulation` | ✓ | GDPR / CCPA / HIPAA citation, or `null` |
| `checkEntropy` | – | If `true`, run Shannon entropy on the match before flagging |
| `minEntropy` | – | Minimum entropy to flag — strings below this are treated as examples |
| `skipOnDocs` | – | If `true`, skip this rule on `.md` / `.txt` / `.rst` files |
| `category` | – | One of `PII` / `CREDENTIALS` / `NETWORK` / `BUSINESS` / `IP` / `PHI` / `GENERAL` |
| `redactable` | – | If `true`, this rule's matches are scrubbed from outbound LLM prompts (see Self-Defense). Only set on **value-bearing** rules — a rule like "console.log contains an email field" should leave this off |

### Adding a new AI provider

Add a `callYourProvider()` function in `src/aiClient.ts`, a new `case` in the `callAI()` switch, and the matching implementation in `hookRunner.js`. The outbound filter is applied centrally in `callAI()` so new providers inherit it automatically.

### Known: rule duplication

Rules currently live in two files (`src/nlpScanner.ts` and `hookRunner.js`) with the same shape. Extracting the rule registry into a shared package is on the roadmap; until then, every rule change has to be made in both places.

### Build commands

```bash
npm run compile        # compile TypeScript once
npm run watch          # auto-compile on every save
npm run package        # build and package as .vsix for distribution
npm test               # run full Jest test suite
npm run test:watch     # re-run tests on every save
npm run test:coverage  # generate coverage report
npm run test:unit      # unit tests only (src/test/)
npm run test:fixtures  # integration tests only (test-fixtures/)
```

---

## Tech Stack

- **TypeScript** + VS Code Extension API
- **Multi-provider AI** via direct HTTPS — no backend, no SDK dependencies
- **Local NLP** via regex + Shannon entropy — no external NLP library
- No runtime dependencies beyond VS Code types and Node built-ins