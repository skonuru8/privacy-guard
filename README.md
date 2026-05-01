# Privacy Guard — VS Code Extension

AI-powered privacy analysis built into your development workflow. Catches privacy issues in your code changes and dependencies before they ship, with support for multiple AI providers.

---

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

| Pattern | Severity |
|---|---|
| Hardcoded OpenAI / Stripe keys (`sk-...`) | HIGH |
| AWS Access Key IDs (`AKIA...`) | HIGH |
| Private keys (`-----BEGIN RSA PRIVATE KEY`) | HIGH |
| Credentials in connection URLs (`user:pass@host`) | HIGH |
| GitHub tokens (`ghp_...`, `github_pat_...`) | HIGH |
| PII fields in `console.log` (email, password, ssn, token) | HIGH |
| Template literals logging PII (`` `user=${user.email}` ``) | HIGH |
| Raw password from request body stored without hashing | HIGH |
| Geolocation accessed without visible consent check | MEDIUM |
| `fetch()` or `axios` calls over `http://` | MEDIUM |
| Google Analytics, Mixpanel, Amplitude, Segment calls | MEDIUM |

**What gets flagged:**
- PII collected or logged (names, emails, phone numbers, location data, IDs)
- Sensitive data in logs or error messages (passwords, tokens, health data, financial data)
- Hardcoded secrets and API keys
- Third-party API calls that share user data without consent
- Missing consent checks before data collection
- Insecure data transmission (HTTP instead of HTTPS)
- Relevant GDPR article or CCPA section for each issue

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
| `privacyGuard.openRouterModel` | `string` | `mistralai/mistral-7b-instruct` | Model slug when using OpenRouter |

All three key fields can be filled simultaneously. Switching the `provider` dropdown picks up the correct key automatically.

### Supported Providers

**Anthropic** (default) — uses `claude-sonnet-4-20250514`
```
privacyGuard.provider        →  anthropic
privacyGuard.anthropicApiKey →  sk-ant-...
```

**OpenAI** — uses `gpt-4o`
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
│   └── webviewPanel.ts     — sidebar UI rendered as an HTML webview
├── hookRunner.js           — standalone Node script called by the git hook at commit time
├── package.json            — extension manifest, commands, and settings schema
└── tsconfig.json
```

---

## Contributing

To add a new NLP rule, add an entry to the `RULES` array in `src/nlpScanner.ts` and the matching entry in `hookRunner.js`. No other files need to change.

To add a new AI provider, add a `callYourProvider()` function in `src/aiClient.ts`, a new `case` in the `callAI()` switch, and the matching implementation in `hookRunner.js`.

### Build commands

```bash
npm run compile    # compile TypeScript once
npm run watch      # auto-compile on every save
npm run package    # build and package as .vsix for distribution
```

---

## Tech Stack

- **TypeScript** + VS Code Extension API
- **Multi-provider AI** via direct HTTPS — no backend, no SDK dependencies
- **Local NLP** via regex + Shannon entropy — no external NLP library
- No runtime dependencies beyond VS Code types and Node built-ins