# Privacy Guard — VS Code Extension

AI-powered privacy analysis built into your development workflow. Catches privacy issues in your code changes and dependencies before they ship, with support for multiple AI providers.

---

## Features

### 🔍 Pre-Commit Privacy Check

Automatically runs on every `git commit` via a git hook installed when you open the project. Also triggerable manually at any time.

Analyzes your staged diff and flags:
- PII being collected or logged (names, emails, phone numbers, location data, IDs)
- Sensitive data exposed in logs or error messages (passwords, tokens, health data, financial data)
- New third-party API calls that may share user data without consent
- Missing consent checks before data collection
- Insecure data transmission
- Relevant GDPR article or CCPA section for each issue

Each issue is given a severity of `LOW`, `MEDIUM`, or `HIGH`. The commit is blocked only if the overall risk is `HIGH`. `LOW` and `MEDIUM` findings print a warning but allow the commit to proceed.

**How to trigger:**
- Automatically on every `git commit` (hook installed on extension activation)
- Source Control panel toolbar → Privacy Guard icon
- `Ctrl+Shift+P` → `Privacy Guard: Check Staged Changes`

**Example terminal output on commit:**
```
Privacy Guard [anthropic]: Scanning staged changes... done
────────────────────────────────────────
Risk: HIGH
User credentials are being logged in plaintext.

Issue 1 — auth.js [HIGH]
  Problem: console.log(user.password) exposes credentials in logs
  Fix:     Remove the log or replace with a redacted placeholder
  GDPR Article 5(1)(f) — integrity and confidentiality

❌ Privacy Guard blocked this commit.
   git commit --no-verify   (to bypass)
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

The pre-commit hook is installed automatically when the extension activates and a `.git` directory is detected. It is safe to install — it will not overwrite any existing hook that Privacy Guard did not create.

If you need to manage the hook manually:

| Command | Description |
|---|---|
| `Privacy Guard: Install Pre-Commit Hook` | Installs the hook into `.git/hooks/pre-commit` |
| `Privacy Guard: Uninstall Pre-Commit Hook` | Removes the hook (only if installed by Privacy Guard) |

The hook runs as a standalone Node script (`hookRunner.js`) and does not require VS Code to be open.

---

## Installation

### Install from VSIX (recommended for team distribution)

1. Download `privacy-guard-x.x.x.vsix`
2. In VS Code: `Ctrl+Shift+P` → `Extensions: Install from VSIX`
3. Select the downloaded file
4. Configure your API key (see Configuration below)

### Install from source

```bash
git clone https://github.com/consenterra/privacy-guard
cd privacy-guard
npm install
code .
```

Press `F5` to launch an Extension Development Host with the extension running. Configure your API key in that window.

---

## Configuration

All settings are under `privacyGuard.*` in VS Code Settings (`Ctrl+Shift+P` → `Preferences: Open Settings`).

| Setting | Type | Default | Description |
|---|---|---|---|
| `privacyGuard.apiKey` | `string` | — | API key for the chosen provider |
| `privacyGuard.provider` | `string` | `anthropic` | AI provider: `anthropic`, `openai`, or `openrouter` |
| `privacyGuard.openRouterModel` | `string` | `mistralai/mistral-7b-instruct` | Model slug when using OpenRouter |

### Supported Providers

**Anthropic** (default) — uses `claude-sonnet-4-20250514`
```
privacyGuard.provider  →  anthropic
privacyGuard.apiKey    →  (your Anthropic key from console.anthropic.com)
```

**OpenAI** — uses `gpt-4o`
```
privacyGuard.provider  →  openai
privacyGuard.apiKey    →  (your OpenAI key)
```

**OpenRouter** — routes to any model on [openrouter.ai/models](https://openrouter.ai/models)
```
privacyGuard.provider         →  openrouter
privacyGuard.apiKey           →  (your OpenRouter key, starts with sk-or-...)
privacyGuard.openRouterModel  →  mistralai/mistral-7b-instruct
```

Some useful OpenRouter model slugs:

| Model | Slug |
|---|---|
| Mistral 7B (free tier) | `mistralai/mistral-7b-instruct` |
| Llama 3.1 70B | `meta-llama/llama-3.1-70b-instruct` |
| GPT-4o via OpenRouter | `openai/gpt-4o` |
| Gemini Flash 1.5 | `google/gemini-flash-1.5` |

### CI/CD Configuration

The git hook reads from environment variables when VS Code settings are not available. Set these in your CI environment:

```bash
export PRIVACY_GUARD_PROVIDER=anthropic          # or openai / openrouter
export PRIVACY_GUARD_API_KEY=your-key-here
export PRIVACY_GUARD_OPENROUTER_MODEL=mistralai/mistral-7b-instruct  # openrouter only
```

---

## Project Structure

```
privacy-guard/
├── src/
│   ├── extension.ts        — entry point, registers all commands and the sidebar
│   ├── aiClient.ts         — multi-provider AI client (Anthropic, OpenAI, OpenRouter)
│   ├── diffScanner.ts      — reads git diff and runs pre-commit privacy analysis
│   ├── packageScanner.ts   — reads package.json and scores dependencies
│   ├── hookInstaller.ts    — installs/uninstalls the git pre-commit hook
│   └── webviewPanel.ts     — sidebar UI rendered as an HTML webview
├── hookRunner.js           — standalone Node script called by the git hook at commit time
├── package.json            — extension manifest, commands, and settings schema
└── tsconfig.json
```

---

## Contributing

Each feature lives in its own file with no cross-dependencies beyond `aiClient.ts`. To add a new scanner:

1. Create `src/yourScanner.ts` with a function that calls `callAI()` and returns typed results
2. Add a new command in `extension.ts` that calls your scanner and passes results to the panel
3. Add a `showYourResults()` render method in `webviewPanel.ts`
4. Register the command in `package.json` under `contributes.commands`

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
- No runtime dependencies beyond VS Code types and Node built-ins