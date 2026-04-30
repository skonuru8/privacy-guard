# Privacy Guard — VS Code Extension

AI-powered privacy checks built into your development workflow.

## Features

### 🔍 Pre-Commit Privacy Check
Before you commit, run a privacy scan on your staged changes. Privacy Guard analyzes your git diff and flags:
- PII being collected or logged (names, emails, location, IDs)
- Sensitive data exposed in transit or storage
- New third-party calls that share user data
- Missing consent checks
- Relevant GDPR / CCPA violations

Accessible from the **Source Control panel toolbar** or via Command Palette (`Ctrl+Shift+P` → `Privacy Guard: Check Staged Changes`).

### 📦 Dependency Privacy Scanner
Score every package in your `package.json` for privacy risk. Each package gets:
- A risk score: `SAFE`, `CAUTION`, or `HIGH RISK`
- A plain-English reason
- The relevant regulation (GDPR Article / CCPA Section)
- A suggested alternative where applicable

Accessible from the **Privacy Guard sidebar** or Command Palette (`Privacy Guard: Scan Dependencies`).

---

## Setup

### 1. Clone and install
```bash
git clone https://github.com/consenterra/privacy-guard
cd privacy-guard
npm install
```

### 2. Open in VS Code
```bash
code .
```

### 3. Press F5
This launches the **Extension Development Host** — a new VS Code window with the extension running. Open any project in that window to test it.

### 4. Add your API key
In the Extension Development Host window:
- `Ctrl+Shift+P` → `Preferences: Open Settings`
- Search `privacyGuard.apiKey`
- Paste your [Anthropic API key](https://console.anthropic.com)

---

## Project Structure

```
src/
  extension.ts       — entry point, registers commands
  diffScanner.ts     — git diff reader + pre-commit analysis
  packageScanner.ts  — package.json reader + dependency scoring
  webviewPanel.ts    — sidebar UI (HTML/CSS rendered in VS Code)
  claude.ts          — Anthropic API client
```

---

## Contributing

Each feature is isolated in its own file. To add a new scanner:
1. Create `src/yourScanner.ts` with a function that returns structured JSON
2. Register a new command in `extension.ts`
3. Add a new render method in `webviewPanel.ts`
4. Add the command to `package.json` under `contributes.commands`

### Build
```bash
npm run compile       # one-time build
npm run watch         # auto-compile on save
```

### Package as .vsix
```bash
npm run package
# outputs privacy-guard-x.x.x.vsix — install via "Extensions: Install from VSIX"
```

---

## Tech Stack

- **TypeScript** + VS Code Extension API
- **Anthropic Claude** (`claude-sonnet-4-20250514`) via direct HTTPS — no backend needed
- No external dependencies beyond VS Code types

---

## Notes for Hackathon Demo

- The API key is stored in VS Code user settings — flag to judges that in production this would use a secrets manager or team-shared auth
- Diffs over 8000 characters are truncated before sending to the API
- Both features work offline for the UI; only the analysis calls require internet
