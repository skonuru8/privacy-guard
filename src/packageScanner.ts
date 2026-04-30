import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { callClaude } from "./claude";

const SYSTEM_PROMPT = `You are a privacy expert analyzing npm dependencies.

Score each package for privacy risk based on:
- Data collection and tracking capabilities
- Known third-party data sharing
- Analytics or fingerprinting behavior
- Historical privacy violations or incidents
- GDPR / CCPA compliance concerns

Respond ONLY with a raw JSON array — no markdown, no explanation:
[
  {
    "name": "package-name",
    "version": "x.x.x",
    "score": "SAFE" | "CAUTION" | "HIGH_RISK",
    "reason": "one sentence explanation",
    "alternative": "suggested replacement package name or null",
    "regulation": "relevant GDPR article or CCPA section or null"
  }
]`;

export interface PackageResult {
  name: string;
  version: string;
  score: "SAFE" | "CAUTION" | "HIGH_RISK";
  reason: string;
  alternative: string | null;
  regulation: string | null;
}

export async function scanPackages(apiKey: string): Promise<PackageResult[]> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    throw new Error("No workspace open");
  }

  const pkgPath = path.join(workspaceFolders[0].uri.fsPath, "package.json");
  if (!fs.existsSync(pkgPath)) {
    throw new Error("No package.json found in workspace root");
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  if (Object.keys(deps).length === 0) {
    throw new Error("No dependencies found in package.json");
  }

  const depList = Object.entries(deps)
    .map(([name, version]) => `${name}@${version}`)
    .join("\n");

  const response = await callClaude(
    apiKey,
    SYSTEM_PROMPT,
    `Score these npm packages for privacy risk:\n\n${depList}`
  );

  const cleaned = response.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned) as PackageResult[];
}
