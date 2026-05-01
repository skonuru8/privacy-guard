import * as vscode from "vscode";
import * as https from "https";
import * as fs from "fs";
import * as path from "path";
import { callAI, getAIConfig } from "./aiClient";

/**
 * System prompt that instructs the AI to act as a privacy expert
 * and return a strictly structured JSON array for package scoring.
 * Now also requests the privacy policy URL for each package.
 */
const SYSTEM_PROMPT = `You are a privacy expert analyzing npm dependencies.

Score each package for privacy risk based on:
- Data collection and tracking capabilities
- Known third-party data sharing
- Analytics or fingerprinting behavior
- Historical privacy violations or incidents
- GDPR / CCPA compliance concerns

For each package, also provide the URL to its privacy policy page if one exists.
Use the provided package reference data first when it contains a Privacy Policy URL for that package.
If the package reference data does not contain a Privacy Policy URL, use your own knowledge to provide one only when you are confident it exists.
If no privacy policy URL can be found, set privacyPolicyUrl to null.

Respond ONLY with a raw JSON array — no markdown, no explanation:
[
  {
    "name": "package-name",
    "version": "x.x.x",
    "score": "SAFE" | "CAUTION" | "HIGH_RISK",
    "reason": "one sentence explanation",
    "alternative": "suggested replacement package name or null",
    "regulation": "relevant GDPR article or CCPA section or null",
    "privacyPolicyUrl": "https://example.com/privacy or null"
  }
]`;

/** Consenterra API configuration */
const CONSENTERRA_API_URL = "https://api.consenterra.ai/functions/v1/prixplainer-scan";
const CONSENTERRA_API_KEY = "ct_live_5vk9zt0niv9bqfrnoo9b3npgxcqmhyap";
const CONSENTERRA_TIMEOUT_MS = 240000;

/** Privacy report returned by Consenterra's prixplainer-scan endpoint. */
export interface ConsenTerraReport {
  ok?: boolean;
  statusCode?: number;
  error?: string;
  rawResponse?: string;
  data?: {
    domain?: string;
    score?: number;
    grade?: string;
    risk_level?: string;
    summary?: string;
    clause_count?: number;
    risk_breakdown?: Record<string, number>;
    clauses?: any[];
    [key: string]: any;
  };
  grade?: string;
  score?: number;
  risk_level?: string;
  summary?: string;
  clauses?: any[];
  [key: string]: any;
}

/** Privacy risk score for a single npm package. */
export interface PackageResult {
  name: string;
  version: string;
  score: "SAFE" | "CAUTION" | "HIGH_RISK";
  reason: string;
  alternative: string | null;
  regulation: string | null;
  privacyPolicyUrl: string | null;
  privacyReport: ConsenTerraReport | null;
  debugLlmRequest?: string;
  debugLlmResponse?: string;
}

function readPackagesInfo(): string {
  const candidates = [
    path.join(__dirname, "packages_info.md"),
    path.join(__dirname, "..", "src", "packages_info.md"),
    path.join(__dirname, "..", "packages_info.md"),
  ];

  for (const filePath of candidates) {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, "utf8");
    }
  }

  console.warn("Privacy Guard: packages_info.md was not found; continuing without package reference data");
  return "";
}

/**
 * Calls the Consenterra prixplainer-scan API to analyze a privacy policy URL.
 *
 * @param url - The privacy policy URL to scan
 * @returns The scan result with grade, score, clauses, or raw error details
 */
async function fetchConsenTerraReport(url: string): Promise<ConsenTerraReport | null> {
  return new Promise((resolve) => {
    const body = JSON.stringify({ url });
    const parsed = new URL(CONSENTERRA_API_URL);

    console.log(`Privacy Guard: Fetching Consenterra report for ${url}`);

    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname,
        method: "POST",
        timeout: CONSENTERRA_TIMEOUT_MS,
        headers: {
          "Content-Type": "application/json",
          "apikey": CONSENTERRA_API_KEY,
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const result = JSON.parse(data);
            if (res.statusCode === 200) {
              console.log(`Privacy Guard: Consenterra report fetched for ${url}`);
              resolve({ ok: true, statusCode: res.statusCode, ...result });
            } else {
              console.warn(`Consenterra API returned ${res.statusCode} for ${url}:`, data);
              resolve({
                ok: false,
                statusCode: res.statusCode,
                error: `Consenterra API returned HTTP ${res.statusCode}`,
                rawResponse: data,
                ...result,
              });
            }
          } catch {
            console.warn(`Failed to parse Consenterra response for ${url}`);
            resolve({
              ok: false,
              statusCode: res.statusCode,
              error: "Failed to parse Consenterra API response",
              rawResponse: data,
            });
          }
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      console.warn(`Consenterra API request timed out after ${CONSENTERRA_TIMEOUT_MS}ms for ${url}`);
      resolve({
        ok: false,
        error: `Consenterra API request timed out after ${CONSENTERRA_TIMEOUT_MS / 1000} seconds`,
      });
    });
    req.on("error", (err) => {
      console.warn(`Consenterra API request failed for ${url}:`, err.message);
      resolve({
        ok: false,
        error: `Consenterra API request failed: ${err.message}`,
      });
    });
    req.write(body);
    req.end();
  });
}

/**
 * Reads the workspace's package.json, extracts all dependencies,
 * asks the configured AI model to score each one for privacy risk,
 * and then fetches Consenterra privacy reports for packages that
 * have a privacy policy URL.
 *
 * Merges both `dependencies` and `devDependencies` into a single list
 * before sending to the model.
 *
 * @returns An array of PackageResult, one per dependency
 * @throws If no package.json is found or the workspace has no dependencies
 */
export async function scanPackages(): Promise<PackageResult[]> {
  console.log("Privacy Guard: Starting package scan");

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    console.warn("Privacy Guard: Package scan failed because no workspace is open");
    throw new Error("No workspace open");
  }

  const pkgPath = path.join(workspaceFolders[0].uri.fsPath, "package.json");
  console.log(`Privacy Guard: Looking for package.json at ${pkgPath}`);

  if (!fs.existsSync(pkgPath)) {
    console.warn("Privacy Guard: Package scan failed because package.json was not found");
    throw new Error("No package.json found in workspace root");
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  if (Object.keys(deps).length === 0) {
    console.warn("Privacy Guard: Package scan failed because package.json has no dependencies");
    throw new Error("No dependencies found in package.json");
  }

  console.log(`Privacy Guard: Found ${Object.keys(deps).length} dependencies to scan`);

  /** Format each dep as "name@version" for the prompt */
  const depList = Object.entries(deps)
    .map(([name, version]) => `${name}@${version}`)
    .join("\n");
  const packageInfoReference = readPackagesInfo();
  const packageInfoBlock = packageInfoReference
    ? `Complete packages_info.md content:\n\n${packageInfoReference}`
    : "Complete packages_info.md content: File not found or empty.";

  const { provider, apiKey } = getAIConfig();
  console.log(`Privacy Guard: Requesting package risk scores from ${provider}`);
  const userMessage = `${packageInfoBlock}\n\nScore these npm packages for privacy risk:\n\n${depList}`;

  const response = await callAI(
    provider,
    apiKey,
    SYSTEM_PROMPT,
    userMessage
  );

  console.log("Privacy Guard: AI package risk response received");

  const cleaned = response.replace(/```json|```/g, "").trim();
  const results = JSON.parse(cleaned) as PackageResult[];
  if (results.length > 0) {
    results[0].debugLlmRequest = `System prompt:\n${SYSTEM_PROMPT}\n\nUser message:\n${userMessage}`;
    results[0].debugLlmResponse = response;
  }

  console.log(`Privacy Guard: Parsed ${results.length} package risk results`);

  // Initialize privacyReport as null for all results
  for (const r of results) {
    r.privacyReport = null;
  }

  // Fetch Consenterra reports for packages that have a privacy policy URL
  const reportsToFetch = results.filter((r) => r.privacyPolicyUrl);
  console.log(`Privacy Guard: Found ${reportsToFetch.length} privacy policy URLs to scan`);

  if (reportsToFetch.length > 0) {
    const reportPromises = reportsToFetch.map(async (r) => {
      r.privacyReport = await fetchConsenTerraReport(r.privacyPolicyUrl!);
      const reportData = r.privacyReport?.data ?? r.privacyReport;
      console.log(`Privacy Guard: Consenterra report for ${r.name}@${r.version} - Grade: ${reportData?.grade}, Score: ${reportData?.score}`);
    });
    await Promise.all(reportPromises);
  }

  console.log("Privacy Guard: Package scan completed");

  return results;
}
