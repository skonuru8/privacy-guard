/**
 * fileCache.ts
 *
 * Caches per-file scan results in .git/privacy-guard-cache.json.
 * Key: sha256 hash of the file's diff content.
 * Value: the DiffResult from the last scan.
 *
 * Stored inside .git/ so it is never committed and is automatically
 * scoped to the repository. No .gitignore entry needed.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { DiffResult } from "./diffScanner";

/** Shape of the JSON file written to disk. */
interface CacheStore {
  version: number;
  entries: Record<string, DiffResult>;
}

const CACHE_VERSION = 1;
const CACHE_FILENAME = "privacy-guard-cache.json";

/**
 * Returns the absolute path to the cache file inside .git/.
 * Returns null if no .git directory is found at the given root.
 *
 * @param repoRoot - Absolute path to the repository root
 */
function cachePath(repoRoot: string): string | null {
  const gitDir = path.join(repoRoot, ".git");
  if (!fs.existsSync(gitDir)) return null;
  return path.join(gitDir, CACHE_FILENAME);
}

/**
 * Loads the cache from disk. Returns an empty store if the file
 * doesn't exist, is unreadable, or has an incompatible version.
 *
 * @param repoRoot - Absolute path to the repository root
 */
function loadCache(repoRoot: string): CacheStore {
  const p = cachePath(repoRoot);
  if (!p) return { version: CACHE_VERSION, entries: {} };

  try {
    const raw = fs.readFileSync(p, "utf8");
    const parsed = JSON.parse(raw) as CacheStore;
    if (parsed.version !== CACHE_VERSION) {
      return { version: CACHE_VERSION, entries: {} };
    }
    return parsed;
  } catch {
    return { version: CACHE_VERSION, entries: {} };
  }
}

/**
 * Writes the cache store to disk.
 * Silently swallows write errors so a cache failure never breaks a commit.
 *
 * @param repoRoot - Absolute path to the repository root
 * @param store    - The cache store to persist
 */
function saveCache(repoRoot: string, store: CacheStore): void {
  const p = cachePath(repoRoot);
  if (!p) return;

  try {
    fs.writeFileSync(p, JSON.stringify(store, null, 2), "utf8");
  } catch {
    // Cache write failure is non-fatal — scan will just re-run next time
  }
}

/**
 * Computes a sha256 hash of the diff content for use as a cache key.
 * Two identical diffs will always produce the same hash.
 *
 * @param diffContent - Raw diff text for a single file
 */
export function hashDiff(diffContent: string): string {
  return crypto.createHash("sha256").update(diffContent).digest("hex");
}

/**
 * Looks up a cached DiffResult for the given diff hash.
 * Returns null on a cache miss.
 *
 * @param repoRoot  - Absolute path to the repository root
 * @param diffHash  - sha256 hash of the file's diff content
 */
export function getCached(repoRoot: string, diffHash: string): DiffResult | null {
  const store = loadCache(repoRoot);
  return store.entries[diffHash] ?? null;
}

/**
 * Stores a DiffResult in the cache under the given diff hash.
 * Only HIGH and MEDIUM results are cached — LOW results are cheap
 * to recompute and caching them would inflate the cache file for no benefit.
 *
 * @param repoRoot  - Absolute path to the repository root
 * @param diffHash  - sha256 hash of the file's diff content
 * @param result    - The DiffResult to store
 */
export function setCached(repoRoot: string, diffHash: string, result: DiffResult): void {
  if (result.overall_risk === "LOW") return;

  const store = loadCache(repoRoot);
  store.entries[diffHash] = result;
  saveCache(repoRoot, store);
}

/**
 * Removes all entries from the cache for the given repository.
 * Called if the user wants a full rescan.
 *
 * @param repoRoot - Absolute path to the repository root
 */
export function clearCache(repoRoot: string): void {
  saveCache(repoRoot, { version: CACHE_VERSION, entries: {} });
}
