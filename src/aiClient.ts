import * as https from "https";
import * as vscode from "vscode";

/** Supported AI providers. Add new entries here to extend support. */
export type AIProvider = "anthropic" | "openai" | "openrouter";

/**
 * Reads the configured AI provider and its corresponding API key from VS Code settings.
 * Each provider has its own dedicated key field so users can store all keys simultaneously
 * and switch providers without re-entering credentials.
 *
 * @returns An object with the resolved provider and apiKey
 * @throws If the API key for the selected provider is not set
 */
export function getAIConfig(): { provider: AIProvider; apiKey: string } {
  const config = vscode.workspace.getConfiguration("privacyGuard");
  const provider = config.get<AIProvider>("provider", "anthropic");

  const keyMap: Record<AIProvider, string> = {
    anthropic:  config.get<string>("anthropicApiKey", ""),
    openai:     config.get<string>("openaiApiKey", ""),
    openrouter: config.get<string>("openrouterApiKey", ""),
  };

  const apiKey = keyMap[provider];

  if (!apiKey) {
    throw new Error(
      `No API key set for provider "${provider}". ` +
      `Open Settings and configure privacyGuard.${provider}ApiKey.`
    );
  }

  return { provider, apiKey };
}

/**
 * Sends a system prompt + user message to the configured AI provider
 * and returns the text response.
 *
 * Dispatches to the correct provider implementation based on the
 * `provider` argument so callers don't need to know which API is used.
 *
 * @param provider - Which AI provider to call ("anthropic" | "openai" | "openrouter")
 * @param apiKey   - API key for the chosen provider
 * @param systemPrompt - Instructions that define the AI's role and output format
 * @param userMessage  - The actual content to analyze
 * @returns The raw text response from the model
 */
export async function callAI(
  provider: AIProvider,
  apiKey: string,
  systemPrompt: string,
  userMessage: string
): Promise<string> {
  switch (provider) {
    case "anthropic":
      return callAnthropic(apiKey, systemPrompt, userMessage);
    case "openai":
      return callOpenAI(apiKey, systemPrompt, userMessage);
    case "openrouter":
      return callOpenRouter(apiKey, systemPrompt, userMessage);
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

/**
 * Calls the Anthropic Messages API (claude-sonnet-4-20250514).
 * Uses the x-api-key header and anthropic-version required by Anthropic's API.
 *
 * @param apiKey       - Anthropic API key
 * @param systemPrompt - System instructions
 * @param userMessage  - User content to analyze
 * @returns The text content of the first response block
 */
function callAnthropic(
  apiKey: string,
  systemPrompt: string,
  userMessage: string
): Promise<string> {
  const body = JSON.stringify({
    model: "claude-sonnet-4-20250514",
    max_tokens: 2000,
    system: systemPrompt,
    messages: [{ role: "user", content: userMessage }],
  });

  return httpsPost(
    {
      hostname: "api.anthropic.com",
      path: "/v1/messages",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
    },
    body,
    (parsed) => {
      if (parsed.error) throw new Error(parsed.error.message);
      return parsed.content[0].text;
    }
  );
}

/**
 * Calls the OpenAI Chat Completions API (gpt-4o).
 * Uses the Authorization: Bearer header required by OpenAI's API.
 *
 * @param apiKey       - OpenAI API key
 * @param systemPrompt - System instructions passed as a system role message
 * @param userMessage  - User content to analyze
 * @returns The text content of the first choice message
 */
function callOpenAI(
  apiKey: string,
  systemPrompt: string,
  userMessage: string
): Promise<string> {
  const body = JSON.stringify({
    model: "gpt-4o",
    max_tokens: 2000,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
  });

  return httpsPost(
    {
      hostname: "api.openai.com",
      path: "/v1/chat/completions",
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    },
    body,
    (parsed) => {
      if (parsed.error) throw new Error(parsed.error.message);
      return parsed.choices[0].message.content;
    }
  );
}

/**
 * Calls the OpenRouter Chat Completions API.
 * OpenRouter is OpenAI-compatible but routes to many models (e.g. mistral, llama, gemini).
 * Requires an HTTP-Referer header to identify the calling app.
 * The model is read from the optional `privacyGuard.openRouterModel` setting,
 * defaulting to "mistralai/mistral-7b-instruct" which is free-tier eligible.
 *
 * @param apiKey       - OpenRouter API key (sk-or-...)
 * @param systemPrompt - System instructions passed as a system role message
 * @param userMessage  - User content to analyze
 * @returns The text content of the first choice message
 */
function callOpenRouter(
  apiKey: string,
  systemPrompt: string,
  userMessage: string
): Promise<string> {
  const config = vscode.workspace.getConfiguration("privacyGuard");
  const model = config.get<string>("openRouterModel", "mistralai/mistral-7b-instruct");

  const body = JSON.stringify({
    model,
    max_tokens: 2000,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
  });

  return httpsPost(
    {
      hostname: "openrouter.ai",
      path: "/api/v1/chat/completions",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "HTTP-Referer": "https://github.com/consenterra/privacy-guard",
        "X-Title": "Privacy Guard",
      },
    },
    body,
    (parsed) => {
      if (parsed.error) throw new Error(parsed.error.message);
      return parsed.choices[0].message.content;
    }
  );
}


/**
 * Shared HTTPS POST helper used by all provider implementations.
 * Handles request construction, response buffering, JSON parsing,
 * and error propagation in one place.
 *
 * @param options       - Partial HTTPS request options (hostname, path, extra headers)
 * @param body          - JSON-serialized request body string
 * @param extractText   - Provider-specific function to pull the text out of the parsed response
 * @returns The extracted text from the API response
 */
function httpsPost(
  options: { hostname: string; path: string; headers: Record<string, string> },
  body: string,
  extractText: (parsed: any) => string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: options.hostname,
        path: options.path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          ...options.headers,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            resolve(extractText(parsed));
          } catch (e: any) {
            reject(new Error(`Failed to parse API response: ${e.message}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
