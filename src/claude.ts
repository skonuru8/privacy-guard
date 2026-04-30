import * as https from "https";

export async function callClaude(
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

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.anthropic.com",
        path: "/v1/messages",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) {
              reject(new Error(parsed.error.message));
            } else {
              resolve(parsed.content[0].text);
            }
          } catch {
            reject(new Error("Failed to parse API response"));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
