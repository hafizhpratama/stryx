// Same shape as bad.ts but reads from env. Stryx should report zero findings.

export const config = {
  anthropicKey: process.env.ANTHROPIC_API_KEY,
  awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
  stripeKey: process.env.STRIPE_SECRET_KEY,
  githubToken: process.env.GITHUB_TOKEN,
};

export function callAnthropic() {
  return fetch("https://api.anthropic.com/v1/messages", {
    headers: {
      "x-api-key": config.anthropicKey ?? "",
    },
  });
}
