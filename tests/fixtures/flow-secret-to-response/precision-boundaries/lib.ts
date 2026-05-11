// Precision-boundary fixture for the post-OSS-validation refinement
// (2026-05-11). Each function pins a specific suppression rule:
//   - `publicEmbed`     — public/embed prefix suppression (fires zero)
//   - `validatorOutput` — validator-output suppression    (fires zero)
//   - `compoundLeak`    — compound name from neither      (still fires)
//   - `apiKeyFromEnv`   — env source, no public prefix     (still fires)
//
// Together these prove the refinement neither under-suppresses (FPs
// from OSS validation gone) nor over-suppresses (true positives
// still fire when neither boundary triggers).

declare function embedTokens(): Promise<{
  publicToken: string;
  embedToken: string;
}>;

declare const userSchema: {
  parse(x: unknown): { sessionToken: string; apiToken: string };
};

declare function getStoredAdminSecrets(): Promise<{
  sessionToken: string;
  refreshToken: string;
}>;

// CASE 1: public-prefix suppression. `publicToken` / `embedToken`
// reach `Response.json` — but their names signal intentional-public.
// Expected: zero findings.
export async function publicEmbed() {
  const { publicToken, embedToken } = await embedTokens();
  return Response.json({ publicToken, embedToken });
}

// CASE 2: validator-output suppression. `sessionToken` / `apiToken`
// reach `Response.json` — but the destructure init traces through a
// zod-style parser, so the values are user input being echoed, not
// stored secrets. Expected: zero findings.
export async function validatorOutput(req: Request) {
  const rawBody = await req.text();
  const { sessionToken, apiToken } = userSchema.parse(JSON.parse(rawBody));
  return Response.json({ sessionToken, apiToken });
}

// CASE 3: non-public, non-validator. `sessionToken` / `refreshToken`
// from a server-side helper that reads from storage. Expected: at
// least one finding.
export async function compoundLeak() {
  const { sessionToken, refreshToken } = await getStoredAdminSecrets();
  return Response.json({ sessionToken, refreshToken });
}

// CASE 4: env-source, no public prefix. Still the canonical bad
// pattern. Expected: finding.
export async function apiKeyFromEnv() {
  const apiKey = process.env.STRIPE_SECRET_KEY;
  return Response.json({ apiKey });
}
