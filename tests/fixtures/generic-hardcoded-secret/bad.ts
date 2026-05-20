// Configuration with secrets baked into source.
// Stryx should flag every literal below as `generic/hardcoded-secret`.

export const config = {
  anthropicKey: "sk-ant-api03-FIXTUREFAKEFIXTUREFAKEFIXTUR",
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  stripeKey: "sk_test_FIXTUREFAKEKEYFIXTURE",
  githubToken: "ghp_FIXTUREFAKEKEYFIXTUREFAKEKEYFIXTURE0",
};

export function callAnthropic() {
  return fetch("https://api.anthropic.com/v1/messages", {
    headers: {
      "x-api-key": "sk-ant-api03-FIXTUREFAKEFIXTURELIVEFAKEFIX",
    },
  });
}
