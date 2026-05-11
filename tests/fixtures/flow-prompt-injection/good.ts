// Single-file prompt-injection good fixture — every handler must
// produce zero findings under `flow/prompt-injection`.

import type { NextRequest } from "next/server";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";

const openai = new OpenAI();
const anthropic = new Anthropic();

// GOOD 1: hardcoded user content — no body taint, no flow.
export async function hardcoded() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: "What is the capital of France?" },
    ],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}

// GOOD 2: prompt sourced from env vars — operator-controlled, not
// attacker-controlled.
export async function envPrompt() {
  const seed = process.env.AGENT_SEED ?? "Hello";
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: seed }],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}

// GOOD 3: Anthropic with a fully hardcoded prompt — no body flow.
export async function hardcodedAnthropic() {
  const msg = await anthropic.messages.create({
    model: "claude-3-5-sonnet-latest",
    max_tokens: 1024,
    messages: [
      { role: "user", content: "Summarise the latest TC39 proposals." },
    ],
  });
  return Response.json({ reply: msg.content[0].text });
}

// GOOD 4: body data used elsewhere (DB read) but not in the prompt.
// The prompt is independent of the request body, so no prompt
// injection surface.
export async function bodyButNotPrompt(req: NextRequest) {
  const { sessionId } = await req.json();
  // sessionId is body-tainted but only used as a DB lookup key, not
  // as prompt content.
  void sessionId;
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Generate a greeting." },
      { role: "user", content: "Say hello." },
    ],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}

// GOOD 5: non-LLM call shape that resembles `.create(...)`. Must
// not fire — recogniser is provider-name-anchored
// (`chat.completions.create` / `responses.create` /
// `messages.create`), not bare `.create(...)`.
export async function notAnLlm(req: NextRequest) {
  const { name } = await req.json();
  // prisma.user.create looks superficially like an LLM SDK call, but
  // the path doesn't match any provider shape — the prompt-injection
  // rule must stay silent. (The unvalidated-body-to-db rule fires
  // here, which is the correct rule for this flow.)
  return Response.json({ name });
}
