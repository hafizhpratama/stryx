// Single-file prompt-injection fixture for `flow/prompt-injection`
// slice 1. Each handler is an independent case the rule must flag.

import type { NextRequest } from "next/server";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";

const openai = new OpenAI();
const anthropic = new Anthropic();

// CASE 1: classic body→OpenAI chat user-content.
export async function POST(req: NextRequest) {
  const { message } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: message }],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}

// CASE 2: system prompt + body in user role — the "I added a system
// prompt so I'm safe" pattern. Still injectable.
export async function summarise(req: NextRequest) {
  const { text } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Summarise the user's text." },
      { role: "user", content: text },
    ],
  });
  return Response.json({ summary: completion.choices[0].message.content });
}

// CASE 3: OpenAI Responses API (`responses.create`) with the bare
// `input` field — the newest OpenAI SDK shape.
export async function ask(req: NextRequest) {
  const body = await req.json();
  const r = await openai.responses.create({
    model: "gpt-4o-mini",
    input: body.prompt,
  });
  return Response.json({ output: r.output_text });
}

// CASE 4: Anthropic — same shape, different SDK.
export async function claudeChat(req: NextRequest) {
  const { question } = await req.json();
  const msg = await anthropic.messages.create({
    model: "claude-3-5-sonnet-latest",
    max_tokens: 1024,
    messages: [{ role: "user", content: question }],
  });
  return Response.json({ reply: msg.content[0].text });
}

// CASE 5: template-literal wrapping does NOT save you — the user
// content is still attacker-controlled past the template prefix.
// (The "good" defence requires structural separation + explicit
// instruction-vs-data semantics; mere wrapping in a fixed prefix is
// the classic naive attempt.)
export async function naiveWrap(req: NextRequest) {
  const { input } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content: `Please answer the following user question: ${input}`,
      },
    ],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}
