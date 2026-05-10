// The wrapper signature looks like real auth scaffolding, but the
// body is a no-op. AI-generated wrappers commonly leave a TODO here
// and ship to production unprotected.

type Handler = (req: Request) => Promise<Response>;

export function withAuth<H extends Handler>(handler: H): H {
  // TODO: add session check
  return handler;
}
