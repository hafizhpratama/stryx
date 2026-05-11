// The exported helper redirects to its parameter with no allow-list
// check. `loginRedirect`'s parameter `target` flows directly to the
// redirect URL argument.

import { NextResponse } from "next/server";

export function loginRedirect(target: string) {
  return NextResponse.redirect(target);
}
