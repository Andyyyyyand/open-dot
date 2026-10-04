import { NextResponse, type NextRequest } from "next/server";

// Open Dot has no login screen: the local server trusts whoever can reach it. This filter makes sure that
// "whoever" is only the app window or a tab the user opened on this machine, and not a web page that merely
// happens to be open in the user's browser (cross-site requests, DNS rebinding, clickjacking of approval cards).

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function allowedHostnames(): Set<string> {
  const hosts = new Set(LOCAL_HOSTS);
  try {
    if (process.env.DOTS_PUBLIC_URL) hosts.add(new URL(process.env.DOTS_PUBLIC_URL).hostname);
  } catch {
    // ignore a malformed DOTS_PUBLIC_URL; the local hosts above still work
  }
  return hosts;
}

const hostnameOf = (hostHeader: string) => {
  try {
    return new URL(`http://${hostHeader}`).hostname;
  } catch {
    return "";
  }
};

const deny = (why: string) => new NextResponse(`Forbidden: ${why}`, { status: 403, headers: { "Content-Type": "text/plain" } });

export function proxy(req: NextRequest) {
  const allowed = allowedHostnames();

  // DNS rebinding: a hostile domain pointed at 127.0.0.1 still sends its own name in Host.
  if (!allowed.has(hostnameOf(req.headers.get("host") ?? ""))) return deny("unexpected Host header");

  const site = req.headers.get("sec-fetch-site"); // sent by every modern browser; absent for curl and the like
  const mode = req.headers.get("sec-fetch-mode");
  const safeMethod = req.method === "GET" || req.method === "HEAD";

  if (!safeMethod) {
    // Anything that changes state (server actions, approvals, input to the live browser) must come from our own pages.
    if (site && site !== "same-origin" && site !== "none") return deny("cross-site request");
    const origin = req.headers.get("origin");
    if (origin && origin !== "null") {
      let originHost = "";
      try {
        originHost = new URL(origin).hostname;
      } catch {
        // falls through to the denial below
      }
      if (!allowed.has(originHost)) return deny("cross-origin request");
    } else if (origin === "null") {
      return deny("opaque origin");
    }
  } else if (site === "cross-site" && mode !== "navigate") {
    // Other sites may not read our API or load it as a script/image. Plain top-level navigations stay allowed
    // because the Composio sign-in sends the browser back to /api/composio/oauth (protected by PKCE).
    return deny("cross-site read");
  }

  const res = NextResponse.next();
  res.headers.set("Content-Security-Policy", "frame-ancestors 'self'"); // no clickjacking of the Approve buttons
  res.headers.set("X-Frame-Options", "SAMEORIGIN");
  res.headers.set("X-Content-Type-Options", "nosniff");
  res.headers.set("Referrer-Policy", "no-referrer");
  return res;
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
