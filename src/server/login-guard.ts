// Pure helpers (no I/O, no "server-only") so they can be unit tested on their own.

const stripWww = (h: string) => h.replace(/^www\./, "").toLowerCase();

/** Hostname of a saved site entry such as "github.com" or "https://github.com/login". */
export function savedHost(site: string): string {
  try {
    return stripWww(new URL(site.includes("://") ? site : `https://${site}`).hostname);
  } catch {
    return stripWww(site.trim());
  }
}

/**
 * Decides whether a saved password may be typed into the page that is open right now.
 * The check is made against the page's real URL and the STORED site, never against anything the model supplied:
 * a prompt-injected agent could otherwise open evil.com and ask for the bank's password to be typed there.
 * Returns null when it is safe, or a message for the model when it is not.
 */
export function loginOriginProblem(pageUrl: string, storedSite: string): string | null {
  let u: URL;
  try {
    u = new URL(pageUrl);
  } catch {
    return "Refusing to type the saved password: the page address could not be read. Open the site's real sign-in page first.";
  }
  const want = savedHost(storedSite);
  if (!want || !want.includes(".")) return "Refusing to type the saved password: the saved site is not a valid domain. Ask the user to fix it under Passwords.";
  if (u.protocol !== "https:") {
    return `Refusing to type the saved password into a page that is not HTTPS (${u.protocol}//${u.hostname}). Open the real sign-in page for ${want}.`;
  }
  const have = stripWww(u.hostname);
  if (have === want || have.endsWith(`.${want}`)) return null;
  return `Refusing to type the saved password: the open page is ${have}, but this password belongs to ${want}. Open ${want}'s own sign-in page first.`;
}
