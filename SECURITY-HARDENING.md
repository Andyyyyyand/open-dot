# Security hardening notes

Changes in this branch, and what they do and do not protect against.

## What changed

1. Saved passwords are only typed into the site they belong to (`src/server/login-guard.ts`, `computer/index.ts`).
   The open page must be HTTPS and be the stored site or one of its subdomains. The check uses the stored site,
   not the text the model passed to `sign_in`, so a prompt-injected agent can no longer open a look-alike page
   and have the bank password typed there.
2. `sign_in` and `run_on_my_computer` are locked (`locked: true`): rules can forbid them, but a rule or an
   "Always allow" click can never make them run without a fresh approval. The button is hidden for them.
3. Request filter (`src/proxy.ts`): rejects unexpected Host headers (DNS rebinding), cross-site and cross-origin
   state changes, cross-site reads of the API, and framing of the app (clickjacking of the Approve buttons).
4. Password lookup no longer matches in the reverse direction (a query of "com" selected every .com credential).
5. Vault: on macOS, if the Keychain cannot be used the app now refuses instead of silently storing the key in a
   file beside the database (opt in with `DOTS_ALLOW_FILE_KEY=1`). The key is validated as 32 bytes of hex.
   The data directory is created owner-only (0700).

## Residual risks (not fixed here)

- Any process running as you can read the Keychain item with the `security` command, and the browser profiles
  (cookies and sessions) are not encrypted. Use FileVault, lock the Mac, and do not approve
  `run_on_my_computer` commands you do not fully understand.
- `run_on_my_computer` still runs bash in your home folder with the app's environment (API keys included), unsandboxed.
  Leave local access off unless you need it.
- The reviewer that applies your rules is a small model. Prefer "ask" rules over "allow" rules for anything that matters.
- Reading mail and web pages automatically is the main way hostile instructions reach the agent.
- The Keychain key is passed to `/usr/bin/security` as an argument once, when it is first created.

## Tests

`pnpm test` runs the login-guard tests (Node 22).
