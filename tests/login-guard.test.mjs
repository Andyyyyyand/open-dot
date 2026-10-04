import test from "node:test";
import assert from "node:assert/strict";
import { loginOriginProblem as p } from "../src/server/login-guard.ts";

test("allows the real site, www and subdomains over https", () => {
  assert.equal(p("https://github.com/login", "github.com"), null);
  assert.equal(p("https://www.github.com/login", "github.com"), null);
  assert.equal(p("https://login.github.com/", "github.com"), null);
  assert.equal(p("https://github.com/login", "https://www.github.com/x"), null);
});
test("blocks look-alike and attacker hosts", () => {
  for (const url of [
    "https://evil.com/",
    "https://github.com.evil.com/",
    "https://evilgithub.com/",
    "https://github.com@evil.com/",
    "https://xn--gthub-bva.com/",
    "https://evil.com/?https://github.com",
    "https://github.co/",
  ]) assert.ok(p(url, "github.com"), url);
});
test("blocks http, non-web and unparsable pages", () => {
  for (const url of ["http://github.com/", "about:blank", "data:text/html,<input type=password>", "file:///x", "", "not a url"])
    assert.ok(p(url, "github.com"), url);
});
test("blocks bogus stored sites", () => {
  assert.ok(p("https://com/", "com"));
  assert.ok(p("https://localhost/", "localhost"));
});
