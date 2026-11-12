# Team Dashboard audit

I found six security issues. The member-name heading was already safe
because it used textContent.

## Findings

| Finding | Priority | Source-to-sink path | Attack payload |
|---|---|---|---|
| Search XSS | 1 — High | location.search → q → renderSearch() → innerHTML | `<img src=x onerror=alert(1)>` |
| Stored bio XSS | 2 — High potential | member.bio → renderMembers() → renderMember() → insertAdjacentHTML | `<img src=x onerror=alert(2)>` |
| Prototype pollution | 3 — High potential | settings JSON → applySettings() → JSON.parse() → deepMerge() → Object.prototype | `{"theme":"dark","__proto__":{"isAdmin":true}}` |
| Button-code injection | 4 — Medium potential | member.name → renderMembers() → renderMember() → onclick attribute | `x') ; alert(4) ; ('` |
| Unsafe profile link | 5 — Medium potential | member.website → renderMembers() → renderMember() → link.href | `javascript:alert(3)` |
| Unsafe config parsing | 6 — Medium potential | config text → parseConfig() → JSON.parse() → unchecked fields | `{"title":"oops` |

I put search first because someone can attack it directly through the URL.
Bios and settings could affect other users or shared state. The button
and link attacks require a click.

The member and settings data are fixed fixtures in this demo, so those
issues are latent until real untrusted data reaches them. Config parsing
is also latent: init() does not call it. The harness tests all six paths.

## Fixes and confirmation

| Finding | Fix | Automated replay result |
|---|---|---|
| Search | Build the strong element and use textContent. | PASS: literal text; no image element. |
| Bio | Sanitize with a restricted DOMPurify allow-list. | PASS: attack markup removed; formatting preserved. |
| Pollution | Validate settings, block dangerous keys at every level, copy own keys, and use null-prototype objects. | PASS: ({}).isAdmin stayed undefined. |
| Button | Use addEventListener instead of an onclick string. | PASS: no inline onclick; the name stayed data. |
| Profile link | Allow only HTTP and HTTPS URLs. | PASS: the javascript: URL received no href. |
| Config | Use try/catch and validate the object and field types. | PASS: malformed input returned null without throwing. |

All six checks passed in the automated JSDOM test. verify.js was unchanged.

Browser replay: pending.