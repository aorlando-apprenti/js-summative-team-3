// app.js — the profile handler under test.
//
// A profile page fetches a user record and renders it. A resolved fetch only
// tells you bytes arrived; it tells you nothing about whether those bytes form
// the object this code expects. This starter trusts the parsed shape completely:
// it parses the body and reaches straight into `data.user.name` and
// `data.user.roles` without a single check.
//
// That works the first hundred times, while the API returns the shape you
// assumed. It breaks the moment the API returns an error envelope, a proxy
// truncates the stream, or a field comes back as the wrong type — the handler
// throws inside the render path and the page goes blank, or it mis-uses a
// wrongly typed value and feeds corrupt data downstream toward a DOM write.
//
// `verify.js` runs a well-formed body plus three bad ones through loadProfile().
// In this starter the bad bodies make it throw or return a corrupt profile —
// the harness reports the vulnerability as REPRODUCED.

// A tiny stand-in for a fetch Response, so this lab stays framework- and
// network-free. `text()` returns the raw body; `json()` parses it (and throws
// on malformed JSON, exactly like the real thing).
export function makeResponse(body) {
  return {
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

// Allowed roles.
const ALLOWED_ROLES = ["admin"];

// The defensive handler.
export async function loadProfile(response) {

  // COMPLETE: This is the fix point. Right now the handler trusts the parsed shape:
  //   - it does not wrap the parse to convert a SyntaxError into a safe rejection
  //   - it does not confirm `data.user` exists and is an object before reading it
  //   - it does not check that `name` is a string or `roles` is a string[]
  //   - it does not enforce bounds (name length, allowed roles)
  // Replace the blind property access below with: safeParse -> shape validation
  // (Object.hasOwn for keys, typeof / Array.isArray for types) -> bounds checks,
  // returning { ok: true, profile } or { ok: false, reason } and never throwing.

  // STEP 1: Safe parsing.
  let body;

  try {
    body = await response.text();
  } catch (error) {
    return { ok: false, reason: "Unable to read response body" };
  }

  if (typeof body !== "string" || body.trim() === "") {
    return { ok: false, reason: "Empty or invalid response body" };
  }

  let data;

  try {
    data = JSON.parse(body);
  } catch (error) {
    return { ok: false, reason: "Invalid or malformed JSON" };
  }

  // STEP 2: Shape validation.
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    return { ok: false, reason: "Invalid response structure" };
  }

  if (!Object.hasOwn(data, "user")) {
    return { ok: false, reason: "Missing user object" };
  }

  const user = data.user;

  if (
    user === null ||
    typeof user !== "object" ||
    Array.isArray(user)
  ) {
    return { ok: false, reason: "Invalid user object" };
  }

  if (
    !Object.hasOwn(user, "id") ||
    !Object.hasOwn(user, "name") ||
    !Object.hasOwn(user, "roles")
  ) {
    return { ok: false, reason: "Missing required user fields" };
  }

  if (
    typeof user.id !== "number" ||
    typeof user.name !== "string" ||
    !Array.isArray(user.roles)
  ) {
    return { ok: false, reason: "Invalid user field types" };
  }

  if (!user.roles.every((role) => typeof role === "string")) {
    return { ok: false, reason: "Roles must contain only strings" };
  }

  // STEP 3: Bounds checks.
  if (user.name.length > 100) {
    return { ok: false, reason: "Name exceeds maximum length" };
  }

  if (!user.roles.every((role) => ALLOWED_ROLES.includes(role))) {
    return { ok: false, reason: "Role is not allowed" };
  }

  // All validation passed.
  const profile = {
    id: user.id,
    name: user.name,
    roles: user.roles,
  };

  return { ok: true, profile };
}