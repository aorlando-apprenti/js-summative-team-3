// app.js — the settings merge under test.
//
// An app applies server-sent settings over local defaults using a recursive
// deep-merge. The merge walks the source object and assigns each key onto the
// target. That is the classic prototype-pollution sink: when the source is
// parsed from untrusted JSON and the routine does not screen keys, a single
// crafted payload poisons Object.prototype for the whole page.
//
// JSON.parse itself is safe — it stores "__proto__" as an ordinary own key and
// pollutes nothing. The vulnerability is here, in what this insecure merge does
// with that key afterward: `target["__proto__"] = ...` on a plain object
// triggers the setter and writes through to the shared prototype.
//
// `verify.js` parses a benign payload and two attack payloads, merges each, and
// checks whether Object.prototype got polluted. In this starter it does, so the
// harness reports the attack REPRODUCED.

import { DEFAULT_SETTINGS } from "./defaults.js";

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// parseSettings deserializes the raw body. The parse is harmless on its own.
export function parseSettings(rawText) {
  return JSON.parse(rawText);
}

// The naive recursive merge. There is NO key guard, so "__proto__",
// "constructor", and "prototype" are treated like any other field — including
// inside the recursion, which is how a nested payload reaches the prototype too.
// Fixed below: every recursive call applies the same protections.
function safeDeepMerge(target, source) {
  const result = Object.create(null);

  for (const object of [target, source]) {
    if (!isObject(object)) continue;

    for (const key in object) {
      // Read only this object's own properties.
      if (!Object.hasOwn(object, key)) continue;

      // Block dangerous keys before reading their values.
      if (
        key === "__proto__" ||
        key === "constructor" ||
        key === "prototype"
      ) {
        continue;
      }

      const value = object[key];

      if (isObject(value)) {
        const existing = Object.hasOwn(result, key)
          ? result[key]
          : Object.create(null);

        result[key] = safeDeepMerge(existing, value);
      } else {
        result[key] = value;
      }
    }
  }

  return result;
}

// Apply a parsed settings source over a fresh copy of the defaults.
export function applySettings(parsedSource) {
  // TODO: This is the fix point. This merge is unsafe in two ways:
  //   1. It builds onto a plain {} whose prototype is Object.prototype, so a
  //      "__proto__" / "constructor" key writes through to the shared prototype.
  //   2. It has no key guard at any level, so flat AND nested payloads pollute.
  // Harden it: build the result on Object.create(null); skip any key equal to
  // "__proto__", "constructor", or "prototype" at EVERY recursion level; copy
  // only own keys with Object.hasOwn; and (optionally) strip dangerous keys at
  // parse time with a JSON.parse reviver in parseSettings above.
  return safeDeepMerge(DEFAULT_SETTINGS, parsedSource);
}

const attackTests = [
  {
    name: "flat attack",
    json: '{"__proto__": {"isAdmin": true}}'
  },
  {
    name: "nested attack",
    json: '{"profile": {"__proto__": {"isAdmin": true}}}'
  }
];

for (const test of attackTests) {
  applySettings(parseSettings(test.json));

  const currentUser = {};
  const prototypeOwnsIsAdmin =
    Object.hasOwn(Object.prototype, "isAdmin");

  console.assert(
    prototypeOwnsIsAdmin === false,
    `${test.name}: Object.prototype must stay clean`
  );

  console.assert(
    ({}).isAdmin === undefined,
    `${test.name}: empty objects must not inherit isAdmin`
  );

  console.assert(
    !currentUser.isAdmin,
    `${test.name}: the admin branch must not be entered`
  );

  console.log(`[regression] ${test.name}`, {
    prototypeOwnsIsAdmin,
    emptyObjectIsAdmin: ({}).isAdmin,
    userOwnsIsAdmin: Object.hasOwn(currentUser, "isAdmin"),
    adminBranchTaken: Boolean(currentUser.isAdmin)
  });
}





