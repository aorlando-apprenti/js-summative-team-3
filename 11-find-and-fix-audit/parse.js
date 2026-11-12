// parse.js — the data layer (VULNERABLE STARTER).
//
// This module turns server-style JSON into application values. It contains the
// app's DATA flaws (insecure parsing / object handling). Audit each function by
// tracing where the untrusted text comes from and what is done with the result.
//
// Entry points (driven by app.js and by verify.js):
//   parseConfig(text)         -> reads a fetched config blob
//   applySettings(text)       -> merges a fetched settings blob into defaults
//
// NOTE: there are no // TODO markers in this lab. Finding the flaws is the work.
// Trace each untrusted value to where it lands; the flaw is the unbroken path.

// App defaults that the fetched settings are merged on top of.
const DEFAULT_SETTINGS = { theme: "light", pageSize: 10 };

const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype"
]);

function isPlainObject(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
}

// Read a fetched config blob and hand back its fields.
function parseConfig(text) {
  // A bare JSON.parse: no try/catch (a malformed body throws straight through
  // the caller), and the result is read with no shape or type checks at all.
  // Fixed: reject malformed JSON and unexpected shapes or field types.
  try {
    if (typeof text !== "string") return null;

    const cfg = JSON.parse(text);

    if (
      !isPlainObject(cfg) ||
      !Object.hasOwn(cfg, "title") ||
      !Object.hasOwn(cfg, "maxItems") ||
      typeof cfg.title !== "string" ||
      typeof cfg.maxItems !== "number" ||
      !Number.isFinite(cfg.maxItems)
    ) {
      return null;
    }

    return {
      title: cfg.title,
      maxItems: cfg.maxItems
    };
  } catch {
    return null;
  }
}

// Recursively deep-merge `source` onto `target` (so nested settings objects are
// combined rather than replaced). This is a classic prototype-pollution vector:
// when a key is "__proto__", `target[key]` reaches Object.prototype, and the
// nested merge writes onto it.
function deepMerge(target, source) {
  const result = Object.create(null);

  for (const object of [target, source]) {
    if (!isPlainObject(object)) continue;

    for (const key of Object.keys(object)) {
      if (
        !Object.hasOwn(object, key) ||
        DANGEROUS_KEYS.has(key)
      ) {
        continue;
      }

      const value = object[key];

      if (isPlainObject(value)) {
        const existing = Object.hasOwn(result, key)
          ? result[key]
          : Object.create(null);

        result[key] = deepMerge(existing, value);
      } else {
        result[key] = value;
      }
    }
  }

  return result;
}

// Merge a fetched settings blob on top of the app defaults.
function applySettings(text) {
  // A deep merge of an untrusted object into trusted state with no __proto__
  // guard. If `parsed` carries a "__proto__" key, deepMerge writes onto
  // Object.prototype and every object on the page inherits it.
  try {
    if (typeof text !== "string") return null;

    const parsed = JSON.parse(text);

    if (!isPlainObject(parsed)) return null;

    // Validate permitted settings before calling the guarded merge.
    for (const key of Object.keys(parsed)) {
      if (DANGEROUS_KEYS.has(key)) continue;

      if (!Object.hasOwn(DEFAULT_SETTINGS, key)) {
        return null;
      }

      const value = parsed[key];

      if (key === "theme" && typeof value !== "string") {
        return null;
      }

      if (
        key === "pageSize" &&
        (typeof value !== "number" || !Number.isFinite(value))
      ) {
        return null;
      }
    }

    return deepMerge(DEFAULT_SETTINGS, parsed);
  } catch {
    return null;
  }
}

// Expose entry points for app.js and the harness.
window.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
window.parseConfig = parseConfig;
window.applySettings = applySettings;