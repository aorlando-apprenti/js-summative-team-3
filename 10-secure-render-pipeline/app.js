// app.js — Secure Render Pipeline (VULNERABLE STARTER)
//
// A feature does the same three things almost every page does: it fetches some
// data, parses the bytes into a value, and renders that value to the screen.
// fetch -> parse -> render. This starter collapses all three into one careless
// chain with no control at any boundary, so it is open to BOTH problems at once:
//
//   * insecure object handling (no try/catch, no shape check, no __proto__ guard)
//   * XSS (every field reaches the DOM through innerHTML, a markup sink)
//
// verify.js drives runPipeline(body, root) with a good body plus a set of
// malformed and hostile ones. Against this starter the attacks SUCCEED:
// a truncated body throws, a wrong-type field renders, a __proto__ payload
// pollutes Object.prototype, and a script string executes.

// The pipeline has three stages. Right now parse and render are jammed together
// with no checkpoint between them. Your job is to give each stage its own
// control: a defensive parse, then a render that uses safe sinks.

function parseStage(text) {
  // COMPLETE (parse boundary): this is the first defense point. Right now this does
  // a bare JSON.parse and trusts whatever comes back. Make it a DEFENSIVE PARSE:
  //   1. wrap JSON.parse in try/catch and return null on a SyntaxError
  //      (a malformed body is a rejection condition, not a crash);
  //   2. validate the shape and types — confirm `title`, `body`, `link`, and
  //      `richText` all exist and are strings; return null if any is wrong;
  //   3. LAST, reject the prototype-pollution keys __proto__ / constructor /
  //      prototype (use Object.hasOwn) BEFORE the object is copied or trusted;
  //   4. build the result with Object.create(null) and copy only the keys you
  //      validated, so a poisoned inherited property has nowhere to land.
  // Return the validated object, or null to fail closed.

  let parsed;

  try {
    parsed = JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return null;
    }
    return null;
  }

  // Confirm we received a plain object-like value.
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    return null;
  }

  // Validate required fields and their types.
  const allowedFields = ["title", "body", "link", "richText"];

  for (const field of allowedFields) {
    if (
      !Object.hasOwn(parsed, field) ||
      typeof parsed[field] !== "string"
    ) {
      return null;
    }
  }

  // Reject dangerous property names BEFORE copying anything.
  const dangerousKeys = ["__proto__", "constructor", "prototype"];

  for (const key of dangerousKeys) {
    if (Object.hasOwn(parsed, key)) {
      return null;
    }
  }

  // Create an object without a prototype and copy only validated fields.
  const safeData = Object.create(null);

  for (const field of allowedFields) {
    safeData[field] = parsed[field];
  }

  return safeData;
}

function renderStage(data, root) {
  // COMPLETE (render boundary): this is the second defense point. A value that
  // passed parse is NOT automatically safe to render — a well-typed string is
  // still a working script if it lands in a markup sink. Rebuild this so every
  // untrusted value reaches the DOM through a SAFE sink:
  //   * title and body -> textContent (built with createElement, never innerHTML)
  //   * link -> setAttribute("href", ...) only after a scheme allow-list check
  //     (http:/https:/mailto:); reject javascript: and data: URLs;
  //   * richText is the ONE field that genuinely carries HTML -> run it through
  //     DOMPurify.sanitize(...) and assign only the sanitized result.
  // The single line below is the canonical pipeline bug: it concatenates every
  // untrusted field into one HTML string and assigns it to innerHTML.

  const heading = document.createElement("h2");
  heading.textContent = data.title;

  const paragraph = document.createElement("p");
  paragraph.textContent = data.body;

  const link = document.createElement("a");
  link.textContent = "Read more";

  // Validate the URL scheme before assigning the href.
  try {
    const parsedURL = new URL(data.link, document.baseURI);

    const allowedProtocols = ["http:", "https:", "mailto:"];

    if (allowedProtocols.includes(parsedURL.protocol)) {
      link.setAttribute("href", parsedURL.href);
    }
  } catch (error) {
    // Invalid URLs are rejected: the link remains without an href.
  }

  const richContent = document.createElement("div");

  // DOMPurify is the only permitted HTML sink in this pipeline.
  richContent.innerHTML = DOMPurify.sanitize(data.richText, {
  ALLOWED_TAGS: [
    "b",
    "i",
    "em",
    "strong",
    "p",
    "br",
    "ul",
    "ol",
    "li"
  ]
});

  // Replace existing content with the safely constructed elements.
  root.replaceChildren(
    heading,
    paragraph,
    link,
    richContent
  );
}

// Shared application state the feature caches parsed responses into. A real app
// keeps state like this around between renders.
const appState = { lastArticle: {} };

// Recursively deep-merge `source` onto `target`. When `parseStage` returns an
// object that still carries a "__proto__" key, this merge writes onto
// Object.prototype — a prototype-pollution vector with no guard in front of it.
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]); // key === "__proto__" -> pollutes
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Orchestrator. A real version fetches the body first; the harness hands the
// raw body text in directly so the lab stays network-free.
function runPipeline(body, root) {
  // COMPLETE (orchestration): when the parse stage cannot validate a body it should
  // return null, and this orchestrator should FAIL CLOSED — render a safe empty
  // state instead of any partial or unvalidated content. Right now it passes
  // whatever parseStage returned straight into render with no check, and the
  // deep-merge below trusts every key the parse stage let through.

  const data = parseStage(body);

  // Fail closed if parsing or validation failed.
  if (data === null) {
    appState.lastArticle = {};

    const emptyState = document.createElement("p");
    emptyState.textContent = "Article unavailable.";

    root.replaceChildren(emptyState);
    return;
  }

  // Cache only the validated, allow-listed data.
  appState.lastArticle = deepMerge({}, data);

  // Render using safe DOM sinks.
  renderStage(data, root);
}

// Expose the entry point so the attack harness can drive it directly.
window.runPipeline = runPipeline;