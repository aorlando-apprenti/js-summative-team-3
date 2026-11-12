// app.js — Comment-with-profile-card widget (VULNERABLE STARTER).
//
// A realistic user-generated feature: parse a comment response, then render an
// author, a timestamp, comment text, a linked profile, and an optional
// rich-text body. As shipped it has only thin, partial defenses — a single
// gatekeeper here and there — so a single bug exposes the whole feature.
//
// Your job is to layer FIVE independent controls so that no single bug
// compromises the widget:
//   1. validation  — schema, types, and bounded lengths at parse
//   2. object-handling — a prototype-pollution guard before building the object
//   3. safe sinks  — textContent for author / timestamp / text
//   4. sanitization — DOMPurify for the rich-text body ONLY
//   5. URL         — scheme allow-listing for the profile link + addEventListener
//
// verify.js runs a scripted attack set and an independence test. Against this
// starter the attacks SUCCEED (script executes, a javascript: link is written,
// Object.prototype is polluted, an over-long / malformed body slips through).

const MAX_LEN = 2000;
const POLLUTION_KEYS = ["__proto__", "constructor", "prototype"];
const SAFE_SCHEMES = ["http:", "https:", "mailto:"];

// Field defaults a parsed comment is normalized onto.
const COMMENT_DEFAULTS = { author: "", timestamp: "", text: "", website: "", richText: "" };

// ---- Parse: turn a comment response body into a comment object. ----
function validateComment(text) {
  // COMPLETE (validation layer + object-handling layer): right now this parses and
  // does ONE weak check (that the result is an object), then deep-merges the raw
  // parsed object onto the defaults with NO pollution guard. Make it a real
  // validation layer: wrap JSON.parse in try/catch (fail closed), confirm every
  // required field — author, timestamp, text, website, richText — is a string
  // AND is within MAX_LEN, and reject anything that does not conform.
  // Then add the object-handling layer: reject the POLLUTION_KEYS with
  // Object.hasOwn BEFORE building the object, and build it with
  // Object.create(null), copying only the validated fields (drop deepMerge).

  let raw;

  // Defensive JSON parsing: malformed input fails closed.
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }

  // Require a non-null object, not an array.
  if (
    raw === null ||
    typeof raw !== "object" ||
    Array.isArray(raw)
  ) {
    return null;
  }

  // Reject dangerous own properties before copying anything.
  for (const key of POLLUTION_KEYS) {
    if (Object.hasOwn(raw, key)) {
      return null;
    }
  }

  // Validate every required field.
  const fields = Object.keys(COMMENT_DEFAULTS);

  for (const field of fields) {
    if (
      !Object.hasOwn(raw, field) ||
      typeof raw[field] !== "string" ||
      raw[field].length > MAX_LEN
    ) {
      return null;
    }
  }

  // Build a fresh object with no prototype.
  // Copy only the explicitly validated fields.
  const safeComment = Object.create(null);

  for (const field of fields) {
    safeComment[field] = raw[field];
  }

  return safeComment;
}

// Return an allowed href, or null. (Helper for the URL layer once you build it.)
function safeUrl(value) {
  try {
    const u = new URL(value, location.origin);
    return SAFE_SCHEMES.includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}

// ---- Render: write the comment to the DOM. ----
function renderComment(c, root) {
  const card = document.createElement("div");
  card.className = "comment";

  // COMPLETE (safe-sink layer): author, timestamp, and text are plain values and
  // should reach the DOM through textContent. Right now they are concatenated
  // into one HTML string and assigned to innerHTML — a markup sink that runs any
  // script the fields carry. Rebuild this with createElement + textContent.

  const author = document.createElement("span");
  author.className = "author";
  author.textContent = c.author;

  const timestamp = document.createElement("time");
  timestamp.textContent = c.timestamp;

  const paragraph = document.createElement("p");
  paragraph.textContent = c.text;

  card.append(author, timestamp, paragraph);

  // COMPLETE (URL layer): set the profile link with setAttribute only after a scheme
  // allow-list check (use safeUrl above), and wire any click behavior with
  // addEventListener — never a raw href and never an inline on* attribute.

  const link = document.createElement("a");
  link.textContent = c.author;

  const href = safeUrl(c.website);

  if (href !== null) {
    link.setAttribute("href", href);

    link.addEventListener("click", () => {
      openProfile(c.author);
    });
  }

  card.appendChild(link);

  // COMPLETE (sanitization layer): the rich-text body is the ONE field that
  // genuinely carries HTML. Route it through DOMPurify.sanitize(...) and assign
  // only the sanitized result. Right now the raw value is assigned to innerHTML.

  const rich = document.createElement("div");

  rich.innerHTML = DOMPurify.sanitize(c.richText, {
    ALLOWED_TAGS: [
      "b",
      "i",
      "em",
      "strong",
      "p",
      "br",
      "ul",
      "ol",
      "li",
      "a"
    ]
  });

  card.appendChild(rich);

  root.appendChild(card);
}

// A trivial profile opener referenced by the inline handler above.
function openProfile(name) {
  console.log("open profile:", name);
}

// Expose the entry points so the attack harness can drive them directly.
window.validateComment = validateComment;
window.renderComment = renderComment;
window.openProfile = openProfile;