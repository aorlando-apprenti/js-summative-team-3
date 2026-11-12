// app.js — VULNERABLE starter.
//
// renderComment(comment, host) renders a rich-text comment. Comments may
// legitimately contain <b>, <i>, <a>, and <ul>, so the feature renders them as
// HTML — which means textContent is NOT an option here (it would show the tags
// as literal characters and break the feature).
//
// As written, the untrusted comment.html is assigned straight to innerHTML, so a
// comment like `<img src=x onerror=...>` or `<a href="javascript:...">` executes
// on render. Open index.html and read the verdict in #result: the payload
// battery will report FAIL.
//
// YOUR TASK: sanitize comment.html so it is safe to render, while preserving
// benign formatting (bold, italics, safe links, lists). Sanitization is an XSS
// OUTPUT defense — it runs at the render boundary, on the exact string you
// assign, with nothing concatenated afterward. Two ways to do it:
//
//   - Vetted library (the professional default): DOMPurify is loaded by
//     index.html, so you can call DOMPurify.sanitize(...). Prefer a strict
//     allow-list config (ALLOWED_TAGS / ALLOWED_ATTR).
//   - Manual allow-list (teaching): parse with DOMParser into a detached, inert
//     tree, drop any tag not on a small allow-list, strip any attribute not
//     permitted, re-validate href schemes, then serialize and assign that string.

function sanitizeManually(html) {
  const parsed = new DOMParser().parseFromString(
    String(html ?? ""),
    "text/html"
  );

  const allowed = {
    b: [],
    strong: [],
    i: [],
    em: [],
    a: ["href", "title"],
    ul: [],
    ol: [],
    li: [],
    p: [],
    br: []
  };

  for (const element of parsed.body.querySelectorAll("*")) {
    const tag = element.localName;

    if (
      element.namespaceURI !== "http://www.w3.org/1999/xhtml" ||
      !Object.hasOwn(allowed, tag)
    ) {
      element.remove();
      continue;
    }

    for (const attribute of Array.from(element.attributes)) {
      if (!allowed[tag].includes(attribute.name)) {
        element.removeAttribute(attribute.name);
      }
    }

    if (element.hasAttribute("href")) {
      try {
        const url = new URL(
          element.getAttribute("href"),
          document.baseURI
        );

        if (
          url.protocol === "http:" ||
          url.protocol === "https:"
        ) {
          element.setAttribute("href", url.href);
        } else {
          element.removeAttribute("href");
        }
      } catch {
        element.removeAttribute("href");
      }
    }
  }

  return parsed.body.innerHTML;
}


function renderComment(comment, host) {
  const el = document.createElement("div");
  el.className = "comment";

  // TODO: Sanitize comment.html (DOMPurify with a strict config, or a manual
  //       allow-list sanitizer) and assign the cleaned string here — with no
  //       concatenation after the sanitizer runs.
  const useManual = true;

  const cleaned = useManual
    ? sanitizeManually(comment.html)
    : DOMPurify.sanitize(comment.html, {
      ALLOWED_TAGS: [
        "b", "strong",
        "i", "em",
        "a",
        "ul", "ol", "li",
        "p", "br"
      ],
      ALLOWED_ATTR: ["href", "title"]
    });

  el.innerHTML = cleaned;
  host.appendChild(el);
}

window.renderComment = renderComment;

