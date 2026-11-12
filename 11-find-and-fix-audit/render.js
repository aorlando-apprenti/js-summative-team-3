// render.js — the view layer (VULNERABLE STARTER).
//
// This module writes values to the DOM. It contains the app's RENDER flaws
// (XSS). Audit each function by tracing the untrusted value to the sink it
// reaches: a markup sink (innerHTML / insertAdjacentHTML), a URL sink (href),
// or a code sink (an inline on* attribute).
//
// Entry points (driven by app.js and by verify.js):
//   renderSearch(term, el)      -> echoes the search term
//   renderMembers(members, el)  -> renders the team-member list
//
// A member looks like: { name, bio, website }
//   name    -> shown as the heading and used by the "say hi" button
//   bio     -> a short blurb that may contain light formatting
//   website -> the member's profile link

// Echo the search term into the results banner.
function renderSearch(term, el) {
  // SOURCE: location.search ?q=  (see app.js).  SINK: innerHTML.
  // The untrusted term is concatenated into markup and parsed as HTML.
  el.textContent = "Showing results for: ";

  const strong = document.createElement("strong");
  strong.textContent = typeof term === "string" ? term : "";

  el.appendChild(strong);
}

function safeWebsite(raw) {
  if (typeof raw !== "string" || raw.trim() === "") {
    return null;
  }

  try {
    const url = new URL(raw, document.baseURI);

    return url.protocol === "http:" || url.protocol === "https:"
      ? url.href
      : null;
  } catch {
    return null;
  }
}

function isValidMember(member) {
  return member !== null &&
    typeof member === "object" &&
    !Array.isArray(member) &&
    ["name", "bio", "website"].every((key) =>
      Object.hasOwn(member, key) && typeof member[key] === "string"
    );
}

// Render one member card and append it to the list container.
function renderMember(member, listEl) {
  if (!isValidMember(member)) return;

  const card = document.createElement("div");
  card.className = "member";

  // Heading: the member name.
  const h = document.createElement("h3");
  h.textContent = member.name; // (this one is already safe — note it in your audit)
  card.appendChild(h);

  // Bio: rendered as HTML so light formatting shows. SINK: insertAdjacentHTML.
  // The stored bio is attacker-controllable (a saved profile field), so this is
  // a markup sink fed by persisted untrusted data.
  const bio = document.createElement("div");

  if (
    window.DOMPurify &&
    typeof window.DOMPurify.sanitize === "function"
  ) {
    const cleaned = window.DOMPurify.sanitize(member.bio, {
      ALLOWED_TAGS: [
        "b", "strong", "i", "em",
        "p", "br", "ul", "ol", "li"
      ],
      ALLOWED_ATTR: [],
      RETURN_DOM_FRAGMENT: true
    });

    bio.appendChild(cleaned);
  } else {
    // If the library is unavailable, display plain text safely.
    bio.textContent = member.bio;
  }

  card.appendChild(bio);

  // Profile link. SINK: href set from untrusted data with no scheme check, so a
  // "javascript:" value becomes executable when clicked.
  const link = document.createElement("a");
  const href = safeWebsite(member.website);

  if (href !== null) {
    link.href = href;
  }

  link.textContent = "Profile";
  card.appendChild(link);

  // "Say hi" button. SINK: an inline onclick string built from the member name,
  // so a name containing a quote-and-paren breakout injects code.
  const btn = document.createElement("button");
  btn.type = "button";

  btn.addEventListener("click", () => {
    alert("hi " + member.name);
  });

  btn.textContent = "Say hi";
  card.appendChild(btn);

  listEl.appendChild(card);
}

// Render the whole member list.
function renderMembers(members, el) {
  el.replaceChildren();

  if (
    !Array.isArray(members) ||
    !members.every(isValidMember)
  ) {
    el.textContent = "Unable to load the member list.";
    return;
  }

  for (const m of members) renderMember(m, el);
}

// Expose entry points for app.js and the harness.
window.renderSearch = renderSearch;
window.renderMembers = renderMembers;