Yes. You can write:

> **Source:** The `q` query parameter from `location.search`.
>
> **Path:** `location.search` → `params.get("q")` → `renderBanner(q)` → `resultsEl.innerHTML`.
>
> **Original sink:** `innerHTML`, which interpreted the untrusted input as HTML.
>
> **Fix:** Replaced `innerHTML` with `textContent` so the input displays as literal text.