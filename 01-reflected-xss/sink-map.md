| Dangerous sink | Interprets the string as | Safe replacement | Rendering context |
|---|---|---|---|
| `resultsEl.innerHTML` | HTML markup, including elements and event-handler attributes | `resultsEl.textContent = "Results for: " + query;` | Plain text inside the results banner |