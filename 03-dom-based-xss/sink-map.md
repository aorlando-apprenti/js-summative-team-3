| Dangerous sink | Interprets the string as | Safe replacement | Rendering context |
|---|---|---|---|
| `panel.innerHTML` | HTML markup | `panel.textContent = "Viewing: " + tabName;` | Plain text inside the tab panel |
| `panel.insertAdjacentHTML("beforeend", detailString)` | HTML markup | Create a `small` element, set its `textContent`, then use `panel.append(detail)` | Plain text inside a `small` element in the tab panel |