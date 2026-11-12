Both the DOMPurify path and the manual allow-list path neutralized all five payloads: the script tag, image with onerror, SVG with onload, javascript: link, and style payload. Neither path missed a tested payload.

Bold, italics, safe links, and lists remained correctly formatted in both paths.


| Payload | DOMPurify | Manual |
|---|---|---|
| Script tag | Blocked | Blocked |
| Image with `onerror` | Blocked | Blocked |
| SVG with `onload` | Blocked | Blocked |
| `javascript:` link | Blocked | Blocked |
| Style payload | Blocked | Blocked |

