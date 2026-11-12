| Fixture / pattern | Before | After |
|---|---|---|
| `valid.json` — benign update | Updates the profile but also copies `preferredKey` onto the user. | Copies only the three allowed fields; returns `#fff`; numeric tier `1` passes. |
| `mass-assign.json` — mass assignment | Sets `isAdmin: true` and adds `internalId`. | `isAdmin` stays `false`; `internalId` is not added. |
| `dynamic-key.json` — unsafe dynamic read | Returns the `Object` constructor. | Returns `undefined`. |
| `coercion.json` — loose-equality bypass | String `"1"` passes `== 1`; string `"0"` is truthy. | String `"1"` fails the strict numeric gate; `count` is not copied. |