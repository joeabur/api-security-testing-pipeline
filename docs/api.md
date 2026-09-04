# API Architecture

All routes are versioned under `/api/v1`. Login returns a short-lived JWT and an HttpOnly SameSite cookie. Subsequent requests use `Authorization: Bearer <token>`.

| Method | Route | Required role | Object scope |
|---|---|---|---|
| POST | `/auth/login` | anonymous | rate limited |
| GET | `/users` | authenticated | public fields only |
| GET | `/users/{id}` | same user or admin | object check |
| POST | `/users` | authenticated | server assigns role |
| GET | `/orders` | authenticated | owner or admin |
| GET | `/orders/{id}` | authenticated | owner or admin |
| POST | `/orders` | authenticated | current user owns object |
| GET | `/admin/audit` | admin | role check |

Invalid input returns `422`; missing/invalid authentication returns `401`; valid identity without permission returns `403`; missing objects return `404` without database details.
