# Security Requirements

- All protected routes require a valid, short-lived JWT.
- Authorization must evaluate both role and object ownership.
- Passwords must be Argon2id hashed and never returned or logged.
- Request bodies must be typed, bounded, and allowlisted; server-owned fields cannot be mass assigned.
- Login and mutation endpoints must be rate limited with configurable thresholds.
- Responses must use explicit schemas and omit secrets and payment data.
- Errors must be stable and generic to clients; diagnostic detail stays in controlled logs.
- Responses must include anti-sniffing, framing, CSP, referrer, and no-store headers.
- CORS origins must be configured explicitly.
- CI must run lint, tests, SAST, SCA, secret scanning, image scanning, DAST, and a configurable gate.
- The lab API must be loopback-only and never share deployment credentials with the secure API.
