# OWASP ASVS Verification Checklist

Primary standard: OWASP Application Security Verification Standard (ASVS). IDs are representative controls for this lab and should be checked against the current ASVS release during a real assessment.

| Area | Requirement | Evidence | Status |
|---|---|---|---|
| Architecture | V1 define trust boundaries and fail securely | architecture and threat model docs | Pass |
| Authentication | V2.1 credential verification and generic failures | hashed passwords, 401 tests | Pass |
| Session management | V3 expiry and secure cookie flags | JWT `exp`, HttpOnly/SameSite cookie | Pass |
| Access control | V4 deny by default and object checks | role and owner dependencies | Pass |
| Input validation | V5 allowlist, bounds, typed models | Pydantic schemas and 422 tests | Pass |
| Cryptography | V6 password hashing and signed tokens | Argon2id/PyJWT | Pass |
| Error handling | V7 no sensitive details in responses | generic HTTP errors | Pass |
| Data protection | V8 minimize response fields and disable caching | response models, no-store | Pass |
| Communications | V9 CORS allowlist and deployment TLS boundary | CORS config, Compose boundary | Partial |
| API security | V13 authentication, authorization, rate limits | route dependencies and SlowAPI | Pass |
| Configuration | V14 secure headers and dependency gates | middleware, CI scans | Pass |
| Logging | security events are structured and attributable | `security.audit` logger | Partial |

Partial items require production integration validation: TLS termination, centralized tamper-resistant logs, secret manager rotation, and PostgreSQL repository tests.
