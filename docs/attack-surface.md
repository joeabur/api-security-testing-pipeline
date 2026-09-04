# Attack Surface

| Surface | Threat | Control | Test |
|---|---|---|---|
| Login | brute force, credential stuffing | SlowAPI, generic 401, Argon2 | rate-limit/auth tests |
| User IDs | IDOR and enumeration | subject/admin check | authorization test |
| Order IDs | BOLA and sensitive data | owner/admin check, allowlist | IDOR test |
| JSON bodies | injection and mass assignment | Pydantic bounds/patterns | validation tests |
| JWT/cookie | theft/replay | expiry, HttpOnly, SameSite | auth regression |
| Audit endpoint | privilege escalation/log exposure | admin dependency, last 100 events | admin test |
| Dependencies/images | known CVEs | pip-audit, Trivy, lock/pins | CI gate |
| Runtime config | CORS/debug exposure | explicit origins, no debug errors | header/error checks |
