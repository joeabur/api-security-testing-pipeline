# Testing Methodology

1. Unit and integration tests exercise route contracts with FastAPI `TestClient`.
2. Authentication tests cover missing, malformed, expired/invalid, and wrong credentials.
3. Authorization tests cover role denial and same-user/owner object scope.
4. Input tests cover length, character allowlists, numeric bounds, duplicates, and mass assignment.
5. Regression tests assert security headers, redacted fields, generic errors, and rate limits.
6. Semgrep provides SAST over both implementations; vulnerable findings are expected training evidence.
7. pip-audit and Trivy provide SCA and image evidence.
8. Gitleaks prevents credentials entering git history.
9. OWASP ZAP baseline probes the running secure API.

Reports are uploaded as CI artifacts. A real engagement should add authenticated ZAP contexts, PostgreSQL integration tests, TLS scanning, and performance tests for distributed rate limiting.
