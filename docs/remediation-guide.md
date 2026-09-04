# Remediation Guide

1. Reproduce the issue against the isolated vulnerable API and capture request, response, and scanner evidence.
2. Identify the owning trust boundary and root cause, not only the failing line.
3. Implement the smallest secure control in `secure/` with an explicit regression test.
4. Run lint, Pytest, Semgrep, pip-audit, Gitleaks, Trivy, and ZAP.
5. Review the ASVS mapping and update the catalogue with the retest result.
6. Release only when the configured gate passes or an approved exception exists.

For a suspected exposed secret: revoke it immediately, preserve CI evidence, rotate all dependents, scan history, and record incident impact. Never place the replacement secret in source or test fixtures.
