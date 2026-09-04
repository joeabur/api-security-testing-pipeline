# Security Gates

The gate reads JSON reports in `reports/` and compares counts by severity to environment variables:

- Critical: fail by default (`CRITICAL_THRESHOLD=0`)
- High: fail by default (`HIGH_THRESHOLD=0`)
- Medium: configurable (`MEDIUM_THRESHOLD=0` in CI, change per environment)
- Low: report only (`LOW_THRESHOLD=999999`)

Change thresholds through protected GitHub environment variables, not source edits. Any exception must have an owner, expiry date, ticket, compensating control, and documented risk acceptance. Reports remain artifacts even when the gate fails.
