# Threat Model

```mermaid
flowchart TD
  Client[Untrusted API client] -->|HTTPS + JWT| API[FastAPI]
  API -->|parameterized repository calls| DB[(PostgreSQL)]
  API --> Logs[Structured audit sink]
  Attacker[Attacker] -. IDOR, injection, brute force .-> API
  CI[CI runner] -->|scans and gates| Artifact[Reports]
```

Assets are identities, orders, audit records, passwords, tokens, and CI artifacts. Actors include anonymous internet clients, authenticated users, administrators, malicious insiders, and compromised dependencies.

Primary threats: credential stuffing, token theft, BOLA/IDOR, mass assignment, injection, sensitive data leakage, excessive requests, log tampering, vulnerable dependencies, and insecure CI configuration. Mitigations are mapped to ASVS in [asvs-checklist.md](asvs-checklist.md).
