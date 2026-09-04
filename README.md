# API Security Testing Pipeline

A deliberately vulnerable FastAPI REST API paired with a hardened reference implementation and an executable DevSecOps pipeline. This is a training project: the vulnerable service is never published and is bound to loopback only.

## Quick start

```bash
cp .env.example .env
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
.venv/bin/uvicorn secure.app:app --reload
```

The secure API is available at `http://127.0.0.1:8000/docs`. Test users are `alice@example.com` / `alice-password`, `bob@example.com` / `bob-password`, and `admin@example.com` / `admin-password`.

```bash
docker compose up --build
# secure API: http://127.0.0.1:8000
```

The vulnerable lab can be run only on localhost with `docker compose -f docker-compose.vulnerable.yml up --build`; never expose port 8001 to a shared network.

## Project map

- `vulnerable/`: intentionally unsafe training examples, isolated from the hardened service.
- `secure/`: protected API reference implementation.
- `tests/`: unit, integration, authentication, authorization, IDOR, validation, rate-limit, and regression tests.
- `docs/`: architecture, threat model, ASVS checklist, attack surface, remediation records, and operating guidance.
- `.github/workflows/security.yml`: PR pipeline from lint through ZAP and configurable gates.
- `reports/`: generated SAST, SCA, secret, container, ZAP, and test reports; generated files are ignored.

## Security gates

`CRITICAL_THRESHOLD` and `HIGH_THRESHOLD` default to `0`; `MEDIUM_THRESHOLD` defaults to `0` and can be changed per repository/environment. Low findings are reported without failing the gate. See [docs/security-gates.md](docs/security-gates.md).

## Scope and limitations

This is an educational reference, not a production authorization server. The demo uses in-memory repositories for deterministic tests; Compose provides PostgreSQL as the deployment dependency boundary. See [docs/limitations.md](docs/limitations.md).
