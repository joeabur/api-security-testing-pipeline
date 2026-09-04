# Limitations

This training project does not provide a production identity provider, refresh-token rotation, CSRF strategy for browser-only cookie clients, distributed rate limiting, TLS termination, database migrations, backup/restore, centralized audit retention, or a full authenticated ZAP context. The secure app uses in-memory records for deterministic tests even though Compose includes PostgreSQL as the intended deployment database boundary. Replace demo credentials, JWT secret, database password, CORS origin, and cookie `secure` setting before deployment.
