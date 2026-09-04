install:
	python -m pip install -r requirements.txt

test:
	pytest --cov=secure --cov-report=term-missing

lint:
	ruff check secure tests

sast:
	mkdir -p reports
	semgrep --config p/python --json --output reports/sast.json secure vulnerable || true

sca:
	mkdir -p reports
	pip-audit -r requirements.txt -f json -o reports/sca.json || true

secrets:
	gitleaks detect --no-banner --redact --report-format json --report-path reports/secrets.json

build:
	docker build -t api-security-testing-pipeline:secure .

up:
	docker compose up --build -d

zap:
	mkdir -p reports
	docker run --network host -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:8000 -J /zap/wrk/zap.json -r /zap/wrk/zap.html || true
