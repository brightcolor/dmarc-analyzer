.PHONY: help install dev lint test cov run smtp migrate upgrade image clean

PYTHON := python
PIP    := pip
PYTEST := pytest
RUFF   := ruff

help:
	@echo "DMARC Analyzer — common tasks"
	@echo ""
	@echo "  make install       Install all dependencies"
	@echo "  make dev           Install in editable mode with dev extras"
	@echo "  make lint          Run ruff linter"
	@echo "  make test          Run the test suite"
	@echo "  make cov           Run tests with coverage report"
	@echo "  make run           Start the web server (uvicorn)"
	@echo "  make smtp          Start the SMTP inbound server"
	@echo "  make migrate       Generate a new Alembic migration (set MSG=...)"
	@echo "  make upgrade       Apply pending Alembic migrations"
	@echo "  make image         Build the Docker image"
	@echo "  make clean         Remove build artefacts and caches"

install:
	$(PIP) install -r requirements.txt

dev:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest-asyncio pytest-cov ruff

lint:
	$(RUFF) check app smtp_inbound

lint-fix:
	$(RUFF) check --fix app smtp_inbound

test:
	$(PYTEST) tests/ -v

cov:
	$(PYTEST) tests/ -v --cov=app --cov=smtp_inbound --cov-report=term-missing --cov-report=html

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8765

smtp:
	$(PYTHON) -m smtp_inbound

migrate:
	alembic revision --autogenerate -m "$(MSG)"

upgrade:
	alembic upgrade head

image:
	docker build -t dmarc-analyzer:latest .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage dist build *.egg-info
