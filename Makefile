.PHONY: install install-dev install-full lint type-check test test-fast clean run run-fast run-all help

# ── Default target ──
help:
	@echo ""
	@echo "  LLM Security Testing Framework — Development Commands"
	@echo "  ======================================================"
	@echo ""
	@echo "  Setup:"
	@echo "    make install          Install core dependencies"
	@echo "    make install-dev      Install core + dev tools (pytest, ruff, mypy)"
	@echo "    make install-full     Install everything (all APIs, local models, dense vectors)"
	@echo ""
	@echo "  Quality:"
	@echo "    make lint             Run ruff linter"
	@echo "    make type-check       Run mypy type checker"
	@echo "    make test             Run full test suite"
	@echo "    make test-fast        Run tests excluding slow/integration"
	@echo ""
	@echo "  Run:"
	@echo "    make run              Single model test (default config)"
	@echo "    make run-fast         Quick scan: 10 attacks, max concurrency"
	@echo "    make run-all          Test all configured models"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make clean            Remove generated files (reports, logs, __pycache__)"
	@echo ""

# ── Installation ──
install:
	pip install -e . --break-system-packages

install-dev:
	pip install -e ".[dev]" --break-system-packages

install-full:
	pip install -e ".[full,dev]" --break-system-packages

# ── Code Quality ──
lint:
	ruff check src/ adapters/ --fix
	ruff format src/ adapters/

type-check:
	mypy src/ adapters/ --ignore-missing-imports

test:
	pytest tests/ -v --tb=short

test-fast:
	pytest tests/ -v --tb=short -m "not slow and not integration"

# ── Run Framework ──
run:
	cd src && python main.py

run-fast:
	cd src && python main.py --max-attacks 10 --fast

run-all:
	cd src && python main.py --mode all

run-rag:
	cd src && python rag_security_tester.py

# ── Cleanup ──
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf reports/ logs/ .pytest_cache/ htmlcov/ .coverage *.egg-info/ dist/ build/
	rm -f security_metrics.db
	@echo "Cleaned generated files"
