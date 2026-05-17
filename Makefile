# reverge_collector — developer task runner.
#
# Mirrors the conventions used in the main reverge repo. Tests need the
# scanner binaries (nmap, masscan, naabu, etc.) installed by `install.sh`;
# the CI Dockerfile (tests/Dockerfile) does that automatically.
#
# Local dev tooling (ruff, pytest-cov, pytest-mock) can be installed with:
#   uv sync --group dev          (if you have uv set up at .venv/)
#   pip install ruff pytest-cov pytest-mock  (into the same venv used for tests)

SRC_DIRS  := reverge_collector
TEST_DIRS := tests
COV_PKG   := reverge_collector

# Override with `make UV=/path/to/uv <target>` or `export UV=...`.
# Falls back to whatever `uv` is on PATH.
UV ?= $(shell test -x .venv/bin/uv && echo .venv/bin/uv || echo uv)

# How ruff is invoked. Default is `<uv> run` (which manages the .venv).
# CI / Docker overrides this to empty so ruff is invoked directly from the
# venv that install.sh already activated.
UV_RUN ?= $(UV) run

# Pytest runs from the active venv (the Docker test image activates
# ~/venv before invoking pytest). Override locally as needed.
PYTEST ?= pytest

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# -- Setup --------------------------------------------------------------------

.PHONY: install
install: ## Sync the uv-managed dev environment (.venv/)
	$(UV) sync --group dev

# -- Quality ------------------------------------------------------------------

.PHONY: lint
lint: ## Run linter (ruff check)
	$(UV_RUN) ruff check $(SRC_DIRS) $(TEST_DIRS)

.PHONY: lint-fix
lint-fix: ## Run linter with auto-fix
	$(UV_RUN) ruff check --fix $(SRC_DIRS) $(TEST_DIRS)

.PHONY: format
format: ## Format code (ruff format)
	$(UV_RUN) ruff format $(SRC_DIRS) $(TEST_DIRS)

.PHONY: format-check
format-check: ## Check formatting without changes
	$(UV_RUN) ruff format --check $(SRC_DIRS) $(TEST_DIRS)

# -- Testing ------------------------------------------------------------------

# Coverage gate: 20% baseline. The existing test suite is per-scanner with
# many tools skipped when their binary is missing; raise this as the suite
# grows toward something like the 70% reverge has reached.
.PHONY: test
test: ## Run unit tests with coverage gate (20% baseline)
	$(PYTEST) $(TEST_DIRS) -x -q --cov=$(COV_PKG) --cov-fail-under=20

.PHONY: test-cov
test-cov: ## Run tests with detailed coverage report (html + term-missing)
	$(PYTEST) $(TEST_DIRS) --cov=$(COV_PKG) --cov-report=term-missing --cov-report=html --cov-fail-under=20

.PHONY: test-no-cov
test-no-cov: ## Run tests without the coverage gate (useful for fast local loops)
	$(PYTEST) $(TEST_DIRS) -x -q

# -- Composite ----------------------------------------------------------------

.PHONY: check
check: format-check lint test ## Run all quality gates (format-check, lint, test)

.PHONY: fix
fix: format lint-fix ## Auto-fix formatting and lint issues

.PHONY: ci
ci: format-check lint test ## Alias for `check` — what CI runs

# -- Housekeeping -------------------------------------------------------------

.PHONY: clean
clean: ## Remove caches and coverage artifacts
	rm -rf .ruff_cache .pytest_cache .coverage htmlcov coverage.xml
	find $(SRC_DIRS) -type d -name __pycache__ -exec rm -rf {} +
	find $(TEST_DIRS) -type d -name __pycache__ -exec rm -rf {} +
