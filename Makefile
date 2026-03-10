# Security Audit Tool – Makefile
# Usage: make help

PYTHON  := python3
SAT_DIR := sat
VENV    := .venv
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest

.DEFAULT_GOAL := help

# ── setup ─────────────────────────────────────────────────────────────────────

.PHONY: venv
venv:                            ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r $(SAT_DIR)/requirements.txt
	$(PIP) install pytest pytest-cov flake8 bandit rich
	@echo "  ✅  venv ready. Run: source $(VENV)/bin/activate"

.PHONY: install
install: venv                    ## Install all dependencies (alias for venv)

# ── test ──────────────────────────────────────────────────────────────────────

.PHONY: test
test:                            ## Run unit tests
	cd $(SAT_DIR) && $(PYTHON) -m pytest tests/ -v --tb=short

.PHONY: test-cov
test-cov:                        ## Run tests with coverage report
	cd $(SAT_DIR) && $(PYTHON) -m pytest tests/ -v --tb=short \
	  --cov=. --cov-report=term-missing --cov-report=html:htmlcov

.PHONY: test-fast
test-fast:                       ## Run tests (fail fast on first error)
	cd $(SAT_DIR) && $(PYTHON) -m pytest tests/ -v -x --tb=short

# ── lint ──────────────────────────────────────────────────────────────────────

.PHONY: lint
lint:                            ## Lint with flake8
	flake8 $(SAT_DIR)/ --max-line-length=120 --max-complexity=12 \
	  --extend-ignore=E501,W503 --exclude=.venv,__pycache__

.PHONY: security-lint
security-lint:                   ## Run bandit security linter
	bandit -r $(SAT_DIR)/ -ll -x $(SAT_DIR)/tests/ \
	  --skip B101,B603,B602,B404,B607,B110

.PHONY: check
check: lint test                 ## Run lint + tests

# ── run ───────────────────────────────────────────────────────────────────────

.PHONY: scan
scan:                            ## Run a full security scan
	cd $(SAT_DIR) && $(PYTHON) main.py scan

.PHONY: scan-quick
scan-quick:                      ## Quick scan (skip kali_tools + docker)
	cd $(SAT_DIR) && $(PYTHON) main.py scan --skip kali_tools docker_scan --no-dashboard

.PHONY: scan-deep
scan-deep:                       ## Deep scan (includes nmap vuln scripts, rkhunter)
	cd $(SAT_DIR) && $(PYTHON) main.py scan --deep

.PHONY: report
report:                          ## Show last scan report
	cd $(SAT_DIR) && $(PYTHON) main.py report

.PHONY: modules
modules:                         ## List available scanner modules
	cd $(SAT_DIR) && $(PYTHON) main.py modules

.PHONY: tools
tools:                           ## Show external tool availability
	cd $(SAT_DIR) && $(PYTHON) main.py tools

# ── baseline ──────────────────────────────────────────────────────────────────

.PHONY: baseline
baseline:                        ## Save current scan as baseline
	cd $(SAT_DIR) && $(PYTHON) main.py scan --save-baseline

.PHONY: diff
diff:                            ## Show drift vs last saved baseline
	cd $(SAT_DIR) && $(PYTHON) main.py diff

# ── schedule ──────────────────────────────────────────────────────────────────

.PHONY: schedule-status
schedule-status:                 ## Show scheduler status
	cd $(SAT_DIR) && $(PYTHON) main.py schedule status

.PHONY: schedule-install
schedule-install:                ## Install daily systemd timer (requires sudo)
	cd $(SAT_DIR) && sudo $(PYTHON) main.py schedule install --freq daily

.PHONY: schedule-remove
schedule-remove:                 ## Remove systemd timer
	cd $(SAT_DIR) && sudo $(PYTHON) main.py schedule remove

# ── clean ─────────────────────────────────────────────────────────────────────

.PHONY: clean
clean:                           ## Remove cache and temp files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.xml" -path "*/coverage*" -delete
	@echo "  🧹  Cleaned."

.PHONY: clean-reports
clean-reports:                   ## Remove generated scan reports
	rm -rf $(SAT_DIR)/reports/
	@echo "  🧹  Reports cleared."

# ── help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:                            ## Show this help
	@echo ""
	@echo "  🔒  Security Audit Tool — available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
