# Makefile for memon project

.PHONY: test test-verbose lint check-syntax install-hooks clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  test          - Run tests"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  lint          - Run linting checks"
	@echo "  check-syntax  - Check Python syntax"
	@echo "  install-hooks - Install pre-commit hooks"
	@echo "  clean         - Remove generated files"

# Run tests
test:
	python -m unittest memon.test

# Run tests with verbose output
test-verbose:
	python -m unittest memon.test -v

# Check Python syntax
check-syntax:
	python -m py_compile memon.py
	python -m py_compile memon.test.py
	@echo "Syntax check passed"

# Verify mm_meta block exists
check-mm-meta:
	@head -n 5 memon.py | grep -q "mm_meta" || (echo "ERROR: Missing mm_meta block in memon.py" && exit 1)
	@echo "mm_meta block check passed"

# Run all checks
lint: check-syntax check-mm-meta
	@echo "All lint checks passed"

# Install pre-commit hooks
install-hooks:
	pip install pre-commit
	pre-commit install

# Clean generated files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "memon.state.json" -delete
	@echo "Cleaned generated files"
