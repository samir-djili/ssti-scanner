.PHONY: help install install-dev test test-unit test-integration lint format clean build docs

help:  ## Show this help message
	@echo "SSTI Scanner - Development Commands"
	@echo "=================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package for production
	pip install -e .

install-dev:  ## Install package with development dependencies
	pip install -e .[dev,browser,advanced]
	pip install -r requirements-dev.txt

test:  ## Run all tests
	pytest -v

test-unit:  ## Run unit tests only
	pytest tests/unit/ -v

test-integration:  ## Run integration tests only
	pytest tests/integration/ -v

test-coverage:  ## Run tests with coverage report
	pytest --cov=ssti_scanner --cov-report=html --cov-report=term-missing

lint:  ## Run code linting
	flake8 src/ssti_scanner tests/
	mypy src/ssti_scanner
	black --check src/ssti_scanner tests/
	isort --check-only src/ssti_scanner tests/

format:  ## Format code
	black src/ssti_scanner tests/
	isort src/ssti_scanner tests/

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build:  ## Build package
	python -m build

docs:  ## Generate documentation
	cd docs && make html

run-example:  ## Run example scan
	python -m ssti_scanner.cli.main scan --url http://testphp.vulnweb.com --intensity normal --output example_results.json

docker-build:  ## Build Docker image
	docker build -t ssti-scanner .

docker-run:  ## Run in Docker container
	docker run --rm -it ssti-scanner --help

security-check:  ## Run security checks
	bandit -r src/ssti_scanner/
	safety check

pre-commit:  ## Run pre-commit checks
	make format
	make lint
	make test-unit
