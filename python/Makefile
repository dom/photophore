.PHONY: lint lint-isolation test

lint-isolation:
	python ../tools/ast_lint_network_isolation.py src/ ../../thermocline/thermocline/python/src/

test:
	python -m pytest tests/

lint: lint-isolation
	ruff check src/ tests/
