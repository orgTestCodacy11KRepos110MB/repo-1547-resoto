.PHONY: clean clean-test clean-pyc clean-build clean-env docs help setup
.DEFAULT_GOAL := help
.SILENT: clean clean-build clean-pyc clean-test setup env

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr .mypy_cache/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -fr {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

clean-env: ## remove environment
	rm -fr env

lint: ## check style with flake8
	flake8 core
	mypy core tests

test: env ## run tests quickly with the default Python
	pytest

test-all: env ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source core -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

release: dist ## package and upload a release
	twine upload dist/*

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	python setup.py install

env:
	python3 -m venv env
	./env/bin/pip install -r requirements-dev.txt
	./env/bin/pip install -r requirements.txt
	./env/bin/mypy core tests > /dev/null 2>&1 || true
	echo "Run mypy once to collect all required types and packacges..."
	./env/bin/mypy --install-types --non-interactive || true
	printf "Consider to execute in your running shell:\n\nPYTHONPATH=`pwd`\nsource env/bin/activate\n\n"

setup: clean clean-env env

install-latest: env
	pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U


docker:
	docker login rg.fr-par.scw.cloud/funcscwcloudkeeperjiaxo1v0 -u nologin -p "$$SCW_SECRET_TOKEN"
	docker build -f deployment/Dockerfile -t core .
	docker tag core:latest rg.fr-par.scw.cloud/funcscwcloudkeeperjiaxo1v0/core:latest
	docker push rg.fr-par.scw.cloud/funcscwcloudkeeperjiaxo1v0/core:latest

