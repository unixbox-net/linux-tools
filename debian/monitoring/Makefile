SHELL := /bin/bash
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: help setup venv deps test run docker clean

help:
	@echo "make setup      - install system deps (Debian/Ubuntu)"
	@echo "make venv       - create Python venv"
	@echo "make deps       - install pip deps"
	@echo "make test       - run unit tests"
	@echo "make run        - run the monitor"
	@echo "make docker     - build Docker image"
	@echo "make clean      - remove venv and caches"

setup:
	./scripts/install-deps-debian.sh

venv:
	python3 -m venv --system-site-packages $(VENV)
	$(PIP) install --upgrade pip

deps: venv
	$(PIP) install -r requirements.txt

test: deps
	$(PY) -m pytest -q

run: deps
	sudo $(PY) socket_snoop.py

docker:
	docker build -t socket-snoop:latest .

clean:
	rm -rf $(VENV) .pytest_cache __pycache__
