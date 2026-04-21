DETECT_VERSION ?= 9.2.0
REGISTRY       ?= your-registry.example.com
IMAGE_NAME     ?= security/blackduck-detect
TAG            ?= dev

IMAGE := $(REGISTRY)/$(IMAGE_NAME):$(TAG)

.PHONY: build push lint lint-docker lint-shell lint-python test test-unit test-integration mock-hub clean help

help:
	@echo "Targets:"
	@echo "  build             Build the scanner image"
	@echo "  push              Push the scanner image"
	@echo "  lint              Run all linters"
	@echo "  lint-docker       Lint Dockerfile with hadolint"
	@echo "  lint-shell        Lint entrypoint.sh with shellcheck"
	@echo "  lint-python       Lint scripts/ with flake8 + black"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run pytest unit tests"
	@echo "  test-integration  Run integration tests against mock Hub"
	@echo "  mock-hub          Start mock Hub server (scenario=clean)"
	@echo "  clean             Remove local build artifacts"

build:
	docker build \
		--build-arg DETECT_VERSION=$(DETECT_VERSION) \
		-t $(IMAGE) \
		./docker
	@echo "Built: $(IMAGE)"

push: build
	docker push $(IMAGE)

build:
	docker build \
		--build-arg DETECT_VERSION=$(DETECT_VERSION) \
		-t $(IMAGE) \
		./docker
	@echo "Built: $(IMAGE)"

push: build
	docker push $(IMAGE)

lint: lint-docker lint-shell lint-python

test: test-unit test-integration

test-unit:
	pip install -q -r requirements-dev.txt
	pytest tests/test_policy_gate.py -v

test-integration:
	pip install -q -r requirements-dev.txt
	bash tests/integration_test.sh

mock-hub:
	@echo "Starting mock Hub on http://localhost:8888 (scenario=$(BD_MOCK_SCENARIO))"
	BD_MOCK_SCENARIO=$(BD_MOCK_SCENARIO) python3 tests/mock_hub.py

lint-docker:
	hadolint --config .hadolint.yaml docker/Dockerfile

lint-shell:
	shellcheck docker/entrypoint.sh

lint-python:
	flake8 scripts/ --max-line-length=100
	black --check scripts/
	isort --check-only scripts/

clean:
	docker rmi $(IMAGE) 2>/dev/null || true
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
