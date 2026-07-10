# react-native-smtp-tcp
#
# Bare `make` prints this help. Every target works on a fresh clone.

.DEFAULT_GOAL := help
.PHONY: help install build test cover lint typecheck check ci pack-check clean release

# Version bump for `make release`: patch (default), minor, major, or an explicit X.Y.Z.
VERSION ?= patch

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies (npm ci if a lockfile exists, else npm install)
	@if [ -f package-lock.json ]; then npm ci; else npm install; fi

build: ## Compile TypeScript to dist (ESM + CJS + types)
	npm run build

typecheck: ## Type-check the sources without emitting
	npm run typecheck

lint: ## Run ESLint and the disable-validation guard
	npm run lint

test: ## Run the full test suite
	npm test

cover: ## Run tests with coverage; fail if below 90%
	npm run cover

pack-check: ## Build, verify the pack manifest, and scan the tarball for leaks/secrets
	npm run build
	npm run pack-check

check: typecheck lint test ## Type-check, lint, and test
ci: typecheck lint cover pack-check ## Full CI: typecheck, lint, coverage gate, pack/secret scan

clean: ## Remove build and coverage artifacts
	npm run clean
	rm -rf coverage *.tgz

release: ## Bump version (VERSION=patch|minor|major|X.Y.Z), tag, push, and publish to npm
	npm version $(VERSION)
	git push origin HEAD --follow-tags
	npm publish --access public
