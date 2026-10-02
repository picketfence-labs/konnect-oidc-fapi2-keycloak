SHELL := /bin/bash

.PHONY: init fmt validate plan apply generate-dev-assets render-runtime sync-demo-data plugin-schema-check plugin-schema-sync deck-validate deck-diff deck-sync up down destroy test test-plugin test-upstream01

WP4_UPSTREAM01_RECEIPT ?= .generated/evidence/wp4-upstream01.json

init:
	terraform -chdir=infra init

fmt:
	terraform -chdir=infra fmt -recursive

validate: init
	./scripts/validate.sh

plan: init
	./scripts/with-env.sh terraform -chdir=infra plan -out=tfplan

apply:
	./scripts/with-env.sh terraform -chdir=infra apply tfplan

generate-dev-assets:
	./scripts/generate-dev-assets.sh

render-runtime:
	./scripts/render-runtime-env.sh runtime

sync-demo-data: generate-dev-assets
	./scripts/sync-keycloak-demo-data.py

plugin-schema-check:
	GATEWAY="$(GATEWAY)" ./scripts/plugin-schema.sh check

plugin-schema-sync:
	GATEWAY="$(GATEWAY)" ./scripts/plugin-schema.sh sync

deck-validate:
	./scripts/deck.sh validate

deck-diff:
	GATEWAY="$(GATEWAY)" STAGE="$(STAGE)" ./scripts/deck.sh diff

deck-sync:
	GATEWAY="$(GATEWAY)" STAGE="$(STAGE)" ./scripts/deck.sh sync

up:
	./scripts/require-wp5-readiness.sh

down:
	docker compose --env-file .env --env-file .generated/runtime.env down

destroy:
	./scripts/destroy.sh

test:
	python3 tests/test_static.py
	python3 tests/test_jwk_export.py
	python3 tests/test_runtime_secrets.py
	python3 tests/test_wp1.py
	python3 tests/test_wp2.py
	python3 tests/test_pop_verifier.py
	python3 tests/test_pki_generation.py
	python3 tests/test_up_guard.py
	luajit tests/test_wp1_schema.lua

test-plugin:
	luajit tests/test_plugin.lua

test-upstream01:
	python3 tests/harness/upstream01.py --receipt "$(WP4_UPSTREAM01_RECEIPT)"
