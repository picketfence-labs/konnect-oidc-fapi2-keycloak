SHELL := /bin/bash

.PHONY: init fmt validate plan apply generate-dev-assets render-runtime sync-demo-data plugin-schema-check plugin-schema-sync deck-validate deck-diff deck-sync up down destroy test test-plugin

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
	./scripts/plugin-schema.sh check

plugin-schema-sync:
	./scripts/plugin-schema.sh sync

deck-validate:
	./scripts/deck.sh validate

deck-diff:
	./scripts/deck.sh diff

deck-sync:
	./scripts/deck.sh sync

up: generate-dev-assets render-runtime
	docker compose --env-file .env --env-file .generated/runtime.env up -d
	./scripts/sync-keycloak-demo-data.py

down:
	docker compose --env-file .env --env-file .generated/runtime.env down

destroy:
	./scripts/destroy.sh

test:
	python3 tests/test_static.py
	python3 tests/test_jwk_export.py
	python3 tests/test_runtime_secrets.py

test-plugin:
	luajit tests/test_plugin.lua
