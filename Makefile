SHELL := /bin/bash

.PHONY: init fmt validate plan apply generate-dev-assets render-runtime sync-demo-data plugin-schema-check plugin-schema-sync deck-validate deck-diff deck-sync up down destroy test test-plugin test-upstream01 test-wp5-observer test-wp5-transport

WP4_UPSTREAM01_RECEIPT ?= .generated/evidence/wp4-upstream01.json
WP5_OBSERVER_PYTHON ?= python3

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
	python3 tests/test_wp3_runtime.py
	python3 tests/test_wp3_flow.py
	python3 tests/test_wp3_query_guard.py
	python3 tests/test_wp3_tls_metadata.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_build_capture.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_minimal_image_context.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_observation_parser.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_reentry.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_reentry_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_stock_relay.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_stock_fixture.py
	$(WP5_OBSERVER_PYTHON) -m unittest tests.test_wp5_stock_flow
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_deck_selector.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_transport_fixture.py
	python3 tests/test_pki_generation.py
	python3 tests/test_up_guard.py
	luajit tests/test_wp1_schema.lua

test-plugin:
	luajit tests/test_plugin.lua
	luajit tests/test_wp5_transport.lua

test-upstream01:
	python3 tests/harness/upstream01.py --receipt "$(WP4_UPSTREAM01_RECEIPT)"

test-wp5-observer:
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_build_capture.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_minimal_image_context.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_observation_parser.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_reentry.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_reentry_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_stock_relay.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_observer_stock_fixture.py
	$(WP5_OBSERVER_PYTHON) -m unittest tests.test_wp5_stock_flow

test-wp5-transport:
	luajit tests/test_wp5_transport.lua
	luajit tests/test_plugin.lua
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_runtime.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_deck_selector.py
	$(WP5_OBSERVER_PYTHON) tests/test_wp5_transport_fixture.py
	$(WP5_OBSERVER_PYTHON) -m unittest tests.test_wp5_stock_flow
