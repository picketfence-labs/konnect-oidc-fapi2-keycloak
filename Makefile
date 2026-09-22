SHELL := /bin/bash

.PHONY: init fmt validate plan apply render render-runtime deck-validate deck-diff deck-sync up down destroy test

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
	./scripts/render-runtime-env.sh

render:
	./scripts/render-runtime-env.sh

render-runtime:
	./scripts/render-runtime-env.sh runtime

deck-validate: render
	./scripts/deck.sh validate

deck-diff: render
	./scripts/deck.sh diff

deck-sync: render
	./scripts/deck.sh sync

up: render-runtime
	docker compose --env-file .env --env-file .generated/runtime.env up -d

down:
	docker compose --env-file .env --env-file .generated/runtime.env down

destroy:
	./scripts/destroy.sh

test:
	python3 tests/test_static.py
