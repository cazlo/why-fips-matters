.PHONY: build up test shell down clean

build:
	docker compose build

up:
	docker compose up -d

test: build up
	docker compose exec tls-lab pytest -rA -vv

shell: up
	docker compose exec tls-lab bash

down:
	docker compose down --remove-orphans

clean: down
	rm -rf pcaps certs/server.crt certs/server.key
