# NetAudit – Makefile
.PHONY: up down build logs shell-backend shell-mongo ps clean reset debug

## ── Dev shortcuts ──────────────────────────────────────────────────────────

# Start all services (prod profile)
up:
	cp -n .env.example .env 2>/dev/null || true
	docker compose up -d --build
	@echo ""
	@echo "  🟢 NetAudit is running"
	@echo "  Frontend  → http://localhost"
	@echo "  API docs  → http://localhost:8000/docs"
	@echo "  API       → http://localhost:8000/api"
	@echo ""

# Start with Mongo Express UI (debug profile)
debug:
	cp -n .env.example .env 2>/dev/null || true
	docker compose --profile debug up -d --build
	@echo "  Mongo UI  → http://localhost:8081"

# Stop all services
down:
	docker compose down

# Rebuild images without cache
build:
	docker compose build --no-cache

# Follow logs
logs:
	docker compose logs -f

logs-backend:
	docker compose logs -f backend

logs-mongo:
	docker compose logs -f mongodb

# Shell access
shell-backend:
	docker compose exec backend bash

shell-mongo:
	docker compose exec mongodb mongosh \
	  --username $${MONGO_USER:-admin} \
	  --password $${MONGO_PASSWORD:-changeme_strong_password} \
	  --authenticationDatabase admin \
	  netaudit

# Status
ps:
	docker compose ps

# Remove containers + volumes (WARNING: deletes all data)
clean:
	docker compose down -v --remove-orphans
	@echo "⚠️  All containers and volumes removed."

# Full reset: clean + rebuild
reset: clean up
