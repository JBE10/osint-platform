# OSINT Platform

Open Source Intelligence platform for investigations and data gathering.

## Stack

| Component | Technology |
|-----------|------------|
| API | FastAPI + Uvicorn |
| Database | PostgreSQL 16 |
| Cache/Broker | Redis 7 |
| Worker | Celery |
| Migrations | Alembic |
| Object Storage | MinIO |
| Monitoring | Prometheus + Grafana |
| Package Manager | Poetry |

## Quick Start

```bash
# Clone and start
git clone <repo>
cd osint-platform

# Start all services
docker compose up -d --build

# Run migrations
docker compose exec api alembic upgrade head

# Verify
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
```

## Health Endpoints

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /healthz` | Liveness probe | `{"ok": true}` |
| `GET /readyz` | Readiness probe (DB + Redis) | `{"ok": true, "db": true, "redis": true}` |
| `GET /` | API info | `{"name": "osint-platform", "version": "0.1.0"}` |

## Services

| Service | Port | URL |
|---------|------|-----|
| API | 8000 | http://localhost:8000 |
| API Docs | 8000 | http://localhost:8000/docs |
| PostgreSQL | 5432 | - |
| Redis | 6379 | - |
| MinIO Console | 9001 | http://localhost:9001 |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3000 | http://localhost:3000 |

## Development

### Local Setup (with Poetry)

```bash
# API
cd api
poetry install
poetry run uvicorn app.main:app --reload

# Worker
cd worker
poetry install
poetry run celery -A worker_app.celery_app worker --loglevel=INFO
```

### Migrations

```bash
# Inside container
docker compose exec api alembic revision -m "description"
docker compose exec api alembic upgrade head

# Local
cd api
poetry run alembic revision -m "description"
poetry run alembic upgrade head
```

## Project Structure

```
osint-platform/
├── api/                    # FastAPI service
│   ├── app/
│   │   ├── main.py
│   │   ├── core/           # Config, logging
│   │   ├── db/             # Database session
│   │   └── routers/        # API routes
│   ├── alembic/            # Migrations
│   ├── pyproject.toml
│   └── poetry.lock
├── worker/                 # Celery worker
│   ├── worker_app/
│   │   ├── celery_app.py
│   │   └── tasks.py
│   ├── pyproject.toml
│   └── poetry.lock
├── shared/                 # Shared utilities
├── infra/                  # Prometheus, Grafana configs
└── docker-compose.yml
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+psycopg://osint:osint@postgres:5432/osint` | PostgreSQL connection |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection |
| `CELERY_BROKER_URL` | `redis://redis:6379/1` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/2` | Celery results |
