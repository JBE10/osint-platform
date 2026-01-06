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

## Architecture

### Job State Machine

```
CREATED → QUEUED → RUNNING → SUCCEEDED
                     ↓
                  RETRYING → FAILED → DEAD_LETTER
                     ↑_________|
```

| Status | Description |
|--------|-------------|
| CREATED | Job persisted, not yet sent to Celery |
| QUEUED | Sent to broker |
| RUNNING | Worker processing |
| RETRYING | Failed but will retry |
| SUCCEEDED | Completed successfully |
| FAILED | Non-recoverable error |
| DEAD_LETTER | Exhausted retries |
| CANCELLED | Manually cancelled |

### Data Model

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Workspaces │────<│   Targets   │────<│    Jobs     │
└─────────────┘     └─────────────┘     └─────┬───────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
              ┌─────▼─────┐            ┌──────▼──────┐           ┌──────▼──────┐
              │ Raw       │            │  Findings   │           │   Audit     │
              │ Evidence  │            │ (normalized)│           │   Logs      │
              └───────────┘            └─────────────┘           └─────────────┘
```

### Job Flow

```
API                                     Worker
────                                    ──────
1. POST /jobs                           
   └─ Insert job (CREATED)              
   └─ Generate idempotency_key          
                                        
2. POST /jobs/{id}/enqueue              
   └─ Send to Celery                    
   └─ Update → QUEUED                   
                                        3. Receive job_id (ONLY)
                                           └─ Rehydrate from DB
                                           └─ Update → RUNNING
                                           └─ Execute technique
                                           └─ Store raw_evidence (MinIO)
                                           └─ Upsert findings (fingerprint)
                                           └─ Update → SUCCEEDED
```

## API Endpoints

### Health

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /healthz` | Liveness probe | `{"ok": true}` |
| `GET /readyz` | Readiness probe | `{"ok": true, "db": true, "redis": true}` |

### Authentication

| Endpoint | Description |
|----------|-------------|
| `POST /auth/register` | Register user |
| `POST /auth/login` | Get JWT token |
| `GET /auth/me` | Current user info |

### Workspaces

| Endpoint | Description |
|----------|-------------|
| `POST /workspaces` | Create workspace |
| `GET /workspaces/{id}` | Get workspace |
| `POST /workspaces/{id}/members` | Add member |

### Targets

| Endpoint | Description |
|----------|-------------|
| `POST /workspaces/{id}/targets/email` | Create email target |
| `POST /workspaces/{id}/targets/domain` | Create domain target |
| `GET /workspaces/{id}/targets` | List targets |

### Jobs

| Endpoint | Description |
|----------|-------------|
| `POST /workspaces/{id}/jobs` | Create job (CREATED) |
| `GET /workspaces/{id}/jobs` | List jobs |
| `GET /workspaces/{id}/jobs/{job_id}` | Get job |
| `POST /workspaces/{id}/jobs/{job_id}/enqueue` | Enqueue job (QUEUED) |
| `POST /workspaces/{id}/jobs/{job_id}/requeue` | Requeue failed job |
| `POST /workspaces/{id}/jobs/{job_id}/cancel` | Cancel job |
| `GET /workspaces/{id}/jobs/{job_id}/findings` | Get job findings |

### Findings

| Endpoint | Description |
|----------|-------------|
| `GET /workspaces/{id}/findings` | List findings |
| `GET /workspaces/{id}/findings/search?q=` | Search findings |
| `GET /workspaces/{id}/findings/stats` | Aggregated stats |
| `GET /workspaces/{id}/findings/{finding_id}` | Get finding |

### Evidence

| Endpoint | Description |
|----------|-------------|
| `GET /workspaces/{id}/evidence` | List evidence metadata |
| `GET /workspaces/{id}/evidence/{evidence_id}` | Get evidence metadata |
| `GET /workspaces/{id}/evidence/{evidence_id}/content` | Get full content (ADMIN) |
| `GET /workspaces/{id}/evidence/job/{job_id}/files` | List job evidence files |

## Techniques

| Code | Description |
|------|-------------|
| `dns_lookup` | DNS records (A, AAAA, MX, NS, TXT) |
| `whois_lookup` | WHOIS information |
| `email_verify` | Email deliverability check |
| `port_scan` | Basic port scan |

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
│   │   ├── core/           # Config, security, storage
│   │   ├── db/             # Database session
│   │   ├── models/         # SQLAlchemy models
│   │   └── routers/        # API routes
│   ├── alembic/            # Migrations
│   ├── pyproject.toml
│   └── poetry.lock
├── worker/                 # Celery worker
│   ├── worker_app/
│   │   ├── celery_app.py
│   │   └── tasks.py        # OSINT techniques
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
| `MINIO_ENDPOINT` | `minio:9000` | MinIO endpoint |
| `MINIO_ACCESS_KEY` | `minio` | MinIO access key |
| `MINIO_SECRET_KEY` | `minio123456` | MinIO secret key |
| `MINIO_BUCKET` | `evidence` | Evidence bucket |
| `SECRET_KEY` | (required) | JWT signing key |

## Idempotency

Jobs use idempotency keys to prevent duplicates:

```
idempotency_key = sha256(
  workspace_id +
  target_id +
  technique_code +
  canonical_json(params) +
  "v1"
)
```

If a job with the same key exists, the existing job is returned (no duplicate created).

## Findings Deduplication

Findings use fingerprints for upsert behavior:

```
finding_fingerprint = sha256(
  workspace_id +
  finding_type +
  subject +
  stable_data
)
```

Same fingerprint = update `last_seen_at`, different = new finding.
