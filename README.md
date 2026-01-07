# OSINT Platform V1

Open Source Intelligence platform for passive investigations.

## Features

- **3 Target Types**: DOMAIN, USERNAME, EMAIL
- **6 OSINT Techniques**: All passive, legal, non-intrusive
- **Audit Trail**: Full logging of all actions
- **Evidence Storage**: Immutable raw evidence + normalized findings

## Quick Start

```bash
# Start services
docker compose up -d --build

# Run migrations
docker compose exec api alembic upgrade head

# Verify
curl http://localhost:8000/healthz
curl http://localhost:8000/v1
```

## API Endpoints (V1)

All endpoints are prefixed with `/v1/`.

### Health (no prefix)

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness check |

### Authentication

| Endpoint | Description |
|----------|-------------|
| `POST /v1/auth/register` | Register user |
| `POST /v1/auth/login` | Get JWT token |
| `GET /v1/auth/me` | Current user |

### Workspaces

| Endpoint | Description |
|----------|-------------|
| `POST /v1/workspaces` | Create workspace |
| `GET /v1/workspaces` | List workspaces |
| `GET /v1/workspaces/{id}` | Get workspace |

### Targets

| Endpoint | Description |
|----------|-------------|
| `POST /v1/workspaces/{id}/targets/domain` | Create domain target |
| `POST /v1/workspaces/{id}/targets/email` | Create email target |
| `POST /v1/workspaces/{id}/targets/username` | Create username target |
| `GET /v1/workspaces/{id}/targets` | List targets |

### Jobs

| Endpoint | Description |
|----------|-------------|
| `POST /v1/workspaces/{id}/jobs` | Create job |
| `POST /v1/workspaces/{id}/jobs/{job_id}/enqueue` | Execute job |
| `GET /v1/workspaces/{id}/jobs` | List jobs |
| `GET /v1/workspaces/{id}/jobs/{job_id}` | Get job status |

### Findings

| Endpoint | Description |
|----------|-------------|
| `GET /v1/workspaces/{id}/findings` | List findings |
| `GET /v1/workspaces/{id}/findings/export/json` | Export findings |

## Enabled Techniques (V1)

| Technique | Target | Description |
|-----------|--------|-------------|
| `domain_dns_lookup` | DOMAIN | A, AAAA, MX, NS, TXT, SPF, DMARC |
| `domain_whois_rdap_lookup` | DOMAIN | RDAP/WHOIS registrar info |
| `username_github_lookup` | USERNAME | GitHub profile |
| `username_reddit_lookup` | USERNAME | Reddit profile |
| `email_mx_spf_dmarc_correlation` | EMAIL | Email domain config |
| `email_breach_lookup` | EMAIL | Breach database check |

## Usage Example

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass"}' | jq -r '.access_token')

# 2. Get workspace
WS=$(curl -s http://localhost:8000/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

# 3. Create target
TARGET=$(curl -s -X POST "http://localhost:8000/v1/workspaces/$WS/targets/domain" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | jq -r '.id')

# 4. Create and run job
JOB=$(curl -s -X POST "http://localhost:8000/v1/workspaces/$WS/jobs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"target_id\":\"$TARGET\",\"technique_code\":\"domain_dns_lookup\"}" | jq -r '.id')

curl -X POST "http://localhost:8000/v1/workspaces/$WS/jobs/$JOB/enqueue" \
  -H "Authorization: Bearer $TOKEN"

# 5. Check results
sleep 5
curl -s "http://localhost:8000/v1/workspaces/$WS/findings?target_id=$TARGET" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         API (FastAPI)                       │
│  /v1/auth  /v1/workspaces  /v1/jobs  /v1/findings          │
├──────────────────────┬──────────────────────────────────────┤
│     PostgreSQL       │           Redis                      │
│  (jobs, findings,    │  (rate limit, celery broker)        │
│   audit_logs)        │                                      │
├──────────────────────┼──────────────────────────────────────┤
│                      │           Celery Worker              │
│       MinIO          │  (execute techniques, store evidence)│
│   (raw evidence)     │                                      │
└──────────────────────┴──────────────────────────────────────┘
```

## Job State Machine

```
CREATED → QUEUED → RUNNING → SUCCEEDED
                     ↓
                  RETRYING → FAILED → DEAD_LETTER
```

## Security

- **Rate Limiting**: Atomic counters per user/IP
- **Audit Logging**: Automatic for all mutations
- **Technique Allowlist**: Only V1 techniques enabled
- **Production Checks**: Fail-fast on dangerous defaults

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ENV` | No | `local` / `prod` (default: local) |
| `JWT_SECRET_KEY` | **Yes (prod)** | JWT signing key |
| `DATABASE_URL` | No | PostgreSQL connection |
| `REDIS_URL` | No | Redis connection |

### Production Deployment

```bash
# Generate secrets
export JWT_SECRET_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

# Deploy
ENV=prod docker compose -f docker-compose.prod.yml up -d
```

## Development

```bash
# API
cd api && poetry install
poetry run uvicorn app.main:app --reload

# Worker  
cd worker && poetry install
poetry run celery -A worker_app.celery_app worker -l INFO
```

## Services

| Service | Port | URL |
|---------|------|-----|
| API | 8000 | http://localhost:8000 |
| Docs | 8000 | http://localhost:8000/docs |
| MinIO | 9001 | http://localhost:9001 |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3000 | http://localhost:3000 |

## License

MIT
