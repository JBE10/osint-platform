import os
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL)

def check_redis() -> bool:
    try:
        return redis_client.ping() is True
    except Exception:
        return False
