import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg://osint:osint@localhost:5432/osint")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-openssl-rand-hex-32")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Rate Limiting (requests per minute)
    RATE_LIMIT_AUTH: int = 5
    RATE_LIMIT_READ: int = 120
    RATE_LIMIT_MUTATE: int = 30

    class Config:
        env_file = ".env"


settings = Settings()

