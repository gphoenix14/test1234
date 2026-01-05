import os

def _env_bool(key: str, default: bool = False) -> bool:
    v = (os.getenv(key, str(default)) or "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")

class BaseConfig:
    APP_NAME = "TrainingOps Simple"

    SECRET_KEY = os.getenv("APP_SECRET_KEY", "change-me-in-production-please")

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_size": 10,
        "max_overflow": 20,
    }

    # Upload
    UPLOAD_ROOT = os.getenv("UPLOAD_ROOT", None)  # se None, sarà impostato da create_app()
    MAX_CV_MB = int(os.getenv("MAX_CV_MB", "10"))
    MAX_CONTENT_LENGTH = MAX_CV_MB * 1024 * 1024

    # Security cookies
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SECURE = _env_bool("REMEMBER_COOKIE_SECURE", True)

    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_SAMESITE = os.getenv("REMEMBER_COOKIE_SAMESITE", "Lax")

    # Reverse proxy trust
    TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", True)

    # Canonical host (anti Host header attacks / CSRF referer/origin allowlist)
    CANONICAL_HOST = os.getenv("CANONICAL_HOST", "").strip()  # es: "example.com"

    # Rate limit storage
    REDIS_URL = os.getenv("REDIS_URL", "").strip()

    # Limiter defaults (tuning)
    LIMITER_DEFAULT = "200 per hour"
    LIMITER_LOGIN = "8 per minute"
    LIMITER_INVITE = "10 per hour"
    LIMITER_SENSITIVE = "30 per minute"

class DevelopmentConfig(BaseConfig):
    DEBUG = True

class ProductionConfig(BaseConfig):
    DEBUG = False
