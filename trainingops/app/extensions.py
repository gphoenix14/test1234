from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"


def _limiter_storage_uri(app) -> str:
    # In produzione meglio Redis: REDIS_URL=redis://...
    if app.config.get("REDIS_URL"):
        return app.config["REDIS_URL"]
    return "memory://"


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",  # verrà impostato correttamente in init
)
