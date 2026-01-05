import os
import logging
from flask import Flask, request, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from jinja2 import DictLoader

from .config import DevelopmentConfig, ProductionConfig
from .extensions import db, login_manager, limiter
from .extensions import _limiter_storage_uri
from .routes import bp, auth, admin, docente_bp, api
from .security import canonical_host_check_or_abort, csrf_origin_referer_check_or_abort, nl2br_safe
from .templates_embedded import TEMPLATES


def _parse_allowed_hosts() -> set[str]:
    raw = (os.environ.get("ALLOWED_HOSTS") or "").strip()
    base = {"localhost", "127.0.0.1", "0.0.0.0"}
    if not raw:
        return base
    extra = {h.strip().lower() for h in raw.split(",") if h.strip()}
    return base | extra


def create_app(env_name: str = "production") -> Flask:
    # Single app instance (keep instance_relative_config for instance folder usage)
    app = Flask(__name__, instance_relative_config=True)

    # IMPORTANT: avoid 400/KeyError due to missing SERVER_NAME
    # Do NOT call app.config(...) because config is not callable.
    app.config["SERVER_NAME"] = None

    allowed_hosts_set = _parse_allowed_hosts()

    @app.before_request
    def _enforce_allowed_host():
        host = (request.host or "").split(":", 1)[0].lower().strip()
        if not host or host not in allowed_hosts_set:
            abort(400)

    # Config
    if env_name == "development":
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    # UPLOAD_ROOT default
    if not app.config.get("UPLOAD_ROOT"):
        base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        app.config["UPLOAD_ROOT"] = os.path.join(base_dir, "uploads")
    os.makedirs(app.config["UPLOAD_ROOT"], exist_ok=True)

    # Audit log path (instance)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["AUDIT_LOG_PATH"] = os.path.join(app.instance_path, "audit.log")

    # Logging base
    app.logger.setLevel(logging.INFO)

    # Reverse proxy support
    if app.config.get("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # DB
    db.init_app(app)

    # Login
    login_manager.init_app(app)
    login_manager.session_protection = "strong"

    # Limiter
    limiter.storage_uri = _limiter_storage_uri(app)
    limiter.init_app(app)

    # Templates embedded
    app.jinja_loader = DictLoader(TEMPLATES)

    # Jinja filters anti-XSS for textareas/notes
    app.jinja_env.filters["nl2br_safe"] = nl2br_safe

    # Register blueprints
    app.register_blueprint(bp)
    app.register_blueprint(auth)
    app.register_blueprint(admin)
    app.register_blueprint(docente_bp)
    app.register_blueprint(api)

    # Security headers (OWASP: Security Misconfiguration / XSS / Clickjacking)
    @app.after_request
    def set_security_headers(resp):
        # Non impostare HSTS se non sei dietro HTTPS
        # Se sei dietro TLS terminato su reverse proxy, assicurati che X-Forwarded-Proto=https e ProxyFix attivo.
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # CSP base (adatta se hai CDN o inline scripts)
        # Se i tuoi template usano inline script, dovrai allentare 'script-src' con nonce o 'unsafe-inline' (sconsigliato).
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        return resp

    # OWASP: Host header attack + CSRF Origin/Referer check
    @app.before_request
    def global_security_checks():
        canonical_host_check_or_abort()
        # CSRF check solo per state-changing su session auth (compatibile con template legacy)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_origin_referer_check_or_abort()

    # Error handlers (no leakage stacktrace)
    @app.errorhandler(400)
    def bad_request(e):
        return "Bad Request", 400

    @app.errorhandler(403)
    def forbidden(e):
        return "Forbidden", 403

    @app.errorhandler(404)
    def not_found(e):
        return "Not Found", 404

    @app.errorhandler(429)
    def rate_limited(e):
        return "Too Many Requests", 429

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal Server Error")
        return "Internal Server Error", 500

    return app
