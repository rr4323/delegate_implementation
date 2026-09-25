import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-not-for-prod")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "delegates",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # CommonMiddleware is deliberately omitted: its APPEND_SLASH/host
    # handling calls request.get_host(), which rejects Docker Compose
    # service hostnames containing underscores (e.g. "control_plane")
    # regardless of ALLOWED_HOSTS. Not needed for this JSON-only API.
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "control_plane.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "control_plane.wsgi.application"

DB_DIR = os.environ.get("DB_DIR", str(BASE_DIR / "db"))
os.makedirs(DB_DIR, exist_ok=True)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(DB_DIR, "control_plane.sqlite3"),
        "OPTIONS": {"timeout": 20},
    }
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REDIS_URL = os.environ.get("REDIS_URL", "rediss://redis:6379/0")
RESTART_GATEWAY_CONTROL_URL = os.environ.get("RESTART_GATEWAY_CONTROL_URL", "http://restart_gateway:8766")

CA_DIR = os.environ.get("CA_DIR", str(BASE_DIR / "ca"))
os.makedirs(CA_DIR, exist_ok=True)

MEDIA_ROOT = os.environ.get("MEDIA_ROOT", str(BASE_DIR / "media"))
os.makedirs(MEDIA_ROOT, exist_ok=True)

WORKSPACE_FIXTURES_DIR = os.environ.get("WORKSPACE_FIXTURES_DIR", "/fixtures")

DELEGATE_CERT_VALIDITY_DAYS = int(os.environ.get("DELEGATE_CERT_VALIDITY_DAYS", "1"))
REGISTRATION_TOKEN_TTL_SECONDS = int(os.environ.get("REGISTRATION_TOKEN_TTL_SECONDS", "300"))
TRANSFER_WAIT_TIMEOUT_SECONDS = float(os.environ.get("TRANSFER_WAIT_TIMEOUT_SECONDS", "15"))

# Extra SAN entries (comma-separated hostnames and/or IPs) baked into the
# Redis / control-plane server certs at issuance, on top of the in-compose-
# network defaults (see delegates/ca.py). Needed the moment a delegate
# reaches either service by an address other than "redis"/"control_plane"/
# "restart_gateway"/"localhost" -- e.g. a remote deployment's public IP or
# DNS name -- since ssl_check_hostname=True on every client here rejects a
# handshake to any address not in the presented cert's SAN list, regardless
# of whether the cert chain itself is valid. Only takes effect on a cert that
# doesn't exist yet: delete the matching *_server.crt/.key in CA_DIR to force
# reissuance after changing this.
REDIS_EXTRA_SAN_NAMES = [n.strip() for n in os.environ.get("REDIS_EXTRA_SAN_NAMES", "").split(",") if n.strip()]
CONTROL_PLANE_EXTRA_SAN_NAMES = [n.strip() for n in os.environ.get("CONTROL_PLANE_EXTRA_SAN_NAMES", "").split(",") if n.strip()]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
