"""
Centralized database configuration for MONI persistence stores.

Provides a single backend-selection and .env-loading policy shared by both
alerts/alert_store.py (AlertStore) and telemetry/live_metrics.py
(LiveMetricsStore) so independent processes and stores always resolve
the exact same database backend without credential fallbacks.
"""

from dataclasses import dataclass
import os
import re
import sqlite3
from typing import Mapping, Optional
from urllib.parse import urlsplit

try:
    from dotenv import load_dotenv as _dotenv_load
except ImportError:  # pragma: no cover - optional fallback if python-dotenv missing
    _dotenv_load = None


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ENV_FILE = os.path.join(PROJECT_ROOT, ".env")
DEFAULT_ALERTS_DB_FILE = os.path.join(PROJECT_ROOT, "ctd_alerts.db")
DEFAULT_METRICS_DB_FILE = os.path.join(PROJECT_ROOT, "ctd_metrics.db")
DEFAULT_CONNECT_TIMEOUT = 1

_PLACEHOLDER_TOKENS = ("YOUR_PASSWORD", "CHANGE_ME", "<password>")
_VALID_POSTGRES_SCHEMES = {"postgresql", "postgres"}
_POSTGRES_MODES = {"postgres", "postgresql", "prod", "production"}
_SQLITE_MODES = {"sqlite", "sqlite3", "dev", "development", "demo"}
_AUTO_MODES = {"", "auto"}
_TRUTHY_VALUES = {"1", "true", "yes", "on"}
_FALSY_VALUES = {"", "0", "false", "no", "off"}

_CREDENTIAL_URI_RE = re.compile(
    r"((?:postgresql|postgres)://)([^:/@\s]+):([^@\s]+)@",
    flags=re.IGNORECASE,
)


class DatabaseConfigError(RuntimeError):
    """Raised when database configuration is invalid or violates strict policy."""


class DatabaseConnectionError(RuntimeError):
    """Raised when strict PostgreSQL mode cannot connect or execute against PostgreSQL."""


@dataclass(frozen=True)
class DatabaseConfig:
    """Resolved database backend configuration for a MONI store."""

    store_name: str
    backend: str
    policy: str
    database_url: Optional[str]
    sqlite_path: str
    strict_postgres: bool
    connect_timeout: int
    reason: str
    url_configured: bool
    url_scheme: str
    dotenv_loaded: bool

    def safe_target(self) -> str:
        """Return a credential-free target description for diagnostics and logs."""
        if self.backend == "postgres" and self.database_url:
            return describe_postgres_url(self.database_url)
        return self.sqlite_path

    @property
    def allow_fallback(self) -> bool:
        """Return True only for automatic ('auto') non-strict PostgreSQL policy."""
        return (
            self.backend == "postgres"
            and self.policy == "auto"
            and not self.strict_postgres
        )

    def to_safe_dict(
        self,
        active_backend: Optional[str] = None,
        fallback_used: bool = False,
    ) -> dict:
        """Return credential-free backend status metadata."""
        resolved_active = active_backend or self.backend
        target = (
            describe_postgres_url(self.database_url)
            if resolved_active == "postgres" and self.database_url
            else self.sqlite_path
        )
        return {
            "store": self.store_name,
            "policy": self.policy,
            "configured_backend": self.backend,
            "active_backend": resolved_active,
            "strict_postgres": self.strict_postgres,
            "allow_fallback": self.allow_fallback,
            "fallback_used": bool(fallback_used),
            "target": target,
            "reason": self.reason,
        }


def redact_database_url(text: str, database_url: Optional[str] = None) -> str:
    """Scrub database credentials and raw URLs from log or exception messages."""
    sanitized = str(text)
    if database_url:
        safe_desc = describe_postgres_url(database_url)
        sanitized = sanitized.replace(database_url, safe_desc)
        try:
            parsed = urlsplit(database_url)
            if parsed.password:
                sanitized = sanitized.replace(parsed.password, "***")
        except Exception:
            pass
    return _CREDENTIAL_URI_RE.sub(r"\1***:***@", sanitized)


def describe_postgres_url(url: str) -> str:
    """Format a PostgreSQL URL cleanly without username or password."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme or "postgresql"
        host = parsed.hostname or "unknown-host"
        port = parsed.port or 5432
        db_name = parsed.path.lstrip("/") or "default"
        return f"{scheme}://{host}:{port}/{db_name}"
    except Exception:
        return "postgresql://<redacted>"


def load_project_env(env_file: Optional[str] = DEFAULT_ENV_FILE) -> bool:
    """
    Load the workspace .env file without overriding explicit process environment variables.

    Explicit environment settings (including empty strings such as DATABASE_URL="")
    always retain precedence so CLI overrides behave consistently across processes.
    """
    if _dotenv_load is None or not env_file or not os.path.isfile(env_file):
        return False
    return bool(_dotenv_load(dotenv_path=env_file, override=False))


def _parse_bool_env(env: Mapping[str, str], names: tuple[str, ...]) -> bool:
    """Parse boolean feature flags deterministically; reject invalid non-empty values."""
    for name in names:
        if name not in env:
            continue
        raw = str(env[name]).strip().lower()
        if raw in _TRUTHY_VALUES:
            return True
        if raw in _FALSY_VALUES:
            return False
        raise DatabaseConfigError(
            f"Invalid boolean value for {name}={env[name]!r}; expected true/false or 1/0."
        )
    return False


def _parse_connect_timeout(env: Mapping[str, str]) -> int:
    raw = str(env.get("CTD_DB_CONNECT_TIMEOUT", str(DEFAULT_CONNECT_TIMEOUT))).strip()
    if not raw:
        return DEFAULT_CONNECT_TIMEOUT
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise DatabaseConfigError(
            f"Invalid CTD_DB_CONNECT_TIMEOUT={raw!r}; expected positive integer seconds."
        ) from exc
    if timeout <= 0:
        raise DatabaseConfigError(
            f"Invalid CTD_DB_CONNECT_TIMEOUT={timeout}; expected > 0 seconds."
        )
    return timeout


def _classify_database_url(raw_url: Optional[str]) -> tuple[str, Optional[str], str]:
    """Classify DATABASE_URL without storing or exposing credentials on invalid states."""
    if raw_url is None:
        return "unset", None, "NONE"
    stripped = str(raw_url).strip()
    if stripped == "":
        return "empty", None, "NONE"
    if any(token in stripped for token in _PLACEHOLDER_TOKENS):
        return "placeholder", None, "NONE"

    try:
        parsed = urlsplit(stripped)
        scheme = (parsed.scheme or "").lower()
        if scheme not in _VALID_POSTGRES_SCHEMES or not parsed.hostname:
            return "invalid", None, scheme or "NONE"
    except Exception:
        return "invalid", None, "NONE"

    return "valid", stripped, scheme


def resolve_database_config(
    store_name: str,
    db_path: Optional[str] = None,
    default_sqlite_path: Optional[str] = None,
    env_file: Optional[str] = DEFAULT_ENV_FILE,
    environ: Optional[Mapping[str, str]] = None,
) -> DatabaseConfig:
    """
    Resolve the unified backend configuration for a MONI store.

    Policy precedence:
      1. Explicit `db_path` argument forces isolated SQLite at `db_path`.
      2. `CTD_DB_BACKEND` selects policy (`auto`, `postgres`, or `sqlite`).
         Explicit SQLite development/demo mode cannot be combined with strict PostgreSQL mode.
      3. `DATABASE_URL` must be a non-empty, non-placeholder postgresql:// URI for PostgreSQL.
      4. `CTD_DB_STRICT` (or alias `CTD_REQUIRE_POSTGRES`) fails cleanly at startup
         whenever PostgreSQL is unconfigured or unavailable rather than falling back to SQLite.
    """
    if default_sqlite_path is not None:
        fallback_sqlite = default_sqlite_path
    elif store_name == "alerts":
        fallback_sqlite = DEFAULT_ALERTS_DB_FILE
    else:
        fallback_sqlite = DEFAULT_METRICS_DB_FILE

    if db_path is not None:
        return DatabaseConfig(
            store_name=store_name,
            backend="sqlite",
            policy="sqlite",
            database_url=None,
            sqlite_path=db_path,
            strict_postgres=False,
            connect_timeout=DEFAULT_CONNECT_TIMEOUT,
            reason="explicit db_path override",
            url_configured=False,
            url_scheme="NONE",
            dotenv_loaded=False,
        )

    dotenv_loaded = False
    if environ is None:
        dotenv_loaded = load_project_env(env_file=env_file)
        env: Mapping[str, str] = os.environ
    else:
        env = environ

    strict_postgres = _parse_bool_env(env, ("CTD_DB_STRICT", "CTD_REQUIRE_POSTGRES"))
    connect_timeout = _parse_connect_timeout(env)

    raw_backend = str(env.get("CTD_DB_BACKEND", "auto")).strip().lower()
    if raw_backend in _AUTO_MODES:
        policy = "auto"
    elif raw_backend in _POSTGRES_MODES:
        policy = "postgres"
    elif raw_backend in _SQLITE_MODES:
        policy = "sqlite"
    else:
        raise DatabaseConfigError(
            f"[{store_name}] Unsupported CTD_DB_BACKEND={raw_backend!r}; "
            "expected 'auto', 'postgres', or 'sqlite'."
        )

    if policy == "sqlite":
        if strict_postgres:
            raise DatabaseConfigError(
                f"[{store_name}] Conflicting database configuration: "
                "explicit SQLite mode (CTD_DB_BACKEND) cannot be combined with "
                "strict PostgreSQL mode (CTD_DB_STRICT / CTD_REQUIRE_POSTGRES)."
            )
        return DatabaseConfig(
            store_name=store_name,
            backend="sqlite",
            policy="sqlite",
            database_url=None,
            sqlite_path=fallback_sqlite,
            strict_postgres=False,
            connect_timeout=connect_timeout,
            reason=f"explicit SQLite development/demo mode (CTD_DB_BACKEND={raw_backend})",
            url_configured=False,
            url_scheme="NONE",
            dotenv_loaded=dotenv_loaded,
        )

    url_status, clean_url, url_scheme = _classify_database_url(env.get("DATABASE_URL"))
    if url_status != "valid":
        reason_map = {
            "unset": "DATABASE_URL is unset",
            "empty": "DATABASE_URL is empty",
            "placeholder": "DATABASE_URL uses placeholder password",
            "invalid": "DATABASE_URL is not a valid PostgreSQL URI",
        }
        reason = reason_map[url_status]
        if strict_postgres or policy == "postgres":
            mode_desc = (
                "strict PostgreSQL mode" if strict_postgres else "CTD_DB_BACKEND=postgres"
            )
            raise DatabaseConfigError(
                f"[{store_name}] PostgreSQL backend required ({mode_desc}), but {reason}."
            )
        return DatabaseConfig(
            store_name=store_name,
            backend="sqlite",
            policy="auto",
            database_url=None,
            sqlite_path=fallback_sqlite,
            strict_postgres=False,
            connect_timeout=connect_timeout,
            reason=reason,
            url_configured=False,
            url_scheme=url_scheme,
            dotenv_loaded=dotenv_loaded,
        )

    return DatabaseConfig(
        store_name=store_name,
        backend="postgres",
        policy=policy,
        database_url=clean_url,
        sqlite_path=fallback_sqlite,
        strict_postgres=strict_postgres,
        connect_timeout=connect_timeout,
        reason=f"DATABASE_URL configured ({url_scheme})",
        url_configured=True,
        url_scheme=url_scheme,
        dotenv_loaded=dotenv_loaded,
    )


def connect_postgres(
    database_url: str,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
):
    """Open a PostgreSQL connection with consistent timeout enforcement."""
    import psycopg

    return psycopg.connect(database_url, connect_timeout=connect_timeout)


_SHUTDOWN_CONNECTION_SQLSTATES = {"57P01", "57P02", "57P03"}


def get_sqlstate(exc: Exception) -> Optional[str]:
    sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    return str(sqlstate).strip().upper() if sqlstate is not None else None


def is_integrity_error(exc: Exception) -> bool:
    """Return True for SQLite or PostgreSQL data-integrity constraint violations."""
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    try:
        import psycopg

        if isinstance(exc, psycopg.IntegrityError):
            return True
    except ImportError:
        pass
    sqlstate = get_sqlstate(exc)
    return bool(sqlstate and sqlstate.startswith("23"))


def is_connection_error(exc: Exception) -> bool:
    """
    Return True for genuine database connection/availability failures.

    Checks SQLSTATE before psycopg base classes because QueryCanceled (57014)
    inherits from psycopg.OperationalError yet must NOT trigger SQLite fallback.
    """
    if is_integrity_error(exc):
        return False

    sqlstate = get_sqlstate(exc)
    if sqlstate is not None:
        return sqlstate.startswith("08") or sqlstate in _SHUTDOWN_CONNECTION_SQLSTATES

    if isinstance(exc, (OSError, ImportError)):
        return True
    try:
        import psycopg

        if isinstance(exc, (psycopg.OperationalError, psycopg.InterfaceError)):
            return True
    except ImportError:
        pass
    return False


def verify_postgres_reachable(
    database_url: Optional[str],
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> bool:
    """Probe whether PostgreSQL accepts new connections and executes SELECT 1."""
    if not database_url:
        return False
    try:
        with connect_postgres(database_url, connect_timeout=connect_timeout) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        return True
    except Exception:
        return False


def handle_postgres_exception(
    store_label: str,
    operation: str,
    exc: Exception,
    *,
    db_config: DatabaseConfig,
    connection=None,
    allow_fallback: bool = True,
) -> str:
    """
    Classify a PostgreSQL runtime exception and decide recovery action.

    Returns "fallback" ONLY when connection failure occurs in automatic non-strict
    mode on a non-destructive operation. Otherwise logs cleanly and raises.
    """
    safe_msg = redact_database_url(
        f"{type(exc).__name__}: {exc}",
        db_config.database_url,
    )

    if is_integrity_error(exc):
        print(
            f"[{store_label}] PostgreSQL data-integrity error in {operation}: {safe_msg}",
            flush=True,
        )
        raise exc

    if is_connection_error(exc):
        sqlstate = get_sqlstate(exc)
        if sqlstate == "57P01":
            conn_closed = getattr(connection, "closed", None)
            conn_broken = getattr(connection, "broken", None)
            if (conn_closed is False and conn_broken is False) or verify_postgres_reachable(
                db_config.database_url,
                connect_timeout=db_config.connect_timeout,
            ):
                print(
                    f"[{store_label}] PostgreSQL administrative session termination (57P01) "
                    f"in {operation}; server remains reachable, keeping PostgreSQL active: {safe_msg}",
                    flush=True,
                )
                raise exc

        print(
            f"[{store_label}] PostgreSQL connection error in {operation}: {safe_msg}",
            flush=True,
        )
        if allow_fallback and db_config.allow_fallback:
            return "fallback"

        if not allow_fallback:
            reason = f"destructive/non-fallback operation '{operation}' cannot fail over to SQLite"
        elif db_config.strict_postgres:
            reason = "strict PostgreSQL mode enabled"
        else:
            reason = "explicit PostgreSQL backend (CTD_DB_BACKEND=postgres) forbids silent fallback"
        raise DatabaseConnectionError(
            f"[{store_label}] PostgreSQL {operation} failed ({reason}): {safe_msg}"
        ) from exc

    print(
        f"[{store_label}] PostgreSQL error in {operation}: {safe_msg}",
        flush=True,
    )
    raise exc
