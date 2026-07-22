from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from context_breach_env.gateway.models import AuthorizationAuditRecord


class GatewayStateError(RuntimeError):
    """Raised when security state cannot be read or committed safely."""


class AuditStore(Protocol):
    def append_audit(self, record: AuthorizationAuditRecord) -> None: ...

    def get_audit(self, audit_id: str) -> AuthorizationAuditRecord | None: ...


class NonceStore(Protocol):
    def consume_nonce(self, *, key_id: str, nonce: str, expires_at: int, now: int) -> bool: ...


class GatewayStateStore(AuditStore, NonceStore, Protocol):
    def health_check(self) -> None: ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._records: dict[str, AuthorizationAuditRecord] = {}
        self._lock = threading.Lock()

    def append_audit(self, record: AuthorizationAuditRecord) -> None:
        with self._lock:
            if record.audit_id in self._records:
                raise GatewayStateError("duplicate audit ID")
            self._records[record.audit_id] = record.model_copy(deep=True)

    def get_audit(self, audit_id: str) -> AuthorizationAuditRecord | None:
        with self._lock:
            record = self._records.get(audit_id)
            return record.model_copy(deep=True) if record is not None else None


class InMemoryNonceStore:
    def __init__(self) -> None:
        self._used: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def consume_nonce(self, *, key_id: str, nonce: str, expires_at: int, now: int) -> bool:
        nonce_key = (key_id, nonce)
        with self._lock:
            self._used = {
                existing: expiry
                for existing, expiry in self._used.items()
                if expiry > now
            }
            if nonce_key in self._used:
                return False
            self._used[nonce_key] = expires_at
            return True


class InMemoryGatewayStateStore:
    def __init__(self) -> None:
        self._records: dict[str, AuthorizationAuditRecord] = {}
        self._used: dict[tuple[str, str], int] = {}
        self._audit_lock = threading.Lock()
        self._nonce_lock = threading.Lock()

    def append_audit(self, record: AuthorizationAuditRecord) -> None:
        with self._audit_lock:
            if record.audit_id in self._records:
                raise GatewayStateError("duplicate audit ID")
            self._records[record.audit_id] = record.model_copy(deep=True)

    def get_audit(self, audit_id: str) -> AuthorizationAuditRecord | None:
        with self._audit_lock:
            record = self._records.get(audit_id)
            return record.model_copy(deep=True) if record is not None else None

    def consume_nonce(self, *, key_id: str, nonce: str, expires_at: int, now: int) -> bool:
        nonce_key = (key_id, nonce)
        with self._nonce_lock:
            self._used = {
                existing: expiry
                for existing, expiry in self._used.items()
                if expiry > now
            }
            if nonce_key in self._used:
                return False
            self._used[nonce_key] = expires_at
            return True

    def health_check(self) -> None:
        return None


class SQLiteGatewayStateStore:
    """Single-host durable state with atomic cross-process nonce consumption."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("SQLite timeout must be positive")
        raw_path = str(path)
        if raw_path == ":memory:" or raw_path.startswith("file:"):
            raise ValueError("SQLite state requires an on-disk filesystem path")
        self.path = Path(path).expanduser().resolve()
        self.timeout_seconds = timeout_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def append_audit(self, record: AuthorizationAuditRecord) -> None:
        payload = record.model_dump_json()
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO gateway_audit_records (
                        audit_id, tenant_id, user_id, agent_id, record_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.audit_id,
                        record.tenant_id,
                        record.user_id,
                        record.agent_id,
                        payload,
                        record.timestamp.isoformat(),
                    ),
                )
        except sqlite3.Error as error:
            raise GatewayStateError("failed to append audit record") from error

    def get_audit(self, audit_id: str) -> AuthorizationAuditRecord | None:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT record_json FROM gateway_audit_records WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise GatewayStateError("failed to read audit record") from error
        if row is None:
            return None
        try:
            return AuthorizationAuditRecord.model_validate_json(row["record_json"])
        except (ValidationError, ValueError, TypeError) as error:
            raise GatewayStateError("stored audit record is invalid") from error

    def consume_nonce(self, *, key_id: str, nonce: str, expires_at: int, now: int) -> bool:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM gateway_nonces WHERE expires_at <= ?", (now,))
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO gateway_nonces (
                    key_id, nonce, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (key_id, nonce, expires_at, now),
            )
            consumed = cursor.rowcount == 1
            connection.commit()
            return consumed
        except sqlite3.Error as error:
            connection.rollback()
            raise GatewayStateError("failed to consume authentication nonce") from error
        finally:
            connection.close()

    def health_check(self) -> None:
        try:
            with self._connection() as connection:
                connection.execute("SELECT 1 FROM gateway_audit_records LIMIT 1").fetchone()
                connection.execute("SELECT 1 FROM gateway_nonces LIMIT 1").fetchone()
        except sqlite3.Error as error:
            raise GatewayStateError("gateway state health check failed") from error

    def _initialize(self) -> None:
        try:
            with self._connection() as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > self.SCHEMA_VERSION:
                    raise GatewayStateError("database schema is newer than this application")
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_nonces (
                        key_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER NOT NULL,
                        PRIMARY KEY (key_id, nonce)
                    ) WITHOUT ROWID;

                    CREATE INDEX IF NOT EXISTS gateway_nonces_expiry
                    ON gateway_nonces (expires_at);

                    CREATE TABLE IF NOT EXISTS gateway_audit_records (
                        audit_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        record_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );

                    CREATE TRIGGER IF NOT EXISTS gateway_audit_no_update
                    BEFORE UPDATE ON gateway_audit_records
                    BEGIN
                        SELECT RAISE(ABORT, 'audit records are append-only');
                    END;

                    CREATE TRIGGER IF NOT EXISTS gateway_audit_no_delete
                    BEFORE DELETE ON gateway_audit_records
                    BEGIN
                        SELECT RAISE(ABORT, 'audit records are append-only');
                    END;

                    PRAGMA user_version = 1;
                    """
                )
            os.chmod(self.path, 0o600)
        except GatewayStateError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise GatewayStateError("failed to initialize SQLite gateway state") from error

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.Error as error:
            raise GatewayStateError("failed to connect to SQLite gateway state") from error

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()
