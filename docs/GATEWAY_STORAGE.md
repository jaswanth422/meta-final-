# Durable gateway state

Set `CONTEXT_BREACH_DATABASE_PATH` to enable the SQLite state backend used by
both request authentication and authorization auditing:

```bash
export CONTEXT_BREACH_DATABASE_PATH=/var/lib/context-breach/gateway.sqlite3
```

The parent directory is created automatically. The database file is restricted
to mode `0600` on initialization. Keep the path on a local persistent volume;
SQLite WAL is not supported here on NFS or as a shared volume between hosts.

With no database path, the gateway intentionally falls back to process-local
memory for development. `GET /health` reports `"storage":"sqlite"` or
`"storage":"memory"` so deployment checks can reject the fallback.

## Guarantees

The version-1 schema provides:

- a unique `(key_id, nonce)` primary key;
- atomic nonce consumption using `BEGIN IMMEDIATE`;
- expired-nonce cleanup inside the same transaction;
- WAL mode, a busy timeout, and full synchronous writes;
- audit records that contain no raw intent or argument values;
- database triggers that reject audit updates and deletions;
- fail-closed `503 gateway_state_unavailable` responses on storage errors.

The nonce uniqueness constraint is shared by multiple gateway worker processes
on one machine. A consumed credential therefore remains blocked across worker
boundaries and server restarts.

## Persistent volume

For a container deployment, mount a host directory or named volume at
`/var/lib/context-breach` and set the database path shown above. Do not bake the
database into an image layer, store it in `/tmp`, or commit it to Git.

For live backups, use SQLite's online backup operation instead of copying only
the main database file while WAL writes are active. Test restore procedures and
protect backups as security logs, because audit metadata identifies tenants,
users, agents, tools, and resources.

## Limits

This is single-host durability, not distributed SaaS storage. It does not yet
provide:

- PostgreSQL or multi-region replication;
- retention, archival, or legal-hold workflows;
- cryptographic chaining or external notarization of audit records;
- durable artifact assessments (artifact risk state is still process-local);
- automatic schema migration beyond version 1;
- managed encryption at rest or managed backups.

The append-only triggers prevent normal SQL modification, but a filesystem or
database administrator can still replace the database. Do not describe the
current audit log as tamper-evident.
