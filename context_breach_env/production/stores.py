from __future__ import annotations

from collections.abc import Iterable

from context_breach_env.production.models import AuditEvent, QuarantineEntry


class AppendOnlyAuditStore:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event.model_copy(deep=True))

    def events(self, episode_id: str | None = None) -> tuple[AuditEvent, ...]:
        events: Iterable[AuditEvent] = self._events
        if episode_id is not None:
            events = (event for event in events if event.episode_id == episode_id)
        return tuple(event.model_copy(deep=True) for event in events)


class AppendOnlyQuarantineStore:
    def __init__(self) -> None:
        self._entries: list[QuarantineEntry] = []

    def append(self, entry: QuarantineEntry) -> None:
        self._entries.append(entry.model_copy(deep=True))

    def entries(self, episode_id: str | None = None) -> tuple[QuarantineEntry, ...]:
        entries: Iterable[QuarantineEntry] = self._entries
        if episode_id is not None:
            entries = (entry for entry in entries if entry.episode_id == episode_id)
        return tuple(entry.model_copy(deep=True) for entry in entries)

    def delete(self, *_: object) -> None:
        raise RuntimeError("Quarantine records are append-only and cannot be deleted")
