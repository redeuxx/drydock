"""Append-only audit log. Rows are written in the caller's transaction."""

import json
import re
from typing import Any

from sqlalchemy.orm import Session

from drydock.models import AuditEvent

SECRET_KEY_RE = re.compile(r"pass|secret|token|key|credential|cookie|auth", re.IGNORECASE)
REDACTED = "[redacted]"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): REDACTED if SECRET_KEY_RE.search(str(k)) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


def record(
    db: Session,
    *,
    actor: str | None,
    action: str,
    target: str | None = None,
    outcome: str = "success",
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditEvent(
            actor=actor[:64] if actor else actor,
            ip=ip,
            action=action,
            target=target[:255] if target else target,
            outcome=outcome,
            details=json.dumps(redact(details or {}), default=str, sort_keys=True),
        )
    )
