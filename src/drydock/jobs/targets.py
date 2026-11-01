"""A job's targets: the containers or Compose projects it backs up, one after another.

The first is the job's own (jobs.target_type, jobs.target and jobs.uuid), so a job made
before there could be more keeps its archive names, retention and passphrase. The others
are job_targets rows, each with a UUID of its own. Every target's archives carry its UUID,
so retention, passphrases and restores work per target exactly as they do per job.
"""

import uuid as uuidlib
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from drydock.models import Job, JobTarget

MAX_TARGETS = 20


@dataclass(frozen=True)
class Spec:
    uuid: str
    target_type: str  # container or stack
    target: str
    primary: bool  # the job's own target

    @property
    def label(self) -> str:
        return f"{'Compose project' if self.target_type == 'stack' else 'container'} {self.target}"


def of(db: Session, job: Job) -> list[Spec]:
    """Every target of the job, the job's own first."""
    first = Spec(job.uuid, job.target_type, job.target, True)
    rows = db.scalars(
        select(JobTarget).where(JobTarget.job_id == job.id).order_by(JobTarget.position)
    )
    return [first, *(Spec(r.uuid, r.target_type, r.target, False) for r in rows)]


def find(db: Session, job: Job, target_uuid: str | None) -> Spec | None:
    """The target a run backs up: the job's own when target_uuid is None."""
    specs = of(db, job)
    if target_uuid is None:
        return specs[0]
    return next((s for s in specs if s.uuid == target_uuid), None)


def replace_extra(db: Session, job: Job, wanted: list[tuple[str, str]]) -> None:
    """Makes the job's second and later targets these (type, target) pairs, in order. A
    target that stays keeps its UUID, so its archives and retention carry on."""
    existing = {
        (r.target_type, r.target): r
        for r in db.scalars(select(JobTarget).where(JobTarget.job_id == job.id))
    }
    keep: list[JobTarget] = []
    for position, pair in enumerate(wanted, start=1):
        row = existing.pop(pair, None)
        if row is None:
            row = JobTarget(
                job_id=job.id,
                target_type=pair[0],
                target=pair[1],
                uuid=str(uuidlib.uuid4()),
                position=position,
            )
            db.add(row)
        row.position = position
        keep.append(row)
    for row in existing.values():
        db.delete(row)


def remove_all(db: Session, job_id: int) -> None:
    db.execute(delete(JobTarget).where(JobTarget.job_id == job_id))
