"""User management. Superadmin only; every change except session revocation needs recent auth."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import User, UserSession
from drydock.routes.auth import FormStr, client_ip, validate_username
from drydock.security import passwords, sessions
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter(prefix="/users")

Superadmin = Annotated[Auth, Depends(require_role(Role.superadmin))]
LAST_SUPERADMIN = "The last active superadmin cannot be demoted, disabled or deleted."


def get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404)
    return user


def is_last_superadmin(db: Session, user: User) -> bool:
    if user.role != Role.superadmin or user.disabled:
        return False
    others = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == Role.superadmin, User.disabled.is_(False), User.id != user.id)
    )
    return others == 0


def edit_page(
    request: Request,
    db: Session,
    auth: Auth,
    user: User,
    status: int = 200,
    error: str | None = None,
) -> Response:
    user_sessions = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == user.id)
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    return render(
        request,
        "users/edit.html",
        status,
        auth=auth,
        user=user,
        sessions=user_sessions,
        error=error,
    )


def deny_last_superadmin(
    request: Request, db: Session, auth: Auth, user: User, action: str
) -> Response:
    audit.record(
        db,
        actor=auth.user.username,
        action=action,
        target=f"user:{user.id}",
        outcome="denied",
        ip=client_ip(request),
        details={"reason": "last superadmin"},
    )
    db.commit()
    return edit_page(request, db, auth, user, 409, LAST_SUPERADMIN)


def parse_role(value: str) -> Role:
    try:
        return Role[value]
    except KeyError:
        raise HTTPException(status_code=422, detail="Unknown role.") from None


def done(request: Request, user: User) -> Response:
    return see_other(request, f"/users/{user.id}")


# LIST AND CREATE


@router.get("")
def list_users(request: Request, auth: Superadmin, db: Session = Depends(get_db)) -> Response:
    users = db.scalars(select(User).order_by(User.username)).all()
    return render(request, "users/list.html", auth=auth, users=users)


@router.get("/new")
def new_user_form(request: Request, auth: Superadmin) -> Response:
    return render(request, "users/new.html", auth=auth, errors=[], username="", role="viewer")


@router.post("")
def create_user(
    request: Request,
    auth: Superadmin,
    username: FormStr = "",
    password: FormStr = "",
    role: FormStr = "viewer",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    new_role = parse_role(role)
    errors = [e for e in (validate_username(username), passwords.validate_new(password)) if e]
    # Hash before the first query, which takes the write lock (BEGIN IMMEDIATE).
    password_hash = None if errors else passwords.hash_password(password)
    if not errors and db.scalar(select(User.id).where(User.username == username)) is not None:
        errors.append("That username is taken.")
    if errors:
        db.rollback()
        return render(
            request,
            "users/new.html",
            422,
            auth=auth,
            errors=errors,
            username=username,
            role=new_role.name,
        )
    user = User(username=username, password_hash=password_hash, role=new_role)
    db.add(user)
    db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="user.create",
        target=f"user:{user.id}",
        ip=client_ip(request),
        details={"username": username, "role": new_role.name},
    )
    db.commit()
    return done(request, user)


# EDIT


@router.get("/{user_id}")
def edit_user(
    request: Request, user_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    return edit_page(request, db, auth, get_user(db, user_id))


@router.post("/{user_id}/role")
def change_role(
    request: Request,
    user_id: int,
    auth: Superadmin,
    role: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    new_role = parse_role(role)
    user = get_user(db, user_id)
    old_role = Role(user.role)
    if new_role != Role.superadmin and is_last_superadmin(db, user):
        return deny_last_superadmin(request, db, auth, user, "user.role")
    user.role = new_role
    sessions.revoke_user(db, user.id)
    audit.record(
        db,
        actor=auth.user.username,
        action="user.role",
        target=f"user:{user.id}",
        ip=client_ip(request),
        details={"from": old_role.name, "to": new_role.name},
    )
    db.commit()
    return done(request, user)


@router.post("/{user_id}/disabled")
def set_disabled(
    request: Request,
    user_id: int,
    auth: Superadmin,
    disabled: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    if disabled not in ("0", "1"):
        raise HTTPException(status_code=422, detail="disabled must be 0 or 1.")
    user = get_user(db, user_id)
    if disabled == "1" and is_last_superadmin(db, user):
        return deny_last_superadmin(request, db, auth, user, "user.disable")
    user.disabled = disabled == "1"
    if user.disabled:
        sessions.revoke_user(db, user.id)
    action = "user.disable" if user.disabled else "user.enable"
    audit.record(
        db, actor=auth.user.username, action=action, target=f"user:{user.id}", ip=client_ip(request)
    )
    db.commit()
    return done(request, user)


@router.post("/{user_id}/password")
def reset_password(
    request: Request,
    user_id: int,
    auth: Superadmin,
    password: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    error = passwords.validate_new(password)
    # Hash before the first query, which takes the write lock (BEGIN IMMEDIATE).
    password_hash = None if error else passwords.hash_password(password)
    user = get_user(db, user_id)
    if password_hash is None:
        return edit_page(request, db, auth, user, 422, error)
    user.password_hash = password_hash
    sessions.revoke_user(db, user.id)
    audit.record(
        db,
        actor=auth.user.username,
        action="user.password_reset",
        target=f"user:{user.id}",
        ip=client_ip(request),
    )
    db.commit()
    return done(request, user)


@router.post("/{user_id}/delete")
def delete_user(
    request: Request, user_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    require_recent_auth(auth)
    user = get_user(db, user_id)
    if is_last_superadmin(db, user):
        return deny_last_superadmin(request, db, auth, user, "user.delete")
    audit.record(
        db,
        actor=auth.user.username,
        action="user.delete",
        target=f"user:{user.id}",
        ip=client_ip(request),
        details={"username": user.username},
    )
    db.delete(user)
    db.commit()
    return see_other(request, "/users")


@router.post("/{user_id}/sessions/revoke")
def revoke_sessions(
    request: Request, user_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    user = get_user(db, user_id)
    sessions.revoke_user(db, user.id)
    audit.record(
        db,
        actor=auth.user.username,
        action="user.sessions_revoke",
        target=f"user:{user.id}",
        ip=client_ip(request),
    )
    db.commit()
    return done(request, user)
