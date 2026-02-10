import hashlib
import secrets
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from core.models import Session

try:
    from django.contrib.auth.hashers import make_password, check_password
except Exception:
    make_password = None
    check_password = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(raw_password: str) -> str:
    if make_password is None:
        raise RuntimeError("Password hasher unavailable")
    return make_password(raw_password)


def verify_password(raw_password: str, stored_hash: str) -> bool:
    if check_password is None:
        raise RuntimeError("Password checker unavailable")
    return check_password(raw_password, stored_hash)


def create_session(user, ip: str | None, user_agent: str, ttl_hours: int = 24) -> tuple[str, Session]:
    token = secrets.token_urlsafe(32)
    token_h = hash_token(token)
    sess = Session.objects.create(
        user=user,
        token_hash=token_h,
        expires_at=timezone.now() + timedelta(hours=ttl_hours),
        ip=ip,
        user_agent=user_agent[:2000],
    )
    return token, sess


def revoke_session(session: Session) -> None:
    session.revoked_at = timezone.now()
    session.save(update_fields=["revoked_at"])


def revoke_all_sessions(user) -> None:
    Session.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=timezone.now())
