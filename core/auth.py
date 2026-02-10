from typing import Optional
from django.conf import settings
from django.utils import timezone
from core.models import Session, User, UserStatus
from core.security import hash_token


def get_user_from_request(request) -> Optional[User]:
    token = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
    if not token:
        return None

    token_h = hash_token(token)
    sess = (
        Session.objects.select_related("user")
        .filter(token_hash=token_h, revoked_at__isnull=True, expires_at__gt=timezone.now())
        .first()
    )
    if not sess:
        return None

    if sess.user.status != UserStatus.ACTIVE:
        return None


    request.auth_session = sess
    return sess.user
