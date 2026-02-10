from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from core.auth import get_user_from_request
from core.rbac import user_has_permission


def require_auth(view_func):
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        user = get_user_from_request(request)
        if not user:
            return Response({"detail": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        request.user_obj = user
        return view_func(self, request, *args, **kwargs)
    return wrapper


def require_perm(resource: str, action: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            user = get_user_from_request(request)
            if not user:
                return Response({"detail": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            if not user_has_permission(user, resource, action):
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

            request.user_obj = user
            return view_func(self, request, *args, **kwargs)
        return wrapper
    return decorator
