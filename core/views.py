from django.conf import settings
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from core.models import (
    User, UserStatus, Session,
    Role, UserRole, Resource, Action, Permission, RolePermission
)
from core.serializers import (
    RegisterSerializer, LoginSerializer, UserMeSerializer,
    RoleSerializer, ResourceSerializer, ActionSerializer, PermissionSerializer
)
from core.security import hash_password, verify_password, create_session, revoke_session, revoke_all_sessions, hash_token
from core.decorators import require_auth, require_perm

from rest_framework.views import APIView
from rest_framework.response import Response

class HealthView(APIView):
    def get(self, request):
        return Response({"status": "ok"})


class RegisterView(APIView):
    def post(self, request):
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)

        data = s.validated_data
        if User.objects.filter(email=data["email"].lower()).exists():
            return Response({"detail": "Email already used"}, status=400)

        user = User.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            middle_name=data.get("middle_name", ""),
            email=data["email"].lower(),
            password_hash=hash_password(data["password"]),
            status=UserStatus.ACTIVE,
        )
        return Response(UserMeSerializer(user).data, status=201)


class LoginView(APIView):
    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        email = s.validated_data["email"].lower()
        password = s.validated_data["password"]

        user = User.objects.filter(email=email).first()
        if not user or user.status != UserStatus.ACTIVE:
            return Response({"detail": "Invalid credentials"}, status=400)

        if not verify_password(password, user.password_hash):
            return Response({"detail": "Invalid credentials"}, status=400)

        ip = request.META.get("REMOTE_ADDR")
        ua = request.META.get("HTTP_USER_AGENT", "")
        token, sess = create_session(user, ip, ua, ttl_hours=24)

        resp = Response({"detail": "ok"}, status=200)
        resp.set_cookie(
            settings.SESSION_COOKIE_NAME,
            token,
            httponly=settings.SESSION_COOKIE_HTTPONLY,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            secure=settings.SESSION_COOKIE_SECURE,
        )
        return resp


class LogoutView(APIView):
    @require_auth
    def post(self, request):
        sess = getattr(request, "auth_session", None)
        if sess:
            revoke_session(sess)
        resp = Response({"detail": "logged out"}, status=200)
        resp.delete_cookie(settings.SESSION_COOKIE_NAME)
        return resp


class MeView(APIView):
    @require_auth
    def get(self, request):
        return Response(UserMeSerializer(request.user_obj).data)

    @require_auth
    def patch(self, request):
        user = request.user_obj
        for field in ["first_name", "last_name", "middle_name", "email"]:
            if field in request.data:
                setattr(user, field, request.data[field])
        user.email = user.email.lower()
        user.updated_at = timezone.now()
        user.save()
        return Response(UserMeSerializer(user).data)

    @require_auth
    def delete(self, request):
        user = request.user_obj
        user.mark_deleted()
        revoke_all_sessions(user)
        resp = Response({"detail": "deleted"}, status=200)
        resp.delete_cookie(settings.SESSION_COOKIE_NAME)
        return resp


# ---- Mock business endpoints ----

class MockProjectsView(APIView):
    @require_perm("projects", "read")
    def get(self, request):
        return Response([{"id": 1, "name": "Project A"}, {"id": 2, "name": "Project B"}])


class MockReportsView(APIView):
    @require_perm("reports", "read")
    def get(self, request):
        return Response([{"id": 10, "title": "Sales report"}, {"id": 11, "title": "Traffic report"}])


# ---- Admin RBAC management ----

class AdminRolesView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request):
        return Response(RoleSerializer(Role.objects.all().order_by("id"), many=True).data)

    @require_perm("rbac", "manage")
    def post(self, request):
        s = RoleSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        role = Role.objects.create(**s.validated_data)
        return Response(RoleSerializer(role).data, status=201)


class AdminResourcesView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request):
        return Response(ResourceSerializer(Resource.objects.all().order_by("id"), many=True).data)

    @require_perm("rbac", "manage")
    def post(self, request):
        s = ResourceSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        obj = Resource.objects.create(**s.validated_data)
        return Response(ResourceSerializer(obj).data, status=201)


class AdminActionsView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request):
        return Response(ActionSerializer(Action.objects.all().order_by("id"), many=True).data)

    @require_perm("rbac", "manage")
    def post(self, request):
        s = ActionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        obj = Action.objects.create(**s.validated_data)
        return Response(ActionSerializer(obj).data, status=201)


class AdminPermissionsView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request):
        qs = Permission.objects.select_related("resource", "action").all().order_by("id")
        return Response(PermissionSerializer(qs, many=True).data)

    @require_perm("rbac", "manage")
    def post(self, request):
        # body: { "resource": <id>, "action": <id> }
        s = PermissionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        obj = Permission.objects.create(**s.validated_data)
        return Response(PermissionSerializer(obj).data, status=201)


class AdminUserRolesView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request, user_id):
        roles = Role.objects.filter(userrole__user_id=user_id).order_by("id")
        return Response(RoleSerializer(roles, many=True).data)

    @require_perm("rbac", "manage")
    def put(self, request, user_id):
        # body: {"role_ids": [1,2,3]}
        role_ids = request.data.get("role_ids", [])
        UserRole.objects.filter(user_id=user_id).delete()
        for rid in role_ids:
            UserRole.objects.create(user_id=user_id, role_id=rid)
        roles = Role.objects.filter(id__in=role_ids).order_by("id")
        return Response(RoleSerializer(roles, many=True).data)


class AdminRolePermissionsView(APIView):
    @require_perm("rbac", "manage")
    def get(self, request, role_id):
        perms = Permission.objects.filter(rolepermission__role_id=role_id).select_related("resource", "action")
        return Response(PermissionSerializer(perms, many=True).data)

    @require_perm("rbac", "manage")
    def put(self, request, role_id):
        # body: {"permission_ids": [1,2,3]}
        perm_ids = request.data.get("permission_ids", [])
        RolePermission.objects.filter(role_id=role_id).delete()
        for pid in perm_ids:
            RolePermission.objects.create(role_id=role_id, permission_id=pid)
        perms = Permission.objects.filter(id__in=perm_ids).select_related("resource", "action")
        return Response(PermissionSerializer(perms, many=True).data)


from rest_framework.views import APIView
from rest_framework.response import Response

class DebugPingView(APIView):
    def get(self, request):
        return Response({"ping": "pong"})
