from core.models import (
    UserRole, RolePermission, Permission, Resource, Action
)

def user_has_permission(user, resource_code: str, action_code: str) -> bool:
    roles = UserRole.objects.filter(user=user).values_list("role_id", flat=True)
    if not roles:
        return False

    perm = (
        Permission.objects
        .select_related("resource", "action")
        .filter(resource__code=resource_code, action__code=action_code)
        .first()
    )
    if not perm:
        return False

    return RolePermission.objects.filter(role_id__in=roles, permission=perm).exists()
