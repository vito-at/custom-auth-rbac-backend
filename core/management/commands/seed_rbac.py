from django.core.management.base import BaseCommand
from core.models import Role, Resource, Action, Permission, RolePermission, User, UserRole, UserStatus
from core.security import hash_password

class Command(BaseCommand):
    help = "Seed RBAC tables with demo data"

    def handle(self, *args, **kwargs):
        # roles
        admin_role, _ = Role.objects.get_or_create(code="admin", defaults={"name": "Admin"})
        manager_role, _ = Role.objects.get_or_create(code="manager", defaults={"name": "Manager"})
        user_role, _ = Role.objects.get_or_create(code="user", defaults={"name": "User"})

        # resources
        rbac, _ = Resource.objects.get_or_create(code="rbac", defaults={"name": "RBAC management"})
        projects, _ = Resource.objects.get_or_create(code="projects", defaults={"name": "Projects"})
        reports, _ = Resource.objects.get_or_create(code="reports", defaults={"name": "Reports"})

        # actions
        read, _ = Action.objects.get_or_create(code="read", defaults={"name": "Read"})
        create, _ = Action.objects.get_or_create(code="create", defaults={"name": "Create"})
        update, _ = Action.objects.get_or_create(code="update", defaults={"name": "Update"})
        delete, _ = Action.objects.get_or_create(code="delete", defaults={"name": "Delete"})
        manage, _ = Action.objects.get_or_create(code="manage", defaults={"name": "Manage"})

        # permissions
        def perm(res, act):
            return Permission.objects.get_or_create(resource=res, action=act)[0]

        p_rbac_manage = perm(rbac, manage)

        p_projects_read = perm(projects, read)
        p_projects_create = perm(projects, create)
        p_projects_update = perm(projects, update)
        p_projects_delete = perm(projects, delete)

        p_reports_read = perm(reports, read)

        # role permissions
        def grant(role, p):
            RolePermission.objects.get_or_create(role=role, permission=p)

        # admin: everything relevant
        for p in [p_rbac_manage, p_projects_read, p_projects_create, p_projects_update, p_projects_delete, p_reports_read]:
            grant(admin_role, p)

        # manager
        for p in [p_projects_read, p_projects_create, p_projects_update, p_reports_read]:
            grant(manager_role, p)

        # user
        for p in [p_projects_read, p_reports_read]:
            grant(user_role, p)

        # demo users
        def ensure_user(email, fn, ln, role):
            u, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": fn,
                    "last_name": ln,
                    "middle_name": "",
                    "password_hash": hash_password("password123"),
                    "status": UserStatus.ACTIVE,
                }
            )
            UserRole.objects.get_or_create(user=u, role=role)

        ensure_user("admin@example.com", "Admin", "User", admin_role)
        ensure_user("manager@example.com", "Manager", "User", manager_role)
        ensure_user("user@example.com", "Regular", "User", user_role)

        self.stdout.write(self.style.SUCCESS("RBAC seeded успешно. Пароль у всех: password123"))
