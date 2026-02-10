import uuid
from django.db import models
from django.utils import timezone


class UserStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    DELETED = "DELETED", "Deleted"


class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    first_name = models.CharField(max_length=120)
    last_name = models.CharField(max_length=120)
    middle_name = models.CharField(max_length=120, blank=True, default="")

    email = models.EmailField(unique=True, db_index=True)
    password_hash = models.CharField(max_length=255)

    status = models.CharField(max_length=16, choices=UserStatus.choices, default=UserStatus.ACTIVE)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def mark_deleted(self):
        self.status = UserStatus.DELETED
        self.deleted_at = timezone.now()
        self.updated_at = timezone.now()
        self.save(update_fields=["status", "deleted_at", "updated_at"])


class Session(models.Model):
    
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sessions")

    token_hash = models.CharField(max_length=64, unique=True, db_index=True)  # sha256 hex
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")

    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()


class Role(models.Model):
    id = models.BigAutoField(primary_key=True)
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120)

    def __str__(self) -> str:
        return self.code


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "role")


class Resource(models.Model):
    id = models.BigAutoField(primary_key=True)
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120)

    def __str__(self) -> str:
        return self.code


class Action(models.Model):
    id = models.BigAutoField(primary_key=True)
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120)

    def __str__(self) -> str:
        return self.code


class Permission(models.Model):
    id = models.BigAutoField(primary_key=True)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    action = models.ForeignKey(Action, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("resource", "action")


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("role", "permission")
