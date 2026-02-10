from rest_framework import serializers
from core.models import User, Role, Resource, Action, Permission


class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=120)
    last_name = serializers.CharField(max_length=120)
    middle_name = serializers.CharField(max_length=120, required=False, allow_blank=True)
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8, write_only=True)
    password2 = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password2": "Passwords do not match"})
        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserMeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "middle_name", "email", "status", "created_at"]


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "code", "name"]


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = ["id", "code", "name"]


class ActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Action
        fields = ["id", "code", "name"]


class PermissionSerializer(serializers.ModelSerializer):
    resource_code = serializers.CharField(source="resource.code", read_only=True)
    action_code = serializers.CharField(source="action.code", read_only=True)

    class Meta:
        model = Permission
        fields = ["id", "resource", "action", "resource_code", "action_code"]
