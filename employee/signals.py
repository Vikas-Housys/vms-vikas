from django.db.models.signals import post_migrate
from django.dispatch import receiver
from .models import Permission

@receiver(post_migrate)
def create_permissions(sender, **kwargs):
    if sender.name == "employee":  # Ensure it runs for this app only
        permission_list = [
            "create_user", "update_user", "delete_user",
            "create_department", "update_department", "delete_department",
            "create_designation", "update_designation", "delete_designation",
            "create_role", "update_role", "delete_role",
            "create_user_role", "update_user_role", "delete_user_role",
            "create_user_designation", "update_user_designation", "delete_user_designation",
            "create_user_department", "update_user_department", "delete_user_department",
            "create_role_permission", "update_role_permission", "delete_role_permission"
        ]
        for perm in permission_list:
            Permission.objects.get_or_create(permission_name=perm)
