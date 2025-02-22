from rest_framework.response import Response
from rest_framework import status
from functools import wraps
from employee.models import UserRole, RolePermission, Permission

def has_user_permission(user, permission_name):
    """Check if the user has a specific permission"""
    if user.is_superuser:
        return True
    try:
        user_roles = UserRole.objects.filter(user=user)
        role_permissions = RolePermission.objects.filter(role__in=user_roles.values('role'))
        return Permission.objects.filter(
            role_permissions__in=role_permissions,
            permission_name=permission_name
        ).exists()
    except:
        return False

def permission_required(permission_name):
    """Decorator for checking user permissions"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not has_user_permission(request.user, permission_name):
                return Response(
                    {'error': f'Permission denied. Required permission: {permission_name}'},
                    status=status.HTTP_403_FORBIDDEN
                )
            return view_func(self, request, *args, **kwargs)
        return wrapper
    return decorator

