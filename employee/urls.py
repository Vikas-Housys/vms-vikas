from django.urls import path, include
from rest_framework.routers import DefaultRouter
from employee.views import (
    UserRegistrationView, UserLoginView, UserLogoutView, UserProfileView,
    UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView,
    DepartmentViewSet, RoleViewSet, DesignationViewSet, PermissionViewSet,
    UserRoleViewSet, UserDepartmentViewSet, UserDesignationViewSet, RolePermissionViewSet
)

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'departments', DepartmentViewSet, basename='department')
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'designations', DesignationViewSet, basename='designation')
router.register(r'permissions', PermissionViewSet, basename='permission')
router.register(r'user-roles', UserRoleViewSet, basename='user-role')
router.register(r'user-departments', UserDepartmentViewSet, basename='user-department')
router.register(r'user-designations', UserDesignationViewSet, basename='user-designation')
router.register(r'role-permissions', RolePermissionViewSet, basename='role-permissions')

urlpatterns = [
    path('auth/register/', UserRegistrationView.as_view(), name="register"),
    path('auth/login/', UserLoginView.as_view(), name="login"),
    path('auth/logout/', UserLogoutView.as_view(), name='logout'),
    path('auth/profile/', UserProfileView.as_view(), name="profile"),
    path('auth/changepassword/', UserChangePasswordView.as_view(), name="changepassword"),
    path('auth/send-password-reset-email/', SendPasswordResetEmailView.as_view(), name="send-password-reset-email"),
    path('auth/reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name="reset-password"),
    
    # Include router-generated URLs
    path('', include(router.urls)),
]

