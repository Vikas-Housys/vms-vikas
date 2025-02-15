from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework import serializers

from employee.serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, 
    UserChangePasswordSerializer, SendPasswordResetEmailSerializer, 
    UserPasswordResetSerializer, DepartmentSerializer, RoleSerializer, PermissionSerializer,
    DesignationSerializer,
    UserRoleSerializer, 
    UserDesignationSerializer,
    UserDepartmentSerializer,
    RolePermissionSerializer,
)
from employee.models import (
    User, Department, Role, Designation, Permission,
    UserRole, UserDepartment, UserDesignation, RolePermission
)
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.db.models.signals import post_migrate
from django.dispatch import receiver


# Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# Check the role permission
def has_user_permission(user, permission_name):
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


# User Registration View
class UserRegistrationView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_user'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response(
                {'data': serializer.data, 'message': 'Registration Successful.'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# User Login View
class UserLoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            
            user = authenticate(email=email, password=password)
            if user is None:
                return Response(
                    {"error": "Invalid email or password."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
                
            token = get_tokens_for_user(user)
            
            return Response({'token': token, 'message': 'Login Successful.'}, status=status.HTTP_200_OK)


# User Logout View
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Blacklist the access token
            access_token = request.auth
            if access_token:
                try:
                    AccessToken(access_token).blacklist()
                except TokenError:
                    pass  # Token is already expired or invalid

            # Blacklist the refresh token (if available)
            user = request.user
            refresh_token = RefreshToken.for_user(user)
            try:
                refresh_token.blacklist()
            except TokenError:
                pass  # Refresh token is already expired or invalid

            return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# User Profile View
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
            

# Change Password View
class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = UserChangePasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.update(user, serializer.validated_data)
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Send Password Reset Email View
class SendPasswordResetEmailView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Password reset email sent successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Password Reset View
class UserPasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        uid = kwargs.get('uid')
        token = kwargs.get('token')

        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': "Password reset successful."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


### Department ViewSet ###
class DepartmentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    
    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


### Role ViewSet ###
class RoleViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    
    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


### Designation ViewSet ###
class DesignationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Designation.objects.all()
    serializer_class = DesignationSerializer
    
    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


### Permission ViewSet ###
class PermissionViewSet(viewsets.ReadOnlyModelViewSet):  # Read-only operations
    permission_classes = [IsAuthenticated]
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    

### UserRole ViewSet ###
class UserRoleViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer

    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_user_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        role = serializer.validated_data['role']

        # Get or create UserRole instance
        user_role, created = UserRole.objects.get_or_create(user=user, role=role)

        return Response(UserRoleSerializer(user_role).data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_user_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Check if the updated user-role combination already exists
        user = serializer.validated_data.get('user', instance.user)
        role = serializer.validated_data.get('role', instance.role)
        if UserRole.objects.filter(user=user, role=role).exclude(id=instance.id).exists():
            return Response(
                {"error": "This user-role combination already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_user_role'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User role deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )


### UserDepartment ViewSet ###
class UserDepartmentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = UserDepartment.objects.all()
    serializer_class = UserDepartmentSerializer

    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_user_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if the user-department combination already exists
        user = serializer.validated_data['user']
        department = serializer.validated_data['department']
        if UserDepartment.objects.filter(user=user, department=department).exists():
            return Response(
                {"error": "This user already belongs to this department."},
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_user_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Check if the updated user-department combination already exists
        user = serializer.validated_data.get('user', instance.user)
        department = serializer.validated_data.get('department', instance.department)
        if UserDepartment.objects.filter(user=user, department=department).exclude(id=instance.id).exists():
            return Response(
                {"error": "This user-department combination already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_user_department'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User department entry deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )


### UserDesignation ViewSet ###
class UserDesignationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = UserDesignation.objects.all()
    serializer_class = UserDesignationSerializer

    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_user_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if the user-designation combination already exists
        user = serializer.validated_data['user']
        designation = serializer.validated_data['designation']
        if UserDesignation.objects.filter(user=user, designation=designation).exists():
            return Response(
                {"error": "This user already has this designation."},
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_user_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Check if the updated user-designation combination already exists
        user = serializer.validated_data.get('user', instance.user)
        designation = serializer.validated_data.get('designation', instance.designation)
        if UserDesignation.objects.filter(user=user, designation=designation).exclude(id=instance.id).exists():
            return Response(
                {"error": "This user-designation combination already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_user_designation'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User designation entry deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )


### RolePermission ViewSet ###
class RolePermissionViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer

    def create(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'create_role_permission'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        role = serializer.validated_data['role']
        permissions = serializer.validated_data['permissions']
        
        role_permission, created = RolePermission.objects.get_or_create(role=role)
        role_permission.permissions.set(permissions)

        return Response(RolePermissionSerializer(role_permission).data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'update_role_permission'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        # Update only the provided fields
        if 'permissions' in serializer.validated_data:
            instance.permissions.set(serializer.validated_data['permissions'])

        return Response(RolePermissionSerializer(instance).data)

    def destroy(self, request, *args, **kwargs):
        if not has_user_permission(request.user, 'delete_role_permission'):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Role permission entry deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )


