# views.py
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from employee.permissions import permission_required
from employee.authentication import JWTAuthentication
from django.contrib.auth import authenticate

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
    UserRole, UserDepartment, UserDesignation, RolePermission,
    BlacklistedToken, User
) 
from employee.utils import generate_tokens


# ############################################################################################
class UserRegistrationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            tokens = generate_tokens(user)
            user.set_tokens(tokens["access"], tokens["refresh"])
            
            return Response(
                {'message': 'Registration Successful.', 'tokens': tokens},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            tokens = generate_tokens(user)
            user.set_tokens(tokens["access"], tokens["refresh"])
            return Response({
                'tokens': tokens,
                'message': 'Login Successful.'
            }, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        if not user or not user.is_refresh_token_valid():
            return Response({'error': 'Token does not exist or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        BlacklistedToken.objects.get_or_create(user=user, token=user.refresh_token)
        user.clear_tokens()
        return Response({'message': 'Logout successful. Token blacklisted.'}, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = UserChangePasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.update(request.user, serializer.validated_data)
            return Response({
                "message": "Password updated successfully"
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Password reset email sent successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        uid = kwargs.get('uid')
        token = kwargs.get('token')
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': "Password reset successful."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ################################################################################################
### Department ViewSet ###
class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]
    
    @permission_required('create_department')
    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to create department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('update_department')
    def update(self, request, *args, **kwargs):
        try:
            return super().update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_department')
    def partial_update(self, request, *args, **kwargs):
        try:
            return super().partial_update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_department')
    def destroy(self, request, *args, **kwargs):
        try:
            return super().destroy(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to delete department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_department')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_department')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


### Role ViewSet ###
class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated]  
    
    
    @permission_required('create_role')
    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to create role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('update_role')
    def update(self, request, *args, **kwargs):
        try:
            return super().update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_role')
    def partial_update(self, request, *args, **kwargs):
        try:
            return super().partial_update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_role')
    def destroy(self, request, *args, **kwargs):
        try:
            return super().destroy(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to delete role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_role')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_role')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


### Designation ViewSet ###
class DesignationViewSet(viewsets.ModelViewSet):
    queryset = Designation.objects.all()
    serializer_class = DesignationSerializer
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    
    @permission_required('create_designation')
    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to create designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('update_designation')
    def update(self, request, *args, **kwargs):
        try:
            return super().update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_designation')
    def partial_update(self, request, *args, **kwargs):
        try:
            return super().partial_update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to update designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_designation')
    def destroy(self, request, *args, **kwargs):
        try:
            return super().destroy(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to delete designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_designation')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_designation')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


### Permission ViewSet ###
class PermissionViewSet(viewsets.ReadOnlyModelViewSet):  # Read-only operations
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @permission_required('view_permission')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_permission')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    

### UserRole ViewSet ###
class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    
    @permission_required('create_user_role')
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            user = serializer.validated_data['user']
            role = serializer.validated_data['role']

            # Get or create UserRole instance
            user_role, created = UserRole.objects.get_or_create(user=user, role=role)

            return Response(UserRoleSerializer(user_role).data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"error": f"Failed to create user role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('update_user_role')
    def update(self, request, *args, **kwargs):
        try:
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
        
        except Exception as e:
            return Response(
                {"error": f"Failed to update user update: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('delete_user_role')
    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response(
                {"message": "User role deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to delete user role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('view_user_role')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user roles: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_user_role')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user role: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    
### UserDepartment ViewSet ###
class UserDepartmentViewSet(viewsets.ModelViewSet):
    queryset = UserDepartment.objects.all()
    serializer_class = UserDepartmentSerializer
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    
    @permission_required('create_user_department')
    def create(self, request, *args, **kwargs):
        try:
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
        
        except Exception as e:
            return Response(
                {"error": f"Failed to create user department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_user_department')
    def update(self, request, *args, **kwargs):
        try:
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
        except Exception as e:
            return Response(
                {"error": f"Failed to update user department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_user_department')
    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response(
                {"message": "User department entry deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to delete user department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @permission_required('view_user_department')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_user_department')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user department: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


### UserDesignation ViewSet ###
class UserDesignationViewSet(viewsets.ModelViewSet):
    queryset = UserDesignation.objects.all()
    serializer_class = UserDesignationSerializer
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @permission_required('create_user_designation')
    def create(self, request, *args, **kwargs):
        try:
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
        except Exception as e:
            return Response(
                {"error": f"Failed to create user designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_user_designation')
    def update(self, request, *args, **kwargs):
        try:
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
        except Exception as e:
            return Response(
                {"error": f"Failed to update user designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_user_designation')
    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response(
                {"message": "User designation entry deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to delete user designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_user_designation')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_user_designation')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch user designation: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    

### RolePermission ViewSet ###
class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    

    @permission_required('create_role_permission')
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            role = serializer.validated_data['role']
            permissions = serializer.validated_data['permissions']
            
            role_permission, created = RolePermission.objects.get_or_create(role=role)
            role_permission.permissions.set(permissions)

            return Response(RolePermissionSerializer(role_permission).data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"error": f"Failed to create role permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('update_role_permission')
    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)

            # Update only the provided fields
            if 'permissions' in serializer.validated_data:
                instance.permissions.set(serializer.validated_data['permissions'])

            return Response(RolePermissionSerializer(instance).data)
        except Exception as e:
            return Response(
                {"error": f"Failed to update role permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('delete_role_permission')
    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response(
                {"message": "Role permission entry deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to delete role permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_role_permission')
    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch role permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @permission_required('view_role_permission')
    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch role permission: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    


