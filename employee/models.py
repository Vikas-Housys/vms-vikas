# models.py
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.core.validators import RegexValidator
from django.utils.timezone import now
from datetime import timedelta


# UserManager to manage User creation
class UserManager(BaseUserManager):
    def create_user(self, name, email, mobile, password=None):
        if not email:
            raise ValueError("Users must have an email address.")
        
        user = self.model(
            name=name,
            email=self.normalize_email(email),
            mobile=mobile
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, name, email, mobile, password=None):
        user = self.create_user(
            name=name,
            email=email,
            mobile=mobile,
            password=password
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    mobile = models.CharField(
        max_length=15,
        unique=True,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Enter a valid mobile number")]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Token storage fields
    access_token = models.TextField(null=True, blank=True)
    refresh_token = models.TextField(null=True, blank=True)
    access_token_expiry = models.DateTimeField(null=True, blank=True)
    refresh_token_expiry = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['name', 'mobile']

    def __str__(self):
        return self.email
    
    def set_tokens(self, access_token, refresh_token):
        """Set access and refresh tokens with expiry time."""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_token_expiry = now() + timedelta(minutes=60)
        self.refresh_token_expiry = now() + timedelta(days=7)
        self.save()

    def clear_tokens(self):
        """Clear access and refresh tokens."""
        self.access_token = None
        self.refresh_token = None
        self.access_token_expiry = None
        self.refresh_token_expiry = None
        self.save()

    def is_access_token_valid(self):
        """Check if the access token is still valid."""
        return self.access_token and self.access_token_expiry and self.access_token_expiry > now()

    def is_refresh_token_valid(self):
        """Check if the refresh token is still valid."""
        return self.refresh_token and self.refresh_token_expiry and self.refresh_token_expiry > now()

class BlacklistedToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=250, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Token for {self.user.email}"

    class Meta:
        db_table = 'employee_blacklistedtoken'

# ##################################################################################################
# Department model
class Department(models.Model):
    dept_id = models.AutoField(primary_key=True)
    department_name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.department_name


# Role model
class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.role_name


# Designation model
class Designation(models.Model):
    desgn_id = models.AutoField(primary_key=True)
    designation_name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.designation_name


# Permission Table
class Permission(models.Model):
    permission_id = models.AutoField(primary_key=True)
    permission_name = models.CharField(max_length=50, unique=True, null=False)

    def __str__(self):
        return self.permission_name


# User_Role Table (Relationship between User and Role)
class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)  
    role = models.ForeignKey(Role, on_delete=models.CASCADE, db_index=True) 

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'role'], name='user_role')
        ]

    def __str__(self):
        return f"{self.user.name} - {self.role.role_name}"


# User_Department Table (Relationship between User and Department)
class UserDepartment(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)  
    department = models.ForeignKey(Department, on_delete=models.CASCADE, db_index=True) 

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'department'], name='user_department')
        ]

    def __str__(self):
        return f"{self.user.name} - {self.department.department_name}"


# User_Designation Table (Relationship between User and Designation)
class UserDesignation(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True) 
    designation = models.ForeignKey(Designation, on_delete=models.CASCADE, db_index=True) 

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'designation'], name='user_designation')
        ]

    def __str__(self):
        return f"{self.user.name} - {self.designation.designation_name}"


# Role Permission Table (Many-to-Many Relationship)
class RolePermission(models.Model):
    id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, db_index=True) 
    permissions = models.ManyToManyField(Permission, related_name="role_permissions") 

    def __str__(self):
        return f"{self.user.username} - {', '.join([perm.permission_name for perm in self.permissions.all()])}"

