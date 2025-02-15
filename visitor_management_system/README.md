Steps to Run in Django Shell
Open the Django shell
Run the following command in your terminal:

sh
Copy
Edit
python manage.py shell
Execute the following Python code in the shell:

python
Copy
Edit
from employee.models import Permission, Role

# Create permissions
create_permission, _ = Permission.objects.get_or_create(permission_name="create")
read_permission, _ = Permission.objects.get_or_create(permission_name="read")
update_permission, _ = Permission.objects.get_or_create(permission_name="update")
delete_permission, _ = Permission.objects.get_or_create(permission_name="delete")

# Create roles and assign permissions
superuser_role, _ = Role.objects.get_or_create(role_name="Superuser")
superuser_role.permissions.set([create_permission, read_permission, update_permission, delete_permission])

admin_role, _ = Role.objects.get_or_create(role_name="Admin")
admin_role.permissions.set([create_permission, read_permission, update_permission])

user_role, _ = Role.objects.get_or_create(role_name="User")
user_role.permissions.set([read_permission])

print("Roles and permissions assigned successfully!")
Key Improvements in this Code
✅ Uses get_or_create()

Prevents duplicate entries if the script is run multiple times.
✅ Uses .set([]) instead of .add()

More efficient for bulk permission assignment.
✅ Includes a confirmation message

Notifies you when roles and permissions are successfully assigned.