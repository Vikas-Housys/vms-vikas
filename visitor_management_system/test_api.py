import requests
import json
from time import sleep

BASE_URL = "http://localhost:8000/api/"  # Adjust based on your server
HEADERS = {'Content-Type': 'application/json'}
AUTH_HEADERS = {}

def print_response(response, endpoint):
    print(f"\n=== Testing {endpoint} ===")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json() if response.content else 'No content'}")
    print("=" * 50)

def test_registration():
    endpoint = "auth/register/"
    data = {
        "name": "Test User",
        "email": "testuser@example.com",
        "mobile": "+1234567890",
        "password": "testpass123",
        "password2": "testpass123"
    }
    response = requests.post(BASE_URL + endpoint, json=data, headers=HEADERS)
    print_response(response, endpoint)
    if response.status_code == 201:
        return response.json().get('token', {}).get('access')
    return None

def test_login():
    endpoint = "auth/login/"
    data = {
        "email": "testuser@example.com",
        "password": "testpass123"
    }
    response = requests.post(BASE_URL + endpoint, json=data, headers=HEADERS)
    print_response(response, endpoint)
    if response.status_code == 200:
        return response.json().get('token', {}).get('access')
    return None

def test_profile(auth_token):
    endpoint = "auth/profile/"
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    response = requests.get(BASE_URL + endpoint, headers=headers)
    print_response(response, endpoint)

def test_change_password(auth_token):
    endpoint = "auth/changepassword/"
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    data = {
        "password": "newtestpass123",
        "password2": "newtestpass123"
    }
    response = requests.post(BASE_URL + endpoint, json=data, headers=headers)
    print_response(response, endpoint)

def test_password_reset_email():
    endpoint = "auth/send-password-reset-email/"
    data = {
        "email": "testuser@example.com"
    }
    response = requests.post(BASE_URL + endpoint, json=data, headers=HEADERS)
    print_response(response, endpoint)

def test_department_operations(auth_token):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "departments/"
    
    # Create
    data = {"department_name": "Test Department"}
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")
    dept_id = response.json().get('dept_id')
    
    # Read
    response = requests.get(f"{BASE_URL}{base_endpoint}{dept_id}/", headers=headers)
    print_response(response, f"{base_endpoint} (READ)")
    
    # Update
    data = {"department_name": "Updated Department"}
    response = requests.put(f"{BASE_URL}{base_endpoint}{dept_id}/", json=data, headers=headers)
    print_response(response, f"{base_endpoint} (UPDATE)")
    
    # Delete
    response = requests.delete(f"{BASE_URL}{base_endpoint}{dept_id}/", headers=headers)
    print_response(response, f"{base_endpoint} (DELETE)")

def test_role_operations(auth_token):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "roles/"
    
    # Create
    data = {"role_name": "Test Role"}
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")
    role_id = response.json().get('role_id')
    
    # Read
    response = requests.get(f"{BASE_URL}{base_endpoint}{role_id}/", headers=headers)
    print_response(response, f"{base_endpoint} (READ)")
    
    return role_id

def test_designation_operations(auth_token):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "designations/"
    
    # Create
    data = {"designation_name": "Test Designation"}
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")
    desgn_id = response.json().get('desgn_id')
    
    # Read
    response = requests.get(f"{BASE_URL}{base_endpoint}{desgn_id}/", headers=headers)
    print_response(response, f"{base_endpoint} (READ)")
    
    return desgn_id

def test_permission_operations(auth_token):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "permissions/"
    
    # Create
    data = {"permission_name": "test_permission"}
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")
    perm_id = response.json().get('permission_id')
    
    return perm_id

def test_user_role_operations(auth_token, user_id, role_id):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "user-roles/"
    
    # Create
    data = {
        "user_id": user_id,
        "role_id": role_id
    }
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")

def test_user_department_operations(auth_token, user_id, dept_id):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "user-departments/"
    
    # Create
    data = {
        "user_id": user_id,
        "department_id": dept_id
    }
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")

def test_user_designation_operations(auth_token, user_id, desgn_id):
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    base_endpoint = "user-designations/"
    
    # Create
    data = {
        "user_id": user_id,
        "designation_id": desgn_id
    }
    response = requests.post(BASE_URL + base_endpoint, json=data, headers=headers)
    print_response(response, f"{base_endpoint} (CREATE)")

def main():
    # Test Registration
    print("\nTesting Registration...")
    auth_token = test_registration()
    if not auth_token:
        # Test Login if registration fails (in case user already exists)
        print("\nTesting Login...")
        auth_token = test_login()
    
    if not auth_token:
        print("Failed to obtain authentication token. Exiting...")
        return

    # Test Profile
    print("\nTesting Profile...")
    test_profile(auth_token)
    
    # Test Change Password
    print("\nTesting Change Password...")
    test_change_password(auth_token)
    
    # Test Password Reset Email
    print("\nTesting Password Reset Email...")
    test_password_reset_email()
    
    # Test Department Operations
    print("\nTesting Department Operations...")
    test_department_operations(auth_token)
    
    # Test Role Operations
    print("\nTesting Role Operations...")
    role_id = test_role_operations(auth_token)
    
    # Test Designation Operations
    print("\nTesting Designation Operations...")
    desgn_id = test_designation_operations(auth_token)
    
    # Test Permission Operations
    print("\nTesting Permission Operations...")
    perm_id = test_permission_operations(auth_token)
    
    # Get user ID from profile
    headers = {**HEADERS, 'Authorization': f'Bearer {auth_token}'}
    profile_response = requests.get(BASE_URL + "auth/profile/", headers=headers)
    user_id = profile_response.json().get('id')
    
    # Test User-Role Operations
    print("\nTesting User-Role Operations...")
    test_user_role_operations(auth_token, user_id, role_id)
    
    # Test User-Department Operations
    print("\nTesting User-Department Operations...")
    test_user_department_operations(auth_token, user_id, 1)  # Assuming department ID 1 exists
    
    # Test User-Designation Operations
    print("\nTesting User-Designation Operations...")
    test_user_designation_operations(auth_token, user_id, desgn_id)

if __name__ == "__main__":
    main()
