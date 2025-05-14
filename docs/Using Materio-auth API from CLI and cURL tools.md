# Command Line Interface (CLI) Usage Guide

This guide demonstrates how to interact with the Materio authentication API using command-line tools like `curl` and tools for script automation.

## API Endpoints

The authentication system provides the following API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.netlify/functions/signup` | POST | Register a new user |
| `/.netlify/functions/login` | POST | Authenticate a user |
| `/.netlify/functions/forgot-password` | POST | Request password reset |
| `/.netlify/functions/forgot-password` | PUT | Reset password using recovery key |
| `/.netlify/functions/profile` | GET | Get user profile |
| `/.netlify/functions/profile` | PUT | Update user profile |
| `/.netlify/functions/profile` | DELETE | Delete user account |

## Base URL

 `https://auth-materioa.netlify.app` is the actual auth API base URL.

## Authentication

Most endpoints require authentication via a JWT token. After logging in, you'll receive a token that should be passed in the `Authorization` header in the format: `Bearer YOUR_TOKEN`.

## Examples

### 1. User Signup

```bash
curl -X POST https://auth-materioa.netlify.app/.netlify/functions/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "username123",
    "displayName": "User Name",
    "password": "secure-password"
  }'
```

#### Response:

```json
{
  "message": "User created successfully",
  "user": {
    "id": "user-uuid",
    "username": "username123",
    "displayName": "User Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T12:34:56.789Z"
  },
  "token": "your.jwt.token",
  "recoveryKey": "abcdef-123456-ghijkl"
}
```

### 2. User Login

```bash
curl -X POST https://auth-materioa.netlify.app/.netlify/functions/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "secure-password"
  }'
```

> Note: The `username` field accepts either an email address or a username. The system automatically detects if it's an email format and searches the appropriate field in the database.

#### Response:

```json
{
  "token": "your.jwt.token",
  "user": {
    "id": "user-uuid",
    "username": "username123",
    "displayName": "User Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T12:34:56.789Z"
  }
}
```

### 3. Get User Profile

```bash
curl -X GET https://auth-materioa.netlify.app/.netlify/functions/profile \
  -H "Authorization: Bearer your.jwt.token"
```

#### Response:

```json
{
  "user": {
    "id": "user-uuid",
    "username": "username123",
    "displayName": "User Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T12:34:56.789Z"
  }
}
```

### 4. Update User Profile

```bash
curl -X PUT https://auth-materioa.netlify.app/.netlify/functions/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your.jwt.token" \
  -d '{
    "username": "updated_username",
    "displayName": "Updated Name"
  }'
```

#### Response:

```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "user-uuid",
    "username": "updated_username",
    "displayName": "Updated Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T14:00:00.000Z"
  }
}
```

### 5. Change Password

```bash
curl -X PUT https://auth-materioa.netlify.app/.netlify/functions/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your.jwt.token" \
  -d '{
    "currentPassword": "secure-password",
    "newPassword": "new-secure-password"
  }'
```

#### Response:

```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "user-uuid",
    "username": "username123",
    "displayName": "User Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T15:00:00.000Z"
  }
}
```

### 6. Generate New Recovery Key

```bash
curl -X PUT https://auth-materioa.netlify.app/.netlify/functions/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your.jwt.token" \
  -d '{
    "currentPassword": "secure-password",
    "generateNewRecoveryKey": true
  }'
```

#### Response:

```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "user-uuid",
    "username": "username123",
    "displayName": "User Name",
    "email": "user@example.com",
    "profilePicture": null,
    "createdAt": "2025-05-13T12:34:56.789Z",
    "updatedAt": "2025-05-13T16:00:00.000Z"
  },
  "recoveryKey": "new-recovery-key-123456"
}
```

### 7. Reset Password with Recovery Key

```bash
curl -X PUT https://auth-materioa.netlify.app/.netlify/functions/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "recoveryKey": "abcdef-123456-ghijkl",
    "newPassword": "new-secure-password"
  }'
```

#### Response:

```json
{
  "message": "Password reset successfully"
}
```

### 8. Request Password Reset (Get Recovery Key)

```bash
curl -X POST https://auth-materioa.netlify.app/.netlify/functions/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

#### Response:

```json
{
  "message": "If this email exists in our system, a recovery key has been sent."
}
```

### 9. Delete Account

```bash
curl -X DELETE https://auth-materioa.netlify.app/.netlify/functions/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your.jwt.token" \
  -d '{
    "password": "secure-password"
  }'
```

#### Response:

```json
{
  "message": "Account deleted successfully"
}
```

## Bash Script Examples

### User Registration and Login

```bash
#!/bin/bash

# Configuration
API_URL="https://auth-materioa.netlify.app/.netlify/functions"
EMAIL="user@example.com"
PASSWORD="secure-password"
USERNAME="username123"
DISPLAY_NAME="User Name"

# Function to handle API errors
handle_error() {
  if [ $? -ne 0 ]; then
    echo "Error: API call failed"
    exit 1
  fi
  
  if echo "$1" | grep -q "error"; then
    echo "API Error: $(echo "$1" | jq -r '.error // .message')"
    exit 1
  fi
}

# Sign up a new user
echo "Creating new user..."
SIGNUP_RESPONSE=$(curl -s -X POST "$API_URL/signup" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"username\": \"$USERNAME\",
    \"displayName\": \"$DISPLAY_NAME\",
    \"password\": \"$PASSWORD\"
  }")

handle_error "$SIGNUP_RESPONSE"

# Extract token and recovery key
TOKEN=$(echo "$SIGNUP_RESPONSE" | jq -r '.token')
RECOVERY_KEY=$(echo "$SIGNUP_RESPONSE" | jq -r '.recoveryKey')

echo "User created successfully!"
echo "Recovery Key: $RECOVERY_KEY"
echo "JWT Token: $TOKEN"

# Save token to file for later use
echo "$TOKEN" > auth_token.txt

# Get user profile
echo -e "\nFetching user profile..."
PROFILE_RESPONSE=$(curl -s -X GET "$API_URL/profile" \
  -H "Authorization: Bearer $TOKEN")

handle_error "$PROFILE_RESPONSE"

echo "User Profile:"
echo "$PROFILE_RESPONSE" | jq

echo -e "\nAuthentication completed successfully!"
```

### Full User Management Script

```bash
#!/bin/bash

# Configuration
API_URL="https://auth-materioa.netlify.app/.netlify/functions"
TOKEN_FILE="auth_token.txt"

# Command line arguments
ACTION=$1
shift

# Help message
show_help() {
  echo "Usage: ./materio-auth.sh [ACTION] [OPTIONS]"
  echo ""
  echo "Actions:"
  echo "  signup EMAIL USERNAME DISPLAYNAME PASSWORD  - Create a new user"
  echo "  login EMAIL PASSWORD                      - Login existing user"
  echo "  profile                                   - Get current user profile"
  echo "  update-profile USERNAME DISPLAYNAME       - Update user profile"
  echo "  change-password CURRENT_PWD NEW_PWD       - Change user password"
  echo "  gen-recovery                              - Generate new recovery key"
  echo "  reset-password EMAIL RECOVERY_KEY NEW_PWD - Reset password with recovery key"
  echo "  delete-account PASSWORD                   - Delete current user account"
  echo "  help                                      - Show this help message"
}

# Function to handle API errors
handle_error() {
  if [ $? -ne 0 ]; then
    echo "Error: API call failed"
    return 1
  fi
  
  if echo "$1" | grep -q "error"; then
    echo "API Error: $(echo "$1" | jq -r '.error // .message')"
    return 1
  fi
  
  return 0
}

# Get saved token
get_token() {
  if [ ! -f "$TOKEN_FILE" ]; then
    echo "Error: Not logged in. Please login first."
    exit 1
  fi
  
  TOKEN=$(cat "$TOKEN_FILE")
  if [ -z "$TOKEN" ]; then
    echo "Error: Invalid token. Please login again."
    exit 1
  fi
  
  echo "$TOKEN"
}

# Sign up a new user
signup() {
  local email=$1
  local username=$2
  local displayName=$3
  local password=$4
  
  if [ -z "$email" ] || [ -z "$username" ] || [ -z "$displayName" ] || [ -z "$password" ]; then
    echo "Error: Missing required parameters"
    show_help
    exit 1
  fi
  
  echo "Creating new user..."
  SIGNUP_RESPONSE=$(curl -s -X POST "$API_URL/signup" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$email\",
      \"username\": \"$username\",
      \"displayName\": \"$displayName\",
      \"password\": \"$password\"
    }")
  
  if handle_error "$SIGNUP_RESPONSE"; then
    TOKEN=$(echo "$SIGNUP_RESPONSE" | jq -r '.token')
    RECOVERY_KEY=$(echo "$SIGNUP_RESPONSE" | jq -r '.recoveryKey')
    
    echo "$TOKEN" > "$TOKEN_FILE"
    
    echo "User created successfully!"
    echo "Recovery Key: $RECOVERY_KEY"
    echo "JWT Token saved to $TOKEN_FILE"
  fi
}

# Login user
login() {
  local email=$1
  local password=$2
  
  if [ -z "$email" ] || [ -z "$password" ]; then
    echo "Error: Missing required parameters"
    show_help
    exit 1
  fi
  
  echo "Logging in..."
  LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/login" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$email\",
      \"password\": \"$password\"
    }")
  
  if handle_error "$LOGIN_RESPONSE"; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
    echo "$TOKEN" > "$TOKEN_FILE"
    echo "Login successful!"
    echo "JWT Token saved to $TOKEN_FILE"
  fi
}

# Get user profile
get_profile() {
  TOKEN=$(get_token)
  
  echo "Fetching user profile..."
  PROFILE_RESPONSE=$(curl -s -X GET "$API_URL/profile" \
    -H "Authorization: Bearer $TOKEN")
  
  if handle_error "$PROFILE_RESPONSE"; then
    echo "User Profile:"
    echo "$PROFILE_RESPONSE" | jq
  fi
}

# Update user profile
update_profile() {
  local username=$1
  local displayName=$2
  
  if [ -z "$username" ] || [ -z "$displayName" ]; then
    echo "Error: Missing required parameters"
    show_help
    exit 1
  fi
  
  TOKEN=$(get_token)
  
  echo "Updating profile..."
  UPDATE_RESPONSE=$(curl -s -X PUT "$API_URL/profile" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"username\": \"$username\",
      \"displayName\": \"$displayName\"
    }")
  
  if handle_error "$UPDATE_RESPONSE"; then
    echo "Profile updated successfully!"
    echo "$UPDATE_RESPONSE" | jq
  fi
}

# Change password
change_password() {
  local currentPassword=$1
  local newPassword=$2
  
  if [ -z "$currentPassword" ] || [ -z "$newPassword" ]; then
    echo "Error: Missing required parameters"
    show_help
    exit 1
  fi
  
  TOKEN=$(get_token)
  
  echo "Changing password..."
  CHANGE_RESPONSE=$(curl -s -X PUT "$API_URL/profile" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"currentPassword\": \"$currentPassword\",
      \"newPassword\": \"$newPassword\"
    }")
  
  if handle_error "$CHANGE_RESPONSE"; then
    echo "Password changed successfully!"
  fi
}

# Generate new recovery key
gen_recovery() {
  local currentPassword=$1
  
  if [ -z "$currentPassword" ]; then
    echo "Error: Current password required"
    show_help
    exit 1
  fi
  
  TOKEN=$(get_token)
  
  echo "Generating new recovery key..."
  RECOVERY_RESPONSE=$(curl -s -X PUT "$API_URL/profile" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"currentPassword\": \"$currentPassword\",
      \"generateNewRecoveryKey\": true
    }")
  
  if handle_error "$RECOVERY_RESPONSE"; then
    NEW_KEY=$(echo "$RECOVERY_RESPONSE" | jq -r '.recoveryKey')
    echo "New recovery key: $NEW_KEY"
  fi
}

# Reset password with recovery key
reset_password() {
  local email=$1
  local recoveryKey=$2
  local newPassword=$3
  
  if [ -z "$email" ] || [ -z "$recoveryKey" ] || [ -z "$newPassword" ]; then
    echo "Error: Missing required parameters"
    show_help
    exit 1
  fi
  
  echo "Resetting password..."
  RESET_RESPONSE=$(curl -s -X PUT "$API_URL/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$email\",
      \"recoveryKey\": \"$recoveryKey\",
      \"newPassword\": \"$newPassword\"
    }")
  
  if handle_error "$RESET_RESPONSE"; then
    echo "Password reset successfully!"
  fi
}

# Delete account
delete_account() {
  local password=$1
  
  if [ -z "$password" ]; then
    echo "Error: Password required"
    show_help
    exit 1
  fi
  
  TOKEN=$(get_token)
  
  echo "WARNING: You are about to delete your account. This action cannot be undone."
  read -p "Are you sure? (y/n): " CONFIRM
  
  if [ "$CONFIRM" != "y" ]; then
    echo "Account deletion cancelled."
    exit 0
  fi
  
  echo "Deleting account..."
  DELETE_RESPONSE=$(curl -s -X DELETE "$API_URL/profile" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"password\": \"$password\"
    }")
  
  if handle_error "$DELETE_RESPONSE"; then
    echo "Account deleted successfully!"
    rm -f "$TOKEN_FILE"
  fi
}

# Main execution logic based on action
case "$ACTION" in
  signup)
    signup "$1" "$2" "$3" "$4"
    ;;
  login)
    login "$1" "$2"
    ;;
  profile)
    get_profile
    ;;
  update-profile)
    update_profile "$1" "$2"
    ;;
  change-password)
    change_password "$1" "$2"
    ;;
  gen-recovery)
    gen_recovery "$1"
    ;;
  reset-password)
    reset_password "$1" "$2" "$3"
    ;;
  delete-account)
    delete_account "$1"
    ;;
  help|--help|-h)
    show_help
    ;;
  *)
    echo "Unknown action: $ACTION"
    show_help
    exit 1
    ;;
esac
```

## Python Script Example

Here's a simple Python client for the auth API:

```python
#!/usr/bin/env python3
import argparse
import json
import os
import requests
import sys

# Configuration
API_URL = "https://auth-materioa.netlify.app/.netlify/functions"
TOKEN_FILE = "auth_token.txt"

def save_token(token):
    """Save token to file"""
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    print(f"Token saved to {TOKEN_FILE}")

def get_token():
    """Get token from file"""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token = f.read().strip()
            if not token:
                raise ValueError("Empty token")
            return token
    except (IOError, ValueError) as e:
        print(f"Error reading token: {e}")
        print("Please login first")
        sys.exit(1)

def handle_response(response):
    """Handle API response and errors"""
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        try:
            error_data = response.json()
            error_msg = error_data.get('error') or error_data.get('message') or str(e)
            print(f"API Error: {error_msg}")
        except:
            print(f"HTTP Error: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON response")
        sys.exit(1)

def signup(args):
    """Create a new user"""
    data = {
        "email": args.email,
        "username": args.username,
        "displayName": args.display_name,
        "password": args.password
    }
    
    print("Creating new user...")
    response = requests.post(f"{API_URL}/signup", json=data)
    result = handle_response(response)
    
    token = result.get('token')
    recovery_key = result.get('recoveryKey')
    
    save_token(token)
    print("User created successfully!")
    print(f"Recovery Key: {recovery_key}")
    return result

def login(args):
    """Login existing user"""
    data = {
        "email": args.email,
        "password": args.password
    }
    
    print("Logging in...")
    response = requests.post(f"{API_URL}/login", json=data)
    result = handle_response(response)
    
    token = result.get('token')
    save_token(token)
    print("Login successful!")
    return result

def get_profile(args):
    """Get user profile"""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("Fetching user profile...")
    response = requests.get(f"{API_URL}/profile", headers=headers)
    result = handle_response(response)
    
    print("User Profile:")
    print(json.dumps(result, indent=2))
    return result

def update_profile(args):
    """Update user profile"""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {}
    if args.username:
        data["username"] = args.username
    if args.display_name:
        data["displayName"] = args.display_name
    
    print("Updating profile...")
    response = requests.put(f"{API_URL}/profile", headers=headers, json=data)
    result = handle_response(response)
    
    print("Profile updated successfully!")
    print(json.dumps(result, indent=2))
    return result

def change_password(args):
    """Change user password"""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {
        "currentPassword": args.current_password,
        "newPassword": args.new_password
    }
    
    print("Changing password...")
    response = requests.put(f"{API_URL}/profile", headers=headers, json=data)
    result = handle_response(response)
    
    print("Password changed successfully!")
    return result

def generate_recovery(args):
    """Generate new recovery key"""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {
        "currentPassword": args.current_password,
        "generateNewRecoveryKey": True
    }
    
    print("Generating new recovery key...")
    response = requests.put(f"{API_URL}/profile", headers=headers, json=data)
    result = handle_response(response)
    
    recovery_key = result.get('recoveryKey')
    print(f"New recovery key: {recovery_key}")
    return result

def reset_password(args):
    """Reset password with recovery key"""
    data = {
        "email": args.email,
        "recoveryKey": args.recovery_key,
        "newPassword": args.new_password
    }
    
    print("Resetting password...")
    response = requests.put(f"{API_URL}/forgot-password", json=data)
    result = handle_response(response)
    
    print("Password reset successfully!")
    return result

def delete_account(args):
    """Delete user account"""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {
        "password": args.password
    }
    
    print("WARNING: You are about to delete your account. This action cannot be undone.")
    confirm = input("Are you sure? (y/n): ")
    
    if confirm.lower() != 'y':
        print("Account deletion cancelled.")
        return
    
    print("Deleting account...")
    response = requests.delete(f"{API_URL}/profile", headers=headers, json=data)
    result = handle_response(response)
    
    print("Account deleted successfully!")
    
    # Remove token file
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
    
    return result

def main():
    parser = argparse.ArgumentParser(description="Materio Auth CLI")
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Signup parser
    signup_parser = subparsers.add_parser('signup', help='Create a new user')
    signup_parser.add_argument('email', help='User email')
    signup_parser.add_argument('username', help='Username')
    signup_parser.add_argument('display_name', help='Display name')
    signup_parser.add_argument('password', help='Password')
    
    # Login parser
    login_parser = subparsers.add_parser('login', help='Login existing user')
    login_parser.add_argument('email', help='User email')
    login_parser.add_argument('password', help='Password')
    
    # Profile parser
    profile_parser = subparsers.add_parser('profile', help='Get user profile')
    
    # Update profile parser
    update_parser = subparsers.add_parser('update-profile', help='Update user profile')
    update_parser.add_argument('--username', help='New username')
    update_parser.add_argument('--display-name', help='New display name')
    
    # Change password parser
    change_pwd_parser = subparsers.add_parser('change-password', help='Change password')
    change_pwd_parser.add_argument('current_password', help='Current password')
    change_pwd_parser.add_argument('new_password', help='New password')
    
    # Generate recovery key parser
    gen_recovery_parser = subparsers.add_parser('gen-recovery', help='Generate new recovery key')
    gen_recovery_parser.add_argument('current_password', help='Current password')
    
    # Reset password parser
    reset_pwd_parser = subparsers.add_parser('reset-password', help='Reset password with recovery key')
    reset_pwd_parser.add_argument('email', help='User email')
    reset_pwd_parser.add_argument('recovery_key', help='Recovery key')
    reset_pwd_parser.add_argument('new_password', help='New password')
    
    # Delete account parser
    delete_parser = subparsers.add_parser('delete-account', help='Delete user account')
    delete_parser.add_argument('password', help='Current password')
    
    args = parser.parse_args()
    
    # Execute appropriate function based on command
    if args.command == 'signup':
        signup(args)
    elif args.command == 'login':
        login(args)
    elif args.command == 'profile':
        get_profile(args)
    elif args.command == 'update-profile':
        update_profile(args)
    elif args.command == 'change-password':
        change_password(args)
    elif args.command == 'gen-recovery':
        generate_recovery(args)
    elif args.command == 'reset-password':
        reset_password(args)
    elif args.command == 'delete-account':
        delete_account(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Usage Examples

### Using the Python Script

```bash
# Installation
chmod +x materio_auth.py

# Sign up
./materio_auth.py signup user@example.com username123 "User Name" secure-password

# Login
./materio_auth.py login user@example.com secure-password

# Get profile
./materio_auth.py profile

# Update profile
./materio_auth.py update-profile --username new_username --display-name "New Name"

# Change password
./materio_auth.py change-password current-password new-password

# Generate new recovery key
./materio_auth.py gen-recovery current-password

# Reset password with recovery key
./materio_auth.py reset-password user@example.com recovery-key-123 new-password

# Delete account
./materio_auth.py delete-account current-password
```

## Security Considerations

1. **Token Management**: When using these scripts in production, store tokens securely.
2. **Password Input**: Consider using hidden input for passwords in production scripts.
3. **Error Handling**: Add proper error handling based on your specific needs.
4. **Logging**: Limit or disable logging of sensitive information in production.

These examples should help you integrate the authentication system with your existing tools and workflows.
