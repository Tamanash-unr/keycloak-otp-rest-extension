# Keycloak OTP Admin API Extension

This Keycloak extension provides Admin REST API endpoints for OTP (One-Time Password) authentication management, compatible with Keycloak 26.1.3.

## Features

- Generate TOTP (Time-based One-Time Password) secrets and authentication URLs
- Set up OTP for users
- Remove OTP configuration from users
- Properly integrated with Keycloak's Admin REST API and permission system

## Installation

1. Build the project:
   ```
   mvn clean package
   ```

2. Copy the JAR file from `target/keycloak-otp-admin-extension.jar` to Keycloak's `providers` directory.

3. Restart Keycloak.

## Admin REST API Endpoints

All endpoints require admin authentication with proper permissions.

### Generate OTP Configuration

```
GET /admin/realms/{realm}/otp/generate/{userId}
```

Generates a new OTP secret, configures it for the specified user, and returns the OTP authentication URL.

**Response:**
```json
{
  "userId": "user-uuid",
  "username": "username",
  "otpAuthUrl": "otpauth://totp/RealmName:username?secret=ABCDEFGHIJKLMNOP&issuer=RealmName",
  "totpSecret": "ABCDEFGHIJKLMNOP"
}
```

### Setup OTP for User

```
POST /admin/realms/{realm}/otp/setup/{userId}
```

**Request Body:**
```json
{
  "totpSecret": "ABCDEFGHIJKLMNOP" // Optional, will generate one if not provided
}
```

**Response:**
```json
{
  "userId": "user-uuid",
  "username": "username",
  "status": "OTP configured successfully"
}
```

### Remove OTP Configuration

```
DELETE /admin/realms/{realm}/otp/remove/{userId}
```

Removes OTP configuration for the specified user.

**Response:**
```json
{
  "userId": "user-uuid",
  "username": "username",
  "status": "OTP removed successfully"
}
```

## Usage Examples

### Generate OTP and Display QR Code

```javascript
// Get admin access token first
fetch('https://keycloak.example.com/admin/realms/myrealm/otp/generate/user-uuid-here', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer ' + adminAccessToken
  }
})
.then(response => response.json())
.then(data => {
  // data.otpAuthUrl can be converted to QR code for scanning
  // data.totpSecret can be displayed as manual entry option
  console.log(data);
})
.catch(error => console.error('Error:', error));
```

## Required Permissions

To use these endpoints, admin users need:
- `view-users` permission to view user information
- `manage-users` permission to manage user OTP settings

These permissions are already included in the `realm-admin` role, but can be customized for more granular control.

## REST Endpoints

All endpoints require a valid bearer token for authentication.

### Generate OTP Configuration

```
GET /realms/{realm}/otp/generate-otp
```

Generates a new OTP secret, configures it for the authenticated user, and returns the OTP authentication URL.

**Response:**
```json
{
  "userId": "user-uuid",
  "otpAuthUrl": "otpauth://totp/RealmName:username?secret=ABCDEFGHIJKLMNOP&issuer=RealmName",
  "totpSecret": "ABCDEFGHIJKLMNOP"
}
```

### Setup OTP for User

```
POST /realms/{realm}/otp/setup-otp
```

**Request Body:**
```json
{
  "totpSecret": "ABCDEFGHIJKLMNOP" // Optional, will generate one if not provided
}
```

**Response:**
```json
{
  "userId": "user-uuid",
  "status": "OTP configured successfully"
}
```

### Remove OTP Configuration

```
DELETE /realms/{realm}/otp/remove-otp
```

Removes OTP configuration for the authenticated user.

**Response:**
```json
{
  "userId": "user-uuid",
  "status": "OTP removed successfully"
}
```

## Usage Examples

### Generate OTP and Display QR Code

```javascript
// Get access token first
fetch('https://keycloak.example.com/realms/myrealm/otp/generate-otp', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer ' + accessToken
  }
})
.then(response => response.json())
.then(data => {
  // data.otpAuthUrl can be converted to QR code for scanning
  // data.totpSecret can be displayed as manual entry option
  console.log(data);
})
.catch(error => console.error('Error:', error));
```

## Integration with Login Flow

After configuring OTP for a user, the user will be required to use OTP during login because the extension adds the `CONFIGURE_TOTP` required action to the user. This ensures that Keycloak's standard OTP login flow works properly.