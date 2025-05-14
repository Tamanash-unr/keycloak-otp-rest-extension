# Keycloak OTP REST Endpoint

This Keycloak extension provides REST endpoints for OTP (One-Time Password) authentication management, compatible with Keycloak 26.1.3.

## Features

- Generate TOTP (Time-based One-Time Password) secrets and authentication URLs
- Set up OTP for users
- Remove OTP configuration from users

## Installation

1. Build the project:
   ```
   mvn clean package
   ```

2. Copy the JAR file from `target/keycloak-otp-rest-endpoint.jar` to Keycloak's `standalone/deployments` directory.

3. Restart Keycloak.

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