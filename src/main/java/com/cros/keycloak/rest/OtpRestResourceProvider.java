package com.cros.keycloak.rest;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OtpRestResourceProvider implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(OtpRestResourceProvider.class);
    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;
    
    // In-memory storage for pending OTP configurations
    // In production, consider using a more robust storage mechanism
    private static final Map<String, PendingOtpConfig> pendingConfigs = new ConcurrentHashMap<>();

    public OtpRestResourceProvider(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * New endpoint for detailed OTP auth validation with specific error messages
     */
    @POST
    @Path("validate")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response validateWithOtp(Map<String, String> credentials) {
        RealmModel realm = session.getContext().getRealm();
        
        String username = credentials.get("username");
        String password = credentials.get("password");
        String otpCode = credentials.get("otp");
        
        Map<String, Object> result = new HashMap<>();
        
        // Validate required fields
        if (username == null || username.trim().isEmpty()) {
            result.put("success", false);
            result.put("error", "MISSING_USERNAME");
            result.put("message", "Username is required");
            return Response.status(Response.Status.BAD_REQUEST).entity(result).build();
        }
        
        if (password == null || password.trim().isEmpty()) {
            result.put("success", false);
            result.put("error", "MISSING_PASSWORD");
            result.put("message", "Password is required");
            return Response.status(Response.Status.BAD_REQUEST).entity(result).build();
        }
        
        // Find user
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            user = session.users().getUserByEmail(realm, username);
        }
        
        if (user == null) {
            result.put("success", false);
            result.put("error", "USER_NOT_FOUND");
            result.put("message", "User not found");
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        
        // Check if user is enabled
        if (!user.isEnabled()) {
            result.put("success", false);
            result.put("error", "USER_DISABLED");
            result.put("message", "User account is disabled");
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        
        // Verify password
        PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) session.getProvider(
                CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);

        // Create password credential input
        CredentialInput passwordInput = UserCredentialModel.password(password);
        
        if (!passwordProvider.isValid(realm, user, passwordInput)) {
            result.put("success", false);
            result.put("error", "INVALID_PASSWORD");
            result.put("message", "Invalid password");
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        
        // Check if user has OTP configured
        boolean hasOtpConfigured = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .findAny()
                .isPresent();
        
        if (!hasOtpConfigured) {
            if (otpCode != null && !otpCode.trim().isEmpty()) {
                result.put("success", false);
                result.put("error", "OTP_NOT_CONFIGURED");
                result.put("message", "OTP is not configured for this user");
                return Response.status(Response.Status.BAD_REQUEST).entity(result).build();
            }
            
            // Password is valid and no OTP required
            result.put("success", true);
            result.put("message", "Validation successful");
            result.put("userId", user.getId());
            result.put("username", user.getUsername());
            result.put("otpRequired", false);
            return Response.ok(result).build();
        }
        
        // OTP is configured, so it's required
        if (otpCode == null || otpCode.trim().isEmpty()) {
            result.put("success", false);
            result.put("error", "OTP_REQUIRED");
            result.put("message", "OTP code is required for this user");
            result.put("otpRequired", true);
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        
        // Verify OTP
        CredentialModel otpData = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).findFirst().get();
        OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(otpData);
        // LOG.infof("Credential Data Secret : %s", otpCredentialModel.getOTPSecretData().getValue());
        
        if (!verifyOtpCode(user, otpCode, realm, otpCredentialModel.getOTPSecretData().getValue())) {
            result.put("success", false);
            result.put("error", "INVALID_OTP");
            result.put("message", "Invalid OTP code");
            result.put("otpRequired", true);
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        
        // Both password and OTP are valid
        result.put("success", true);
        result.put("message", "Validation successful");
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        result.put("email", user.getEmail());
        result.put("otpRequired", true);
        
        return Response.ok(result).build();
    }

    @GET
    @Path("generate-otp")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateOtp() {
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm();
        
        // Generate OTP secret
        Map<String, String> totpData = generateTotpSecret();
        String totpSecret = totpData.get("rawSecret");
        String base32Secret = totpData.get("base32Secret");
        
        // Store the secret temporarily without configuring the user
        String configId = generateConfigId(user.getId());
        PendingOtpConfig pendingConfig = new PendingOtpConfig(
            user.getId(), 
            totpSecret, 
            base32Secret, 
            System.currentTimeMillis()
        );
        pendingConfigs.put(configId, pendingConfig);
        
        // Clean up expired configs (older than 10 minutes)
        cleanupExpiredConfigs();
        
        // Generate OTP auth URL
        String otpAuthUrl = generateOtpAuthUrl(realm, user, base32Secret);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("configId", configId);
        result.put("otpAuthUrl", otpAuthUrl);
        result.put("message", "OTP secret generated. Use verify-and-configure endpoint to complete setup.");
        
        return Response.ok(result).build();
    }
    
    @POST
    @Path("verify-and-configure")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response verifyAndConfigureOtp(Map<String, String> data) {
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        
        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm();
        
        String configId = data.get("configId");
        String otpCode = data.get("otpCode");
        
        if (configId == null || otpCode == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "configId and otpCode are required");
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        }
        
        // Retrieve pending configuration
        PendingOtpConfig pendingConfig = pendingConfigs.get(configId);
        if (pendingConfig == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid or expired configuration ID");
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        }
        
        // Verify the user ID matches
        if (!pendingConfig.getUserId().equals(user.getId())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Configuration ID does not match current user");
            return Response.status(Response.Status.FORBIDDEN).entity(error).build();
        }
        
        // Verify the OTP code
        if (!verifyOtpCode(user, otpCode, realm, pendingConfig.getRawSecret())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid OTP code");
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        }
        
        // OTP is valid, now configure the user
        configureOtpForUser(user, pendingConfig.getRawSecret(), realm);
        
        // Remove the pending configuration
        pendingConfigs.remove(configId);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("status", "OTP configured successfully");
        
        return Response.ok(result).build();
    }
    
    @POST
    @Path("setup-otp")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response setupOtp(Map<String, String> data) {
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        
        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm();
        
        // Get provided OTP secret
        String totpSecret = data.containsKey("totpSecret") ? 
                data.get("totpSecret") : "";

        // Get generate one if not provided
        if(!data.containsKey("totpSecret")){
            Map<String, String> totpData = generateTotpSecret();
            totpSecret = totpData.get("rawSecret");
        }
        
        // Configure OTP for user
        configureOtpForUser(user, totpSecret, realm);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("status", "OTP configured successfully");
        
        return Response.ok(result).build();
    }
    
    @DELETE
    @Path("remove-otp")
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeOtp() {
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        
        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm();
        
        // Remove OTP credentials
        removeOtpCredentials(user, realm);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("status", "OTP removed successfully");
        
        return Response.ok(result).build();
    }

    private Map<String, String> generateTotpSecret() {
        // Generate Random 20 bytes String
        String rawSecret = HmacOTP.generateSecret(20);

        // Generate 20 raw bytes
        byte[] rawBytes = rawSecret.getBytes();
        
        // Generate Base32-encoded secret for the OTP URL
        String base32Secret = Base32.encode(rawBytes)
                .toUpperCase()
                .replace("=", ""); // Remove padding

        
        // LOG.infof("TOTP Secret: %s", rawSecret);
        // LOG.infof("Raw Bytes : %s", rawBytes);
        // LOG.infof("Base32 Secret: %s", base32Secret);
        
        // Return both secrets in a map
        Map<String, String> secrets = new HashMap<>();
        secrets.put("rawSecret", rawSecret);
        secrets.put("base32Secret", base32Secret);
        
        return secrets;
    }

    private void configureOtpForUser(UserModel user, String totpSecret, RealmModel realm) {
        // Remove existing OTP credentials first
        removeOtpCredentials(user, realm);
        
        // Get OTP credential provider
        OTPCredentialProvider otpCredentialProvider = (OTPCredentialProvider) session.getProvider(
                CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);
        
        // Create OTP credential model - Fixed: Use proper OTPCredentialModel creation
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret);
        otpCredentialProvider.createCredential(realm, user, credentialModel);
        
        // Set required action if user doesn't have OTP configured
        // Fixed: Use UserModel's addRequiredAction directly instead of checking getRequiredActions
        // if (!user.getRequiredActionsStream().anyMatch(action -> 
        //         action.equals(UserModel.RequiredAction.CONFIGURE_TOTP.name()))) {
        //     user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        // }
    }
    
    private void removeOtpCredentials(UserModel user, RealmModel realm) {
        // Get all credentials of OTP type and remove them using the updated method
        user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .forEach(credential -> 
                user.credentialManager().removeStoredCredentialById(credential.getId()));
    }
    
    private String generateOtpAuthUrl(RealmModel realm, UserModel user, String totpSecret) {
        // Create OTP auth URL in standard format
        // otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits={digits}&algorithm={algorithm}&period={period}
        // Retrieve OTP policy from the realm
        OTPPolicy policy = realm.getOTPPolicy();
        String algorithm = policy.getAlgorithm().replace("Hmac", ""); // Convert HmacSHA1 to SHA1
        int digits = policy.getDigits();
        int period = policy.getPeriod();

        String issuer = realm.getName();
        String account = user.getUsername();
        
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s&period=%d",
            urlEncode(issuer), 
            urlEncode(account), 
            totpSecret, 
            urlEncode(issuer),
            digits,
            algorithm,
            period
        );
    }
    
    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            LOG.error("Error encoding URL", e);
            return value;
        }
    }
    
    private boolean verifyOtpCode(UserModel user, String code, RealmModel realm, String secret) {        
        try {
            boolean isConfigured = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).findFirst().isPresent();
            
            if(isConfigured){
                CredentialModel otpData = user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).findFirst().get();

                SingleUseObjectProvider singleUseStore = this.session.singleUseObjects();
                String var10000 = otpData.getId();
                String searchKey = var10000 + "." + code;

                if(singleUseStore.contains(searchKey)) {
                    // LOG.infof("Store contains key: %s", searchKey);
                    return false;
                }
                // LOG.infof("Store does not contain key: %s", searchKey);
            }           

            OTPPolicy policy = realm.getOTPPolicy();
            TimeBasedOTP validator = new TimeBasedOTP(
                policy.getAlgorithm(), 
                policy.getDigits(), 
                policy.getPeriod(), 
                policy.getLookAheadWindow()
            );

            return validator.validateTOTP(code, secret.getBytes());             
            
            /* 
            // Validate OTP - Consumes OTP so it cannot be used again
            OTPCredentialProvider otpProvider = (OTPCredentialProvider) session.getProvider(
            CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);

            CredentialModel otpData = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).findFirst().get();

            OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(otpData);
            CredentialInput otpInput = new UserCredentialModel(otpCredentialModel.getId(), OTPCredentialModel.TOTP, code);
            LOG.infof("ID found: %s", otpInput.getCredentialId());

            return otpProvider.isValid(realm, user, otpInput); 
            */
        } catch (Exception e) {
            LOG.error("Error verifying OTP code", e);
            return false;
        }
    }
    
    private String generateConfigId(String userId) {
        return userId + "_" + System.currentTimeMillis() + "_" + Math.random();
    }
    
    private void cleanupExpiredConfigs() {
        long tenMinutesAgo = System.currentTimeMillis() - (10 * 60 * 1000);
        pendingConfigs.entrySet().removeIf(entry -> 
            entry.getValue().getTimestamp() < tenMinutesAgo);
    }
    
    // Inner class to hold pending OTP configuration
    private static class PendingOtpConfig {
        private final String userId;
        private final String rawSecret;
        // private final String base32Secret;
        private final long timestamp;
        
        public PendingOtpConfig(String userId, String rawSecret, String base32Secret, long timestamp) {
            this.userId = userId;
            this.rawSecret = rawSecret;
            // this.base32Secret = base32Secret;
            this.timestamp = timestamp;
        }
        
        public String getUserId() { return userId; }
        public String getRawSecret() { return rawSecret; }
        // public String getBase32Secret() { return base32Secret; }
        public long getTimestamp() { return timestamp; }
    }
}