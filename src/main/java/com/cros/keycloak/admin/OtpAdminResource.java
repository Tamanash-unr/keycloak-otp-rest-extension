package com.cros.keycloak.admin;

import org.jboss.logging.Logger;
import lombok.RequiredArgsConstructor;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

/**
 * Admin REST resource provider for OTP management
 */
@RequiredArgsConstructor
public class OtpAdminResource {

    private static final Logger LOG = Logger.getLogger(OtpAdminResource.class);
    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    @GET
    @Path("generate/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateOtp(@PathParam("userId") String userId) {
        // do the authorization with the existing admin permissions
		final UserPermissionEvaluator userPermissionEvaluator = auth.users();
		userPermissionEvaluator.requireManage();

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }

        // auth.users().requireManage(user);

        Map<String, String> totpData = generateTotpSecret();
        // Generate OTP secret
        String totpSecret = totpData.get("rawSecret");
        String base32Secret = totpData.get("base32Secret");

        configureOtpForUser(user, totpSecret, realm);

        String otpAuthUrl = generateOtpAuthUrl(realm, user, base32Secret);

        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        result.put("otpAuthUrl", otpAuthUrl);
        result.put("totpSecret", totpSecret);

        return Response.ok(result).build();
    }
    
    @POST
    @Path("setup/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response setupOtp(@PathParam("userId") String userId, Map<String, String> data) {
        // do the authorization with the existing admin permissions
		final UserPermissionEvaluator userPermissionEvaluator = auth.users();
		userPermissionEvaluator.requireManage();
        
        // Get user by ID
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }
        
        // Check if admin has permission to manage this user
        // auth.users().requireManage(user);
        
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
        result.put("username", user.getUsername());
        result.put("status", "OTP configured successfully");
        
        return Response.ok(result).build();
    }
    
    @DELETE
    @Path("remove/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeOtp(@PathParam("userId") String userId) {
        // do the authorization with the existing admin permissions
		final UserPermissionEvaluator userPermissionEvaluator = auth.users();
		userPermissionEvaluator.requireManage();
        
        // Get user by ID
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }
        
        // Check if admin has permission to manage this user
        // auth.users().requireManage(user);
        
        // Remove OTP credentials
        removeOtpCredentials(user, realm);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
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
        
        // Create OTP credential model
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret);
        otpCredentialProvider.createCredential(realm, user, credentialModel);
        
        // Set required action if user doesn't have OTP configured
        if (!user.getRequiredActionsStream().anyMatch(action -> 
                action.equals(UserModel.RequiredAction.CONFIGURE_TOTP.name()))) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }
    
    private void removeOtpCredentials(UserModel user, RealmModel realm) {
        // Get all credentials of OTP type and remove them using the updated method
        user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .forEach(credential -> 
                user.credentialManager().removeStoredCredentialById(credential.getId()));
        
        // Remove required action
        user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
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
}