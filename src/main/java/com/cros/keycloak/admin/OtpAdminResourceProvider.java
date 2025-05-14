package com.cros.keycloak.admin;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

/**
 * Admin REST resource provider for OTP management
 */
public class OtpAdminResourceProvider {

    private static final Logger LOG = Logger.getLogger(OtpAdminResourceProvider.class);
    private final KeycloakSession session;
    private final AdminAuth auth;
    private final AdminPermissionEvaluator permissions;

    public OtpAdminResourceProvider(KeycloakSession session) {
        this.session = session;
        this.auth = session.getContext().getRequestAuthenticationManager().authenticateIdentity();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        }
        this.permissions = AdminPermissions.evaluator(session, session.getContext().getRealm(), auth);
    }

    @GET
    @Path("generate/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateOtp(@PathParam("userId") String userId) {
        RealmModel realm = session.getContext().getRealm();
        
        // Check if admin has permission to view and manage users
        permissions.users().requireView();
        
        // Get user by ID
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }
        
        // Check if admin has permission to manage this user
        permissions.users().requireManage(user);
        
        // Generate OTP secret
        String totpSecret = generateTotpSecret();
        
        // Store OTP configuration for user
        configureOtpForUser(user, totpSecret, realm);
        
        // Generate OTP auth URL
        String otpAuthUrl = generateOtpAuthUrl(realm, user, totpSecret);
        
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
        RealmModel realm = session.getContext().getRealm();
        
        // Check if admin has permission to view and manage users
        permissions.users().requireView();
        
        // Get user by ID
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }
        
        // Check if admin has permission to manage this user
        permissions.users().requireManage(user);
        
        // Get provided OTP secret or generate one if not provided
        String totpSecret = data.containsKey("totpSecret") ? 
                data.get("totpSecret") : generateTotpSecret();
        
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
        RealmModel realm = session.getContext().getRealm();
        
        // Check if admin has permission to view and manage users
        permissions.users().requireView();
        
        // Get user by ID
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found"))
                    .build();
        }
        
        // Check if admin has permission to manage this user
        permissions.users().requireManage(user);
        
        // Remove OTP credentials
        removeOtpCredentials(user, realm);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        result.put("status", "OTP removed successfully");
        
        return Response.ok(result).build();
    }
    
    private String generateTotpSecret() {
        // Generate a random secret for TOTP
        return HmacOTP.generateSecret(20);
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
        // Get all credentials of OTP type and remove them
        user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .forEach(credential -> 
                user.credentialManager().removeStoredCredential(credential.getId()));
        
        // Remove required action
        user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
    }
    
    private String generateOtpAuthUrl(RealmModel realm, UserModel user, String totpSecret) {
        // Create OTP auth URL in standard format
        // otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
        String issuer = realm.getName();
        String account = user.getUsername();
        
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                urlEncode(issuer), urlEncode(account), totpSecret, urlEncode(issuer));
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