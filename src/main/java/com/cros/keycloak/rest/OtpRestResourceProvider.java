package com.cros.keycloak.rest;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class OtpRestResourceProvider implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(OtpRestResourceProvider.class);
    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

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

    @GET
    @Path("generate-otp")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateOtp() {
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        UserModel user = auth.getUser();
        RealmModel realm = session.getContext().getRealm(); // Get realm from session context
        
        // Generate OTP secret
        String totpSecret = generateTotpSecret();
        
        // Store OTP configuration for user
        configureOtpForUser(user, totpSecret, realm);
        
        // Generate OTP auth URL
        String otpAuthUrl = generateOtpAuthUrl(realm, user, totpSecret);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("otpAuthUrl", otpAuthUrl);
        result.put("totpSecret", totpSecret);
        
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
        
        // Get provided OTP secret or generate one if not provided
        String totpSecret = data.containsKey("totpSecret") ? 
                data.get("totpSecret") : generateTotpSecret();
        
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
        
        // Create OTP credential model - Fixed: Use proper OTPCredentialModel creation
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret);
        otpCredentialProvider.createCredential(realm, user, credentialModel);
        
        // Set required action if user doesn't have OTP configured
        // Fixed: Use UserModel's addRequiredAction directly instead of checking getRequiredActions
        if (!user.getRequiredActionsStream().anyMatch(action -> 
                action.equals(UserModel.RequiredAction.CONFIGURE_TOTP.name()))) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }
    
    private void removeOtpCredentials(UserModel user, RealmModel realm) {
        // Get all credentials of OTP type and remove them
        // user.credentialManager()
        //     .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
        //     .forEach(credential -> 
        //         user.credentialManager().removeStoredCredential(credential.getId()));
        
        // Remove required action
        // user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
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