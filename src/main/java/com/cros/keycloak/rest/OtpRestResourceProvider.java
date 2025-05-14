package com.cros.keycloak.rest;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

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
        RealmModel realm = auth.getRealm();

        // Generate OTP secret
        String totpSecret = generateTotpSecret();
        
        // Store OTP configuration for user
        configureOtpForUser(user, totpSecret);
        
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
        
        // Get provided OTP secret or generate one if not provided
        String totpSecret = data.containsKey("totpSecret") ? 
                data.get("totpSecret") : generateTotpSecret();
        
        // Configure OTP for user
        configureOtpForUser(user, totpSecret);
        
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
        
        // Remove OTP credentials
        removeOtpCredentials(user);
        
        Map<String, String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("status", "OTP removed successfully");
        
        return Response.ok(result).build();
    }
    
    private String generateTotpSecret() {
        // Generate a random secret for TOTP
        return HmacOTP.generateSecret(20);
    }
    
    private void configureOtpForUser(UserModel user, String totpSecret) {
        // Remove existing OTP credentials first
        removeOtpCredentials(user);
        
        // Get OTP credential provider
        OTPCredentialProvider otpCredentialProvider = (OTPCredentialProvider) session.getProvider(
                CredentialProvider.class, OTPCredentialProvider.PROVIDER_ID);
        
        // Create OTP credential model
        CredentialModel credentialModel = otpCredentialProvider.createCredential(
                auth.getRealm(), user, totpSecret);
        
        // Set required action if user doesn't have OTP configured
        if (!user.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_TOTP.name())) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }
    
    private void removeOtpCredentials(UserModel user) {
        // Get OTP credential provider
        OTPCredentialProvider otpCredentialProvider = (OTPCredentialProvider) session.getProvider(
                CredentialProvider.class, OTPCredentialProvider.PROVIDER_ID);
        
        // Remove OTP credentials
        otpCredentialProvider.disableCredentialType(auth.getRealm(), user, OTPCredentialProvider.TYPE);
        
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