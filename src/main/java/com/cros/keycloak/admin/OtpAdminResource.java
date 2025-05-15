package com.cros.keycloak.admin;

import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;

/**
 * This class integrates our OTP endpoint into the Keycloak Admin REST API structure
 */
public class OtpAdminResource {

    private final KeycloakSession session;

    public OtpAdminResource(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Register the OTP management endpoint under /admin/realms/{realm}/otp/
     */
    @Path("otp")
    public Object getOtpResource() {
        return new OtpAdminResourceProvider(session);
    }
}