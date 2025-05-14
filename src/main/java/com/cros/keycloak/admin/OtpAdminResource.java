package com.cros.keycloak.admin;

import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.AdminRoot;

/**
 * This class integrates our OTP endpoint into the Keycloak Admin REST API structure
 */
public class OtpAdminResource extends AdminRoot {

    public OtpAdminResource(KeycloakSession session) {
        super(session);
    }

    /**
     * Register the OTP management endpoint under /admin/realms/{realm}/otp/
     */
    @Path("otp")
    public Object getOtpResource() {
        return new OtpAdminResourceProvider(session);
    }
}