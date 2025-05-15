package com.cros.keycloak.admin;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Provider for OTP Admin REST resources
 */
public class OtpAdminRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public OtpAdminRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new OtpAdminResourceProvider(session);
    }

    @Override
    public void close() {
        // Nothing to close
    }
}