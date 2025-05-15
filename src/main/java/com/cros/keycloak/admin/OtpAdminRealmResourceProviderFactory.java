package com.cros.keycloak.admin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the OTP Admin REST resource provider
 */
public class OtpAdminRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "admin-otp";
    
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new OtpAdminRealmResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to initialize
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to post-initialize
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return ID;
    }
}