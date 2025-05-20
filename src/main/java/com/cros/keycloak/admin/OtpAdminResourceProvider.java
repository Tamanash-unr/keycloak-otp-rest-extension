package com.cros.keycloak.admin;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

@AutoService(AdminRealmResourceProviderFactory.class)
public class OtpAdminResourceProvider implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String ID = "admin-otp";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return this;
    }

    @Override
	public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
		return new OtpAdminResource(session, realm, auth);
	}

    @Override
    public void init(Config.Scope config) {
        // Initialization if needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization if needed
    }

    @Override
    public void close() {
        // Cleanup if needed
    }

    @Override
    public String getId() {
        return ID;
    }
}