package com.cros.keycloak.admin;

import com.cros.keycloak.rest.OtpRestResourceProvider;
import org.keycloak.Config;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the OTP Admin REST resource provider
 */
public class OtpAdminResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "admin-otp";
    
    @Override
    public OtpRestResourceProvider create(KeycloakSession session) {
        return new OtpRestResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to initialize
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Create admin role for the extension if it doesn't exist
        factory.register(event -> {
            if (event instanceof RealmModel.RealmPostCreateEvent) {
                RealmModel realm = ((RealmModel.RealmPostCreateEvent) event).getCreatedRealm();
                setupAdminPermissions(realm);
            }
        });
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return ID;
    }
    
    private void setupAdminPermissions(RealmModel realm) {
        // Get master admin client
        ClientModel adminClient = realm.getMasterAdminClient();
        if (adminClient == null) {
            return;
        }

        // Create OTP management role if it doesn't exist
        RoleModel otpAdminRole = adminClient.getRole("manage-otp");
        if (otpAdminRole == null) {
            otpAdminRole = adminClient.addRole("manage-otp");
            otpAdminRole.setDescription("Manage OTP settings for users");
            
            // Add to realm-admin composite role to grant it to admins
            RoleModel adminRole = adminClient.getRole(AdminRoles.REALM_ADMIN);
            if (adminRole != null) {
                adminRole.addCompositeRole(otpAdminRole);
            }
        }
    }
}