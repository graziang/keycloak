package org.keycloak.protocol.oidc.verifier;

import org.keycloak.models.KeycloakSession;

public class DPoPTokenVerifierProviderFactory implements TokenVerifierProviderFactory {

    @Override
    public TokenVerifierProvider create(KeycloakSession session) {
        return new DPoPTokenVerifierProvider();
    }

    @Override
    public String getId() {
        return "dpop";
    }
}
