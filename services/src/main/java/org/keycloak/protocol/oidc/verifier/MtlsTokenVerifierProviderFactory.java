package org.keycloak.protocol.oidc.verifier;

import org.keycloak.models.KeycloakSession;

public class MtlsTokenVerifierProviderFactory implements TokenVerifierProviderFactory {

    @Override
    public TokenVerifierProvider create(KeycloakSession session) {
        return new MtlsTokenVerifierProvider();
    }

    @Override
    public String getId() {
        return "mtls";
    }
}
