package org.keycloak.protocol.oid4vc.verifier;

import org.keycloak.TokenVerifier;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.verifier.TokenVerificationContext;
import org.keycloak.protocol.oidc.verifier.TokenVerifierProvider;
import org.keycloak.representations.AccessToken;


public class OID4VCITokenVerifierProvider implements TokenVerifierProvider {

    private final KeycloakSession session;

    public OID4VCITokenVerifierProvider(KeycloakSession session) {
        this.session = session;
    }


    @Override
    public void additionalAccessTokenVerifications(TokenVerifier<AccessToken> verifier, TokenVerificationContext context) {
        verifier.withChecks(new OID4VCITokenVerifier(context));
    }
}
