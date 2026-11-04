package org.keycloak.protocol.oidc.verifier;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.provider.Provider;
import org.keycloak.representations.AccessToken;

/**
 * Additional token restrictions and sender binding verification for Keycloak endpoints.
 */
public interface TokenVerifierProvider extends Provider {

    /**
     * Adds checks to run during token validation, without consuming the proof of possession.
     * Providers that only verify sender bindings can leave the implementation empty.
     */
    void additionalAccessTokenVerifications(TokenVerifier<AccessToken> verifier, TokenVerificationContext context);

    /**
     * Verifies possession of the key of an already validated token. Resource requests invoke this automatically;
     * token exchange invokes it after authorizing the requesting client. Introspection and channel credentials do not.
     */
    default void verifyTokenBinding(AccessToken token, TokenVerificationContext context) throws VerificationException {
    }

    @Override
    default void close() {
    }
}
