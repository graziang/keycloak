package org.keycloak.protocol.oidc.verifier;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

public class TokenVerifierProviderManager {

    /** Adds token restrictions and, for resource authorization, the binding check. */
    public void additionalAccessTokenVerifications(TokenVerifier<AccessToken> verifier, TokenVerificationContext context) {
        context.session().getAllProviders(TokenVerifierProvider.class)
                .forEach(provider -> provider.additionalAccessTokenVerifications(verifier, context));
        if (context.tokenUse().isResourceAuthorization()) {
            verifier.withChecks(token -> {
                verifyTokenBinding(token, context);
                return true;
            });
        }
    }

    /** Verifies the binding after token validation and, for token exchange, client authorization. */
    public void verifyTokenBinding(AccessToken token, TokenVerificationContext context) throws VerificationException {
        if (!context.tokenUse().requiresProofOfPossession()) {
            throw new IllegalArgumentException("Token binding does not apply to " + context.tokenUse());
        }
        for (TokenVerifierProvider provider : context.session().getAllProviders(TokenVerifierProvider.class)) {
            provider.verifyTokenBinding(token, context);
        }
    }
}
