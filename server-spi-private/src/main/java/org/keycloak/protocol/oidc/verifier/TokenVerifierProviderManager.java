package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

public class TokenVerifierProviderManager {

    /**
     * Additional verifications of access token provided by {@link TokenVerifierProvider}
     *
     * @param context for the token verification
     */
    public void additionalAccessTokenVerifications(TokenVerifierProvider.TokenVerifierProviderContext context) {
        context.session().getAllProviders(TokenVerifierProvider.class)
                .forEach(tokenVerifierProvider -> tokenVerifierProvider.additionalAccessTokenVerifications(context));
        if (context.verificationContext().isResourceRequest()) {
            context.accessTokenVerifier().withChecks(token -> {
                verifyTokenBinding(token, context);
                return true;
            });
        }
    }

    public void verifyTokenBinding(AccessToken token, TokenVerifierProvider.TokenVerifierProviderContext context) throws VerificationException {
        if (context.verificationContext().requiresProofOfPossession()) {
            for (TokenVerifierProvider provider : context.session().getAllProviders(TokenVerifierProvider.class)) {
                provider.verifyTokenBinding(token, context);
            }
        }
    }
}
