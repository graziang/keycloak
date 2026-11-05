package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;
import org.keycloak.protocol.oidc.verifier.TokenVerifierProvider.ProofOfPossession;
import org.keycloak.representations.AccessToken;

public class TokenVerifierProviderManager {

    /**
     * Add the additional verifications to the given access token verifier, including the verification of the token
     * binding when the context requires the proof of possession.
     *
     * @param context for the token verification
     */
    public void additionalAccessTokenVerifications(TokenVerifierProvider.TokenVerifierProviderContext context) {
        context.session().getAllProviders(TokenVerifierProvider.class)
                .forEach(tokenVerifierProvider -> tokenVerifierProvider.additionalAccessTokenVerifications(context));
        if (context.proofOfPossession() == ProofOfPossession.REQUIRED) {
            context.accessTokenVerifier().withChecks(token -> {
                verifyTokenBinding(token, context);
                return true;
            });
        }
    }

    /**
     * Verify the binding of the given token. Called by the token verification itself, and by the callers that defer
     * the verification until the request is authorized.
     *
     * @param token the token that was verified
     * @param context for the token verification
     */
    public void verifyTokenBinding(AccessToken token, TokenVerifierProvider.TokenVerifierProviderContext context) throws VerificationException {
        for (TokenVerifierProvider provider : context.session().getAllProviders(TokenVerifierProvider.class)) {
            provider.verifyTokenBinding(token, context);
        }
    }
}
