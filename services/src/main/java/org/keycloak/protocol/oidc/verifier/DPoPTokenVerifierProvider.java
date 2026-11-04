package org.keycloak.protocol.oidc.verifier;

import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.TokenUtil;

public class DPoPTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void additionalAccessTokenVerifications(TokenVerifierProviderContext context) {
        if (context.verificationContext().requiresProofOfPossession()) {
            context.accessTokenVerifier().tokenType(Profile.isFeatureEnabled(Profile.Feature.DPOP)
                    ? List.of(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP)
                    : List.of(TokenUtil.TOKEN_TYPE_BEARER));
        }
    }

    @Override
    public void verifyTokenBinding(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
        if (!Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
            return;
        }
        if (context.verificationContext().isResourceRequest()) {
            DPoPUtil.verifyResourceTokenBinding(token, context.realm(), new DPoPUtil.Validator(context.session())
                    .request(context.request()).uriInfo(context.uriInfo()).accessToken(context.tokenString())
                    .tokenInFormParameter(context.verificationContext() == TokenVerificationContext.RESOURCE_WITH_FORM_TOKEN));
        } else if (token.getConfirmation() != null && token.getConfirmation().getKeyThumbprint() != null) {
            DPoP proof = context.session().getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
            if (proof == null) {
                throw new DPoPUtil.DPoPVerificationException(null, "DPoP proof is missing");
            }
            try {
                DPoPUtil.validateBinding(token, proof);
            } catch (VerificationException e) {
                throw new DPoPUtil.DPoPVerificationException(proof, e.getMessage());
            }
        }
    }
}
