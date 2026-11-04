package org.keycloak.protocol.oidc.verifier;

import java.util.List;

import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.verifier.TokenVerificationContext.TokenUse;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.TokenUtil;

public class DPoPTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void additionalAccessTokenVerifications(TokenVerifier<AccessToken> verifier, TokenVerificationContext context) {
        if (context.tokenUse().requiresProofOfPossession()) {
            boolean enabled = Profile.isFeatureEnabled(Profile.Feature.DPOP);
            verifier.tokenType(enabled ? List.of(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP)
                    : List.of(TokenUtil.TOKEN_TYPE_BEARER));
            verifier.withChecks(token -> {
                if (isDPoPBound(token)) {
                    if (!enabled) {
                        throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "DPoP is disabled");
                    }
                    if (token.getConfirmation() == null || token.getConfirmation().getKeyThumbprint() == null) {
                        throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "No DPoP key thumbprint in access token");
                    }
                }
                return true;
            });
        }
    }

    @Override
    public void verifyTokenBinding(AccessToken token, TokenVerificationContext context) throws VerificationException {
        boolean boundToken = isDPoPBound(token);
        if (!Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
            if (boundToken) {
                throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "DPoP is disabled");
            }
            return;
        }

        try {
            if (context.tokenUse() == TokenUse.TOKEN_EXCHANGE) {
                if (boundToken) {
                    // The token endpoint has validated this proof. It need not contain a resource access token hash.
                    DPoP proof = context.session().getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
                    if (proof == null) {
                        throw new VerificationException("DPoP proof is missing");
                    }
                    DPoPUtil.validateBinding(token, proof);
                }
                return;
            }

            if (context.tokenUse() == TokenUse.RESOURCE_AUTHORIZATION) {
                boolean dPoPScheme = TokenUtil.TOKEN_TYPE_DPOP.equalsIgnoreCase(context.authorizationScheme());
                if (boundToken && !dPoPScheme) {
                    throw new VerificationException("A DPoP-bound access token requires the DPoP authorization scheme");
                }
                if (!boundToken && dPoPScheme) {
                    throw new VerificationException("The DPoP authorization scheme requires a DPoP-bound access token");
                }
            }

            ClientModel client = context.realm().getClientByClientId(token.getIssuedFor());
            if (client == null) {
                throw new VerificationException("Client not found");
            }
            if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseDPoP() && !boundToken) {
                throw new VerificationException("This client requires a DPoP-bound access token");
            }
            if (boundToken) {
                if (context.tokenString() == null) {
                    throw new VerificationException("Access Token not set for validator");
                }
                DPoP proof = new DPoPUtil.Validator(context.session()).request(context.request()).uriInfo(context.uriInfo())
                        .accessToken(context.tokenString()).validate();
                DPoPUtil.validateBinding(token, proof);
            }
        } catch (VerificationException ex) {
            throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, ex);
        }
    }

    private static boolean isDPoPBound(AccessToken token) {
        return TokenUtil.TOKEN_TYPE_DPOP.equalsIgnoreCase(token.getType())
                || (token.getConfirmation() != null && token.getConfirmation().getKeyThumbprint() != null);
    }
}
