package org.keycloak.protocol.oidc.verifier;

import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.TokenUtil;

public class DPoPTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void additionalAccessTokenVerifications(TokenVerifierProviderContext context) {
        if (context.proofOfPossession() != ProofOfPossession.NOT_APPLICABLE) {
            // A DPoP typed access token is accepted where its binding is verified, and only while the feature is enabled
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
        if (context.proofOfPossession() == ProofOfPossession.DEFERRED) {
            verifyAgainstRequestProof(token, context);
        } else {
            verifyPresentedToken(token, context);
        }
    }

    /**
     * The token is presented as a credential, so the proof has to name it by its hash.
     */
    private void verifyPresentedToken(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
        boolean boundToken = isDPoPBound(token);

        if (context.presentation() == TokenPresentation.PROTECTED_RESOURCE) {
            boolean dPoPScheme = TokenUtil.TOKEN_TYPE_DPOP.equalsIgnoreCase(context.authorizationScheme());
            if (boundToken && !dPoPScheme) {
                throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "The access token type is DPoP but Authorization Header is not DPoP");
            }
            if (!boundToken && dPoPScheme) {
                throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "The access token type is not DPoP but Authorization Header is DPoP");
            }
        }

        ClientModel client = context.client(token);
        if (client == null) {
            throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "Client not found");
        }
        if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseDPoP() && !boundToken) {
            throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "This client requires a DPoP-bound access token");
        }

        if (boundToken) {
            if (context.tokenString() == null) {
                throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "Access Token not set for validator");
            }
            DPoP proof = new DPoPUtil.Validator(context.session()).request(context.request()).uriInfo(context.uriInfo())
                    .accessToken(context.tokenString()).validate();
            validateBinding(token, proof);
        }
    }

    /**
     * The verification was deferred until the request was authorized, so the proof of the request itself, which also
     * binds the token being issued, proves possession of the key.
     */
    private void verifyAgainstRequestProof(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
        if (!isDPoPBound(token)) {
            return;
        }
        DPoP proof = context.session().getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
        if (proof == null) {
            throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, "DPoP proof is missing");
        }
        validateBinding(token, proof);
    }

    private void validateBinding(AccessToken token, DPoP proof) throws VerificationException {
        try {
            DPoPUtil.validateBinding(token, proof);
        } catch (VerificationException ex) {
            throw new TokenBindingException(Errors.INVALID_DPOP_PROOF, ex.getMessage());
        }
    }

    private boolean isDPoPBound(AccessToken token) {
        return DPoPUtil.DPOP_TOKEN_TYPE.equalsIgnoreCase(token.getType())
                || (token.getConfirmation() != null && token.getConfirmation().getKeyThumbprint() != null);
    }
}
