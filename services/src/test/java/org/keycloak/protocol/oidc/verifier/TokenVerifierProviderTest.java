package org.keycloak.protocol.oidc.verifier;

import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.profile.CommaSeparatedListProfileConfigResolver;
import org.keycloak.protocol.oidc.verifier.TokenVerificationContext.TokenUse;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.AbstractUtilSessionTest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TokenVerifierProviderTest extends AbstractUtilSessionTest {

    @AfterEach
    public void resetProfileAndProof() {
        Profile.defaults();
        session.removeAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE);
    }

    @ParameterizedTest
    @EnumSource(value = TokenUse.class, names = {"RESOURCE_AUTHORIZATION", "PARAMETER_AUTHORIZATION", "TOKEN_EXCHANGE"})
    public void disabledDPoPRejectsBothTypedAndConfirmationBoundTokens(TokenUse use) {
        Profile.configure(new CommaSeparatedListProfileConfigResolver("", "dpop"));
        DPoPTokenVerifierProvider provider = new DPoPTokenVerifierProvider();
        TokenVerificationContext context = context(use);
        for (String type : new String[] {TokenUtil.TOKEN_TYPE_DPOP, TokenUtil.TOKEN_TYPE_BEARER}) {
            AccessToken token = boundToken(type);
            TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(token);
            provider.additionalAccessTokenVerifications(verifier, context);
            assertThrows(VerificationException.class, verifier::verify);
            assertThrows(VerificationException.class, () -> provider.verifyTokenBinding(token, context));
        }
        AccessToken bearer = new AccessToken();
        bearer.type(TokenUtil.TOKEN_TYPE_BEARER);
        TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(bearer);
        provider.additionalAccessTokenVerifications(verifier, context);
        assertDoesNotThrow(verifier::verify);
    }

    @ParameterizedTest
    @EnumSource(value = TokenUse.class, names = {"RESOURCE_AUTHORIZATION", "PARAMETER_AUTHORIZATION", "TOKEN_EXCHANGE"})
    public void dPoPTypeRequiresConfirmation(TokenUse use) {
        AccessToken token = new AccessToken();
        token.type(TokenUtil.TOKEN_TYPE_DPOP);
        TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(token);
        new DPoPTokenVerifierProvider().additionalAccessTokenVerifications(verifier, context(use));
        assertThrows(VerificationException.class, verifier::verify);
    }

    @ParameterizedTest
    @EnumSource(value = TokenUse.class, names = {"INTROSPECTION", "AUTHENTICATION_CHANNEL"})
    public void nonHolderContextsDoNotRequireDPoP(TokenUse use) {
        Profile.configure(new CommaSeparatedListProfileConfigResolver("", "dpop"));
        TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(boundToken(TokenUtil.TOKEN_TYPE_DPOP));
        new DPoPTokenVerifierProvider().additionalAccessTokenVerifications(verifier, context(use));
        assertDoesNotThrow(verifier::verify);
        assertThrows(IllegalArgumentException.class,
                () -> new TokenVerifierProviderManager().verifyTokenBinding(verifier.getToken(), context(use)));
    }

    @Test
    public void exchangeMatchesTheValidatedRequestProofWithoutResourceHash() throws Exception {
        DPoPTokenVerifierProvider provider = new DPoPTokenVerifierProvider();
        AccessToken token = boundToken(TokenUtil.TOKEN_TYPE_BEARER);
        TokenVerificationContext context = context(TokenUse.TOKEN_EXCHANGE);
        assertThrows(VerificationException.class, () -> provider.verifyTokenBinding(token, context));
        DPoP proof = new DPoP();
        proof.setThumbprint("different-key");
        session.setAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, proof);
        assertThrows(VerificationException.class, () -> provider.verifyTokenBinding(token, context));
        proof.setThumbprint("key-thumbprint");
        provider.verifyTokenBinding(token, context);
    }

    @Test
    public void confirmationCannotBePresentedAsBearer() {
        TokenVerificationContext context = new TokenVerificationContext(session, null, null, null,
                "encoded-token", TokenUtil.TOKEN_TYPE_BEARER, TokenUse.RESOURCE_AUTHORIZATION);
        assertThrows(TokenBindingException.class,
                () -> new DPoPTokenVerifierProvider().verifyTokenBinding(boundToken(TokenUtil.TOKEN_TYPE_BEARER), context));
    }

    private TokenVerificationContext context(TokenUse use) {
        return new TokenVerificationContext(session, null, null, null, null, null, use);
    }

    private AccessToken boundToken(String type) {
        AccessToken token = new AccessToken();
        token.type(type);
        AccessToken.Confirmation confirmation = new AccessToken.Confirmation();
        confirmation.setKeyThumbprint("key-thumbprint");
        token.setConfirmation(confirmation);
        return token;
    }
}
