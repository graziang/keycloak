package org.keycloak.services.util;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.profile.CommaSeparatedListProfileConfigResolver;
import org.keycloak.http.HttpRequest;
import org.keycloak.protocol.oidc.verifier.DPoPTokenVerifierProvider;
import org.keycloak.protocol.oidc.verifier.TokenVerifierProvider.ProofOfPossession;
import org.keycloak.protocol.oidc.verifier.TokenVerifierProvider.TokenVerifierProviderContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.AbstractUtilSessionTest;

import org.jboss.resteasy.mock.MockHttpRequest;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DPoPUtilTests extends AbstractUtilSessionTest {
    private static final String URL = "http://localhost/test";
    private static final long IAT = 1_000_000_000L;

    @Test
    public void testRejectsUnsupportedJwkKeyType() {
        String jwkJson = "{\"kty\":\"foo\",\"kid\":\"invalid-kid\",\"alg\":\"RS256\"}";
        String headerJson = "{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":" + jwkJson + "}";
        String payloadJson = "{\"jti\":\"test-jti\",\"htm\":\"GET\",\"htu\":\"http://localhost/test\",\"iat\":" + IAT + "}";

        String header = encode(headerJson);
        String payload = encode(payloadJson);
        String dpop = header + "." + payload + "." + "sig";

        createHttpRequest("GET", dpop);

        DPoPUtil.Validator validator = new DPoPUtil.Validator(session)
                .request(session.getContext().getHttpRequest())
                .uriInfo(session.getContext().getUri());

        VerificationException thrown = assertThrows(VerificationException.class, validator::validate);
        assertThat(thrown.getMessage(), containsString("Unsupported key type"));
    }

    @Test
    public void testDisabledDPoPRejectsBoundTokens() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver("", "dpop"));
        try {
            for (ProofOfPossession proofOfPossession : new ProofOfPossession[] {ProofOfPossession.REQUIRED, ProofOfPossession.DEFERRED}) {
                AccessToken token = new AccessToken();
                token.type(TokenUtil.TOKEN_TYPE_DPOP);
                TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(token);
                new DPoPTokenVerifierProvider().additionalAccessTokenVerifications(TokenVerifierProviderContext
                        .builder(verifier, session).proofOfPossession(proofOfPossession).build());
                assertThrows(VerificationException.class, verifier::verify);

                token.type(TokenUtil.TOKEN_TYPE_BEARER);
                assertDoesNotThrow(verifier::verify);
            }
        } finally {
            Profile.defaults();
        }
    }

    @Test
    public void testDisabledDPoPAcceptsBoundTokensWithoutProofOfPossession() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver("", "dpop"));
        try {
            AccessToken token = new AccessToken();
            token.type(TokenUtil.TOKEN_TYPE_DPOP);
            TokenVerifier<AccessToken> verifier = TokenVerifier.createWithoutSignature(token);
            new DPoPTokenVerifierProvider().additionalAccessTokenVerifications(TokenVerifierProviderContext
                    .builder(verifier, session).proofOfPossession(ProofOfPossession.NOT_APPLICABLE).build());
            assertDoesNotThrow(verifier::verify);
        } finally {
            Profile.defaults();
        }
    }

    private static void createHttpRequest(String httpMethod, String dpop) {
        MockHttpRequest mockRequest = MockHttpRequest.create(httpMethod, URI.create(URL), URI.create(URL));
        mockRequest.header("DPoP", dpop);
        HttpRequest httpRequest = new HttpRequestImpl(mockRequest);
        session.getContext().setHttpRequest(httpRequest);
    }

    private static String encode(String data) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }
}
