/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.tests.oauth.dpop;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.keys.AbstractEddsaKeyProviderFactory;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.oidc.TokenMetadataRepresentation;
import org.keycloak.services.cors.Cors;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testsuite.util.AccountHelper;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.UserInfoResponse;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.MediaType;

import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpOptions;
import org.junit.jupiter.api.Test;

import static org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE;
import static org.keycloak.OAuthErrorException.INVALID_TOKEN;
import static org.keycloak.services.util.DPoPUtil.DPOP_SCHEME;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


@KeycloakIntegrationTest
public class DPoPTest extends BaseDPoPTest {

    @Test
    public void testDPoPAccessTokenButBearerAuthorizationHeader() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofRsaEncoded).send();

        HttpGet get = new HttpGet(oauth.getEndpoints().getUserInfo());
        get.addHeader("Accept", MediaType.APPLICATION_JSON);
        String authorization = "Bearer" + " " + response.getAccessToken();
        get.addHeader(HttpHeaders.AUTHORIZATION, authorization);

        UserInfoResponse userInfoResponse = new UserInfoResponse(oauth.httpClient().get().execute(get));
        assertEquals(401, userInfoResponse.getStatusCode());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPByPublicClientWithDpopJkt() throws Exception {
        // use pre-computed EC key

        int clockSkew = 10; // acceptable clock skew is +-10sec

        sendAuthorizationRequestWithDPoPJkt(jktEc);

        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        successTokenProceduresWithDPoP(dpopProofEcEncoded, jktEc, true, true);
    }

    @Test
    public void testDPoPByPublicClientWithDpopJktWithDifferentDPoPProofKey() throws Exception {
        // use pre-computed EC and RSA key

        int clockSkew = 10; // acceptable clock skew is +-10sec

        sendAuthorizationRequestWithDPoPJkt(jktEc);

        // change key : EC key to RSA key
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        failureTokenProceduresWithDPoP(dpopProofRsaEncoded, "DPoP Proof public key thumbprint does not match dpop_jkt");
    }

    @Test
    public void testDPoPByPublicClient() throws Exception {
        // use pre-computed EC key

        int clockSkew = 10; // acceptable clock skew is +-10sec

        sendAuthorizationRequestWithDPoPJkt(null);

        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        successTokenProceduresWithDPoP(dpopProofEcEncoded, jktEc, true, true);
    }

    @Test
    public void testDPoPByPublicClientClockSkew() throws Exception {
            sendAuthorizationRequestWithDPoPJkt(null);

            // get a DPoP proof 10 seconds in the future
            String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(),
                    (long) (Time.currentTime() + 10), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

            AccessTokenResponse response = successTokenProceduresWithDPoP(dpopProofEcEncoded, jktEc, true, true, false);

            timeOffSet.set(25); // 25 <= 10+10+15, proof not expired because clockSkew, detected by replay check
            response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(dpopProofEcEncoded).send();
            assertEquals(400, response.getStatusCode());
            assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
            assertEquals("DPoP proof has already been used", response.getErrorDescription());

            timeOffSet.set(36); // 36 > 10+10+15, proof expired definitely
            response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(dpopProofEcEncoded).send();
            assertEquals(400, response.getStatusCode());
            assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
            assertEquals("DPoP proof is not active", response.getErrorDescription());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPByPublicClientTokenRefreshWithoutDPoPProof() throws Exception {
        // use pre-computed EC key

        int clockSkew = 10; // acceptable clock skew is +-10sec

        sendAuthorizationRequestWithDPoPJkt(null);

        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        publicClient.updateWithCleanup(c-> c.dpop(false));
        failureRefreshTokenProceduresWithoutDPoP(dpopProofEcEncoded, jktEc);
    }

    @Test
    public void testDPoPProofByConfidentialClient() throws Exception {
        // use pre-computed RSA key

        int clockSkew = -10; // acceptable clock skew is +-10sec

        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofRsaEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        assertEquals(jktRsa, accessToken.getConfirmation().getKeyThumbprint());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        // For confidential client, DPoP is not bind to refresh token (See "section 5 DPoP Access Token Request" of DPoP specification)
        assertNull(refreshToken.getConfirmation());

        TokenMetadataRepresentation tokenMetadataRepresentation = oauth.doIntrospectionRequest(response.getAccessToken(), "access_token").asTokenMetadata();
        assertTrue(tokenMetadataRepresentation.isActive());
        assertEquals(jktRsa, tokenMetadataRepresentation.getConfirmation().getKeyThumbprint());
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, tokenMetadataRepresentation.getOtherClaims().get(OAuth2Constants.TOKEN_TYPE));

        oauth.tokenRevocationRequest(response.getAccessToken()).accessToken().send();

        tokenMetadataRepresentation = oauth.doIntrospectionRequest(response.getAccessToken(), "access_token").asTokenMetadata();
        assertFalse(tokenMetadataRepresentation.isActive());

        // token refresh
        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(dpopProofEcEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        accessToken = oauth.verifyToken(response.getAccessToken());
        assertEquals(jktEc, accessToken.getConfirmation().getKeyThumbprint());
        refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        assertNull(refreshToken.getConfirmation());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPProofByConfidentialClient_EdDSA() throws Exception {
        // Generating keys
        String curveName = AbstractEddsaKeyProviderFactory.DEFAULT_EDDSA_ELLIPTIC_CURVE;
        KeyPair keyPair = KeyUtils.generateEddsaKeyPair(curveName);

        // JWK
        JWKBuilder b = JWKBuilder.create()
                .algorithm(Algorithm.EdDSA);
        JWK jwkEd = b.okp(keyPair.getPublic(), KeyUse.SIG);

        // Thumbprint
        String jktEd = JWKSUtils.computeThumbprint(jwkEd);

        // Header
        JWSHeader jwsEdHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.valueOf(Algorithm.EdDSA), DPOP_JWT_HEADER_TYPE, jwkEd.getKeyId(), jwkEd);

        int clockSkew = -10; // acceptable clock skew is +-10sec

        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String dpopProofEdEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.EdDSA, jwsEdHeader, keyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEdEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        assertEquals(jktEd, accessToken.getConfirmation().getKeyThumbprint());
        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPDisabledByPublicClient() throws Exception {

        publicClient.update(c-> c.dpop(false));
        try {
            // with DPoP proof
            testDPoPByPublicClient();

            // without DPoP proof
            oauth.client(TEST_PUBLIC_CLIENT_ID);
            oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

            String code = oauth.parseLoginResponse().getCode();
            AccessTokenResponse response = oauth.doAccessTokenRequest(code);
            // token-type must be "Bearer" because no DPoP is present within the token-request
            assertEquals(TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());

            assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
            AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
            assertNull(accessToken.getConfirmation());
            RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
            assertNull(refreshToken.getConfirmation());

            // token refresh
            response = oauth.doRefreshTokenRequest(response.getRefreshToken());
            assertEquals(TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());

            assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
            accessToken = oauth.verifyToken(response.getAccessToken());
            assertNull(accessToken.getConfirmation());
            refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
            assertNull(refreshToken.getConfirmation());

            AccountHelper.logout(realm.admin(), TEST_USER_NAME);
        } finally {
            publicClient.update(c-> c.dpop(true));
        }
    }

    @Test
    public void testTokenRefreshWithReplayedDPoPProofByPublicClient() throws Exception {
        oauth.client(TEST_PUBLIC_CLIENT_ID);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEcEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        // token refresh
        response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(dpopProofEcEncoded).send();
        assertNull(response.getTokenType());
        assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("DPoP proof has already been used", response.getErrorDescription());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testTokenRefreshWithoutDPoPProofByConfidentialClient() throws Exception {
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofRsaEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        // token refresh
        response = oauth.doRefreshTokenRequest(response.getRefreshToken());
        assertNull(response.getTokenType());
        assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("DPoP proof is missing", response.getErrorDescription());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPProofCorsPreflight() throws IOException {
        HttpOptions options = new HttpOptions(oauth.getEndpoints().getToken());
        options.setHeader("Origin", "http://example.com");
        try (CloseableHttpResponse response = oauth.httpClient().get().execute(options)) {
            Map<String, String> responseHeaders = Arrays.stream(response.getAllHeaders())
                    .collect(Collectors.toMap(Header::getName, Header::getValue));
            Set<String> allowedHeaders = Arrays.stream(responseHeaders.get(Cors.ACCESS_CONTROL_ALLOW_HEADERS).split(", "))
                    .collect(Collectors.toSet());

            assertTrue(allowedHeaders.contains(TokenUtil.TOKEN_TYPE_DPOP));
        }
    }

    @Test
    public void testDPoPProofWithoutJwk() throws Exception {
        JWSHeader jwsHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, DPOP_JWT_HEADER_TYPE, jwkEc.getKeyId(), null);
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(),
                Algorithm.ES256, jwsHeader, ecKeyPair.getPrivate(), null, new TestingDPoPGenerator()), "No JWK in DPoP header");
    }

    @Test
    public void testDPoPProofInvalidAlgorithm() throws Exception {
        JWSHeader jwsHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.none, DPOP_JWT_HEADER_TYPE, jwkEc.getKeyId(), jwkEc);
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsHeader, ecKeyPair.getPrivate(), null), "Unsupported DPoP algorithm: none");
    }

    @Test
    public void testDPoPProofInvalidType() throws Exception {
        JWSHeader jwsEcHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, "jwt+dpop", jwkEc.getKeyId(), jwkEc);
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "Invalid or missing type in DPoP header: jwt+dpop");
    }

    @Test
    public void testDPoPProofInvalidSignature() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(),
                Algorithm.PS256, jwsEcHeader, rsaKeyPair.getPrivate(), null, new TestingDPoPGenerator()), "DPoP verification failure: org.keycloak.exceptions.TokenSignatureInvalidException: Invalid token signature");
    }

    @Test
    public void testDPoPProofMandatoryClaimMissing() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(null, HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "DPoP mandatory claims are missing");
    }

    @Test
    public void testDPoPProofReplayed() throws Exception {
        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEcEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());
        AccountHelper.logout(realm.admin(), TEST_USER_NAME);

        testDPoPProofFailure(dpopProofEcEncoded, "DPoP proof has already been used");
    }


    @Test
    public void testWithoutDPoPProof() throws Exception {
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.doAccessTokenRequest(code);

        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("DPoP proof is missing", response.getErrorDescription());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPProofExpired() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() - 100000), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "DPoP proof is not active");
    }

    @Test
    public void testDPoPProofHttpMethodMismatch() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "DPoP HTTP method mismatch");
    }

    @Test
    public void testDPoPProofHttpUrlMalformed() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, ":::*;", (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "Malformed HTTP URL in DPoP proof");
    }

    @Test
    public void testDPoPProofHttpUrlMismatch() throws Exception {
        testDPoPProofFailure(generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, "https://server.example.com/token", (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null), "DPoP HTTP URL mismatch");
    }

    // Helper methods

    private AccessTokenResponse getDPoPBindAccessToken(KeyPair rsaKeyPair) throws Exception {
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofRsaEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.MODULUS, ((RSAPublicJWK) jwkRsa).getModulus());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.PUBLIC_EXPONENT, ((RSAPublicJWK) jwkRsa).getPublicExponent());
        String jkt = JWKSUtils.computeThumbprint(jwkRsa);
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());

        return response;
    }

    private String doSuccessfulUserInfoGet(AccessTokenResponse accessTokenResponse, KeyPair rsaKeyPair) throws Exception {
        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), accessTokenResponse.getAccessToken());
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(accessTokenResponse.getAccessToken()).dpop(dpopProofRsaEncoded).send();
        assertEquals(TEST_USER_NAME, userInfoResponse.getUserInfo().getPreferredUsername());
        return dpopProofRsaEncoded;
    }

    private void testDPoPProofFailure(String dpopProofEncoded, String errorDescription) throws Exception {
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();

        assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals(errorDescription, response.getErrorDescription());
        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    private void testWWWAuthenticateHeaderError(UserInfoResponse userInfoResponse) {
        String wwwAuthenticate = userInfoResponse.getHeaders().get("WWW-Authenticate");
        assertThat(wwwAuthenticate, startsWith(DPOP_SCHEME));
        String chunks1 = wwwAuthenticate.substring(DPOP_SCHEME.length() + 1);
        Map<String, String> map = new HashMap<>();
        for (String p : chunks1.split(", ")) {
            String[] chunks2 = p.split("=");
            map.put(chunks2[0], chunks2[1]);
        }

        assertEquals(map.get(OAuth2Constants.ERROR), "\"" + INVALID_TOKEN + "\"");
    }


    private void failureRefreshTokenProceduresWithoutDPoP(String dpopProofEncoded, String jkt) throws Exception {
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        assertEquals(jkt, refreshToken.getConfirmation().getKeyThumbprint());

        // token refresh without DPoP Proof
        response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(null).send();
        assertEquals(400, response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_GRANT, response.getError());
        assertEquals("DPoP proof is missing", response.getErrorDescription());

        // logout
        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }


    @Test
    public void testDPoPProofWithClientCredentialsGrant() throws Exception {
        confidentialClient.update(c-> {
            c.serviceAccountsEnabled(true);
            c.dpop(true);
            return c;
        });
        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);

        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        AccessTokenResponse response = oauth.clientCredentialsGrantRequest().dpopProof(dpopProofRsaEncoded).send();
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());

        jwkRsa.getOtherClaims().put(RSAPublicJWK.MODULUS, ((RSAPublicJWK) jwkRsa).getModulus());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.PUBLIC_EXPONENT, ((RSAPublicJWK) jwkRsa).getPublicExponent());
        String jkt = JWKSUtils.computeThumbprint(jwkRsa);
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPProofWithResourceOwnerPasswordCredentialsGrant() throws Exception {
        confidentialClient.update(c-> {
            c.directAccessGrantsEnabled(true);
            c.dpop(true);
            return c;
        });

        oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);

        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);

        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), null);

        AccessTokenResponse response = oauth.passwordGrantRequest(TEST_USER_NAME, TEST_USER_PASSWORD).dpopProof(dpopProofRsaEncoded).send();
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        assertEquals(TokenUtil.TOKEN_TYPE_DPOP, response.getTokenType());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());

        jwkRsa.getOtherClaims().put(RSAPublicJWK.MODULUS, ((RSAPublicJWK) jwkRsa).getModulus());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.PUBLIC_EXPONENT, ((RSAPublicJWK) jwkRsa).getPublicExponent());
        String jkt = JWKSUtils.computeThumbprint(jwkRsa);
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }
}
