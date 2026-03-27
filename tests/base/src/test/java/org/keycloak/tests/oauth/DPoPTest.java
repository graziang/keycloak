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

package org.keycloak.tests.oauth;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.keys.AbstractEddsaKeyProviderFactory;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.oidc.TokenMetadataRepresentation;
import org.keycloak.testframework.admin.AdminClientFactory;
import org.keycloak.testframework.annotations.InjectAdminClientFactory;
import org.keycloak.testframework.annotations.InjectClient;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectSimpleHttp;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.RealmConfigBuilder;
import org.keycloak.testframework.remote.timeoffset.InjectTimeOffSet;
import org.keycloak.testframework.remote.timeoffset.TimeOffSet;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testsuite.util.AccountHelper;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.UserInfoResponse;
import org.keycloak.util.DPoPGenerator;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.MediaType;

import org.apache.http.client.methods.HttpGet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.keycloak.OAuth2Constants.DPOP_HTTP_HEADER;
import static org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE;
import static org.keycloak.OAuthErrorException.INVALID_TOKEN;
import static org.keycloak.jose.jwk.JWKUtil.toIntegerBytes;
import static org.keycloak.models.Constants.CREATE_DEFAULT_CLIENT_SCOPES;
import static org.keycloak.services.util.DPoPUtil.DPOP_SCHEME;
import static org.keycloak.services.util.DPoPUtil.DPOP_TOKEN_TYPE;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


@KeycloakIntegrationTest
public class DPoPTest {
    private static final String TEST_CONFIDENTIAL_CLIENT_ID = "dpop-confidential-client";
    private static final String TEST_CONFIDENTIAL_CLIENT_SECRET = "password";
    private static final String TEST_PUBLIC_CLIENT_ID = "dpop-public-client";
    private static final String TEST_USER_NAME = "test-user@localhost";
    private static final String TEST_USER_PASSWORD = "password";

    @InjectRealm(config = DPoPRealm.class)
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectClient(attachTo = TEST_CONFIDENTIAL_CLIENT_ID)
    ManagedClient confidentialClient;

    @InjectClient(attachTo = TEST_PUBLIC_CLIENT_ID)
    ManagedClient publicClient;

    @InjectEvents
    Events events;

    @InjectTimeOffSet
    TimeOffSet  timeOffSet;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @InjectSimpleHttp
    SimpleHttp simpleHttp;

    @InjectAdminClientFactory
    protected AdminClientFactory adminClientFactory;

    public static class DPoPRealm implements RealmConfig {
        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.eventsEnabled(true);

            realm.attribute(CREATE_DEFAULT_CLIENT_SCOPES, String.valueOf(true));

            // Confidential client with DPoP enabled
            realm.addClient(TEST_CONFIDENTIAL_CLIENT_ID)
                    .secret(TEST_CONFIDENTIAL_CLIENT_SECRET)
                    .redirectUris("*")
                    .webOrigins("*")
                    .directAccessGrantsEnabled(true)
                    .attribute(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS, "true");

            // Public client with DPoP enabled
            realm.addClient(TEST_PUBLIC_CLIENT_ID)
                    .publicClient(true)
                    .redirectUris("*")
                    .webOrigins("*")
                    .directAccessGrantsEnabled(true)
                    .attribute(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS, "true");

            // Test users
            realm.addUser(TEST_USER_NAME)
                    .password(TEST_USER_PASSWORD)
                    .name("Test", "User")
                    .email(TEST_USER_NAME)
                    .emailVerified(true)
                    .clientRoles(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID, AccountRoles.DEFAULT);

            realm.addUser("test-admin@localhost")
                    .password("password")
                    .name("Test", "Admin")
                    .email("test-admin@localhost")
                    .emailVerified(true)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.REALM_ADMIN)
                    .roles(OAuth2Constants.OFFLINE_ACCESS);

            return realm;
        }
    }

    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;
    private JWK jwkRsa;
    private JWK jwkEc;
    private JWSHeader jwsRsaHeader;
    private JWSHeader jwsEcHeader;
    private String jktRsa;
    private String jktEc;
    private ClientRegistration reg;

    private HttpGet get;

    @BeforeEach
    public void beforeDPoPTest() throws Exception {
        rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.MODULUS, ((RSAPublicJWK) jwkRsa).getModulus());
        jwkRsa.getOtherClaims().put(RSAPublicJWK.PUBLIC_EXPONENT, ((RSAPublicJWK) jwkRsa).getPublicExponent());
        jktRsa = JWKSUtils.computeThumbprint(jwkRsa);
        jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);

        ecKeyPair = generateEcdsaKey("secp256r1");
        jwkEc = createEcJwk(ecKeyPair.getPublic());
        jwkEc.getOtherClaims().put(ECPublicJWK.CRV, ((ECPublicJWK) jwkEc).getCrv());
        jwkEc.getOtherClaims().put(ECPublicJWK.X, ((ECPublicJWK) jwkEc).getX());
        jwkEc.getOtherClaims().put(ECPublicJWK.Y, ((ECPublicJWK) jwkEc).getY());
        jktEc = JWKSUtils.computeThumbprint(jwkEc);
        jwsEcHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, DPOP_JWT_HEADER_TYPE, jwkEc.getKeyId(), jwkEc);
    }

    @AfterEach
    public void afterDPoPTest() {
      //  oauth.scope(null);
    }

    @Test
    public void testDuplicatedAuthorizationHeaderOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        get = new HttpGet(oauth.getEndpoints().getUserInfo());
        get.addHeader("Accept", MediaType.APPLICATION_JSON);
        String authorization = "DPoP" + " " + response.getAccessToken();
        get.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        get.addHeader(HttpHeaders.AUTHORIZATION, authorization);

        UserInfoResponse userInfoResponse = new UserInfoResponse(oauth.httpClient().get().execute(get));

        assertEquals(401, userInfoResponse.getStatusCode());
        assertEquals("HTTP 401 Unauthorized", userInfoResponse.getError());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPAccessTokenButBearerAuthorizationHeader() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        get = new HttpGet(oauth.getEndpoints().getUserInfo());
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

//    @org.junit.Test
//    public void testDPoPProofCorsPreflight() {
//        Map<String, String> responseHeaders = TokenEndpointCorsTest.getTokenEndpointPreflightResponseHeaders(oauth);
//        Set<String> allowedHeaders = Arrays.stream(responseHeaders.get(Cors.ACCESS_CONTROL_ALLOW_HEADERS).split(", ")).collect(Collectors.toSet());
//
//        assertTrue(allowedHeaders.contains(TokenUtil.TOKEN_TYPE_DPOP));
//    }

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
    public void testDPoPProofOnUserInfoByConfidentialClient() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);
        doSuccessfulUserInfoGet(response, rsaKeyPair);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testWithoutDPoPProofOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(null).send();
        assertEquals(401, userInfoResponse.getStatusCode());
        testWWWAuthenticateHeaderError(userInfoResponse);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPProofOnUserInfoWithMissingAcccessTokenHash() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);
        JWK jwkRsa1 = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader1 = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa1.getKeyId(), jwkRsa1);
        // No ath
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader1, rsaKeyPair.getPrivate(), null);
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProofRsaEncoded).send();
        assertEquals(401, userInfoResponse.getStatusCode());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testInvalidDPoPProofOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        // invalid "htu" claim
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), response.getAccessToken());
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProofRsaEncoded).send();
        assertEquals(401, userInfoResponse.getStatusCode());
        testWWWAuthenticateHeaderError(userInfoResponse);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testMultipleUseDPoPProofOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);
        String dpopProof = doSuccessfulUserInfoGet(response, rsaKeyPair);

        // use the same DPoP proof
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProof).send();
        assertEquals(401, userInfoResponse.getStatusCode());
        testWWWAuthenticateHeaderError(userInfoResponse);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDifferentKeyDPoPProofOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        // use different key
        rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), response.getAccessToken());
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProofRsaEncoded).send();
        assertEquals(401, userInfoResponse.getStatusCode());
        testWWWAuthenticateHeaderError(userInfoResponse);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
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

    @Test
    public void testDPoPDisabledOnUserInfo() throws Exception {

       confidentialClient.update(c-> c.dpop(false));
        try {
            KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
            AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);
            doSuccessfulUserInfoGet(response, rsaKeyPair);

            UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(null).send();
            assertEquals(401, userInfoResponse.getStatusCode());
            testWWWAuthenticateHeaderError(userInfoResponse);

            AccountHelper.logout(realm.admin(), TEST_USER_NAME);
        } finally {
            confidentialClient.update(c-> c.dpop(true));
        }
    }



    // Helper methods

    private static JWK createRsaJwk(java.security.Key publicKey) {
        return JWKBuilder.create()
                .rsa(publicKey, KeyUse.SIG);
    }

    private static JWK createEcJwk(java.security.Key publicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;

        int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
        ECPublicJWK k = new ECPublicJWK();
        k.setKeyType(org.keycloak.crypto.KeyType.EC);
        k.setCrv("P-" + fieldSize);
        k.setX(org.keycloak.common.util.Base64Url.encode(toIntegerBytes(ecKey.getW().getAffineX(), fieldSize)));
        k.setY(org.keycloak.common.util.Base64Url.encode(toIntegerBytes(ecKey.getW().getAffineY(), fieldSize)));

        return k;
    }

    private static KeyPair generateEcdsaKey(String ecDomainParamName) throws Exception {
        return org.keycloak.common.util.KeyUtils.generateEcKeyPair(ecDomainParamName);
    }

    private static String generateSignedDPoPProof(String jti, String htm, String htu, Long iat,
                                                   String algorithm, JWSHeader jwsHeader,
                                                   PrivateKey privateKey, String accessToken) throws IOException {
        return generateSignedDPoPProof(jti, htm, htu, iat, algorithm, jwsHeader, privateKey, accessToken, new DPoPGenerator());
    }

    public static String generateSignedDPoPProof(String jti, String htm, String htu, Long iat, String algorithm, JWSHeader jwsHeader, PrivateKey privateKey, String accessToken, DPoPGenerator dpopGenerator) throws IOException {
        if (algorithm.equals(jwsHeader.getAlgorithm().toString())) {
            return dpopGenerator.generateSignedDPoPProof(jti, htm, htu, iat, jwsHeader, privateKey, accessToken);
        } else {
            // Ability to test failure scenarios when different algorithms are used for the JWSHeader and for the actual key
            JWSHeader updatedHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.valueOf(algorithm), jwsHeader.getType(), jwsHeader.getKeyId(), jwsHeader.getKey());
            String dpop = dpopGenerator.generateSignedDPoPProof(jti, htm, htu, iat, updatedHeader, privateKey, accessToken);
            String dpopOrigHeader = Base64Url.encode(JsonSerialization.writeValueAsBytes(jwsHeader));
            // Replace header with the original algorithm
            String updatedAlgorithmHeader = dpop.substring(0, dpop.indexOf('.'));
            return dpop.replace(updatedAlgorithmHeader, dpopOrigHeader);
        }
    }

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

    private void sendAuthorizationRequestWithDPoPJkt(String dpopJkt) {
        oauth.client(TEST_PUBLIC_CLIENT_ID);
        oauth.loginForm().dpopJkt(dpopJkt).doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
    }

    private AccessTokenResponse successTokenProceduresWithDPoP(String dpopProofEncoded, String jkt, boolean accessTokenBound, boolean refreshTokenBound) throws Exception {
        return successTokenProceduresWithDPoP(dpopProofEncoded, jkt, accessTokenBound, refreshTokenBound, true);
    }

    private AccessTokenResponse successTokenProceduresWithDPoP(String dpopProofEncoded, String jkt, boolean accessTokenBound,
                                                               boolean refreshTokenBound, boolean performLogout) throws Exception {
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();
        assertEquals(accessTokenBound ? TokenUtil.TOKEN_TYPE_DPOP : TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        if (accessTokenBound) {
            assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());
        }
        else {
            assertNull(accessToken.getConfirmation());
        }
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        if (refreshTokenBound) {
            assertEquals(jkt, refreshToken.getConfirmation().getKeyThumbprint());
        }
        else {
            assertNull(refreshToken.getConfirmation());
        }

        // token refresh
        if (dpopProofEncoded != null) {
            dpopProofEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);
        }
        response = oauth.refreshRequest(response.getRefreshToken()).dpopProof(dpopProofEncoded).send();
        assertEquals(accessTokenBound ? TokenUtil.TOKEN_TYPE_DPOP : TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        accessToken = oauth.verifyToken(response.getAccessToken());
        if (accessTokenBound) {
            assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());
        }
        else {
            assertNull(accessToken.getConfirmation());
        }
        refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        if (refreshTokenBound) {
            assertEquals(jkt, refreshToken.getConfirmation().getKeyThumbprint());
        }
        else {
            assertNull(refreshToken.getConfirmation());
        }

        if (accessTokenBound) {
            // userinfo access
            dpopProofEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), response.getAccessToken());
            UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProofEncoded).send();
            assertEquals(TEST_USER_NAME, userInfoResponse.getUserInfo().getPreferredUsername());
        }

        // logout
        if (performLogout) {
            AccountHelper.logout(realm.admin(), TEST_USER_NAME);
        }
        return response;
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

    private void failureTokenProceduresWithDPoP(String dpopProofEncoded, String error) throws Exception {
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();
        assertEquals(400, response.getStatusCode());
        assertEquals(error, response.getErrorDescription());
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

    @Test
    public void testDPoPAdminRequestSuccess() throws Exception {
        confidentialClient.update(c-> {
            c.serviceAccountsEnabled(true);
            c.dpop(true);
            return c;
        });

        try (Keycloak adminClientDPoP = adminClientFactory.create()
                .realm(realm.getName())
                .username("test-admin@localhost")
                .password("password")
                .clientId(TEST_CONFIDENTIAL_CLIENT_ID)
                .clientSecret(TEST_CONFIDENTIAL_CLIENT_SECRET)
                .useDPoP(true)
                .build()
        ) {
            RealmRepresentation realmRep = adminClientDPoP.realm(realm.getName()).toRepresentation();
            assertEquals(realm.getName(), realmRep.getRealm());

            // To enforce token refresh by admin client in the next request
            timeOffSet.set(700);

            realmRep = adminClientDPoP.realm(realm.getName()).toRepresentation();
            assertEquals(realm.getName(), realmRep.getRealm());
        }
    }

    @Test
    public void testDPoPAdminRequestFailure() throws Exception {
        confidentialClient.update(c-> {
            c.directAccessGrantsEnabled(true);
            c.dpop(true);
            return c;
        });

        try (Keycloak adminClientDPoP = adminClientFactory.create()
                .realm(realm.getName())
                .username("test-admin@localhost")
                .password("password")
                .clientId(TEST_CONFIDENTIAL_CLIENT_ID)
                .clientSecret(TEST_CONFIDENTIAL_CLIENT_SECRET)
                .useDPoP(false)
                .build()
        ) {
            adminClientDPoP.realm(realm.getName()).toRepresentation();
            fail("Expected exception when calling adminClient without DPoP for the client, which requires DPoP");
        } catch (ProcessingException pe) {
            assertTrue(pe.getCause() instanceof BadRequestException);
        }
    }

    @Test
    public void testDPoPAccountRequestSuccess() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        oauth.scope("roles");
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        // Valid DPoP proof for the access-token
        String accountUrl = realm.getBaseUrl() + "/account";
        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, accountUrl, (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), response.getAccessToken());

        int status = simpleHttp.doGet(accountUrl)
                .header("Accept", "application/json")
                .header("Authorization", DPOP_TOKEN_TYPE + " " + response.getAccessToken())
                .header(DPOP_HTTP_HEADER, dpopProofRsaEncoded)
                .asStatus();
        assertEquals(200, status);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPAccountRequestFailures() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        String accountUrl = realm.getBaseUrl() + "/account";

        // Request with DPoP accessToken and with "Authorization: Bearer" header should fail
        int status = simpleHttp.doGet(accountUrl)
                .header("Accept", "application/json")
                .auth(response.getAccessToken())
                .asStatus();
        assertEquals(401, status);

        // Request with DPoP accessToken and with "Authorization: DPoP" header should fail
        status = simpleHttp.doGet(accountUrl)
                .header("Accept", "application/json")
                .header("Authorization", DPOP_TOKEN_TYPE + " " + response.getAccessToken())
                .asStatus();
        assertEquals(401, status);

        // Invalid DPoP proof for the access-token (Request URL is userInfo instead of accountUrl)
        JWK jwkRsa = createRsaJwk(rsaKeyPair.getPublic());
        JWSHeader jwsRsaHeader = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsa.getKeyId(), jwkRsa);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeader, rsaKeyPair.getPrivate(), response.getAccessToken());

        status = simpleHttp.doGet(accountUrl)
                .header("Accept", "application/json")
                .header("Authorization", DPOP_TOKEN_TYPE + " " + response.getAccessToken())
                .header(DPOP_HTTP_HEADER, dpopProofRsaEncoded)
                .asStatus();
        assertEquals(401, status);

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    private void setInitialAccessTokenForDynamicClientRegistration() {
        // get initial access token for Dynamic Client Registration with authentication
        reg =  oauth.clientRegistration();
        ClientInitialAccessPresentation token = realm.admin().clientInitialAccess().create(new ClientInitialAccessCreatePresentation(0, 10));
        reg.auth(Auth.token(token));
    }

    // DPoPGenerator with the ability to inject KeyWrapper. Useful for testing purposes of failure scenarios (EG. when different algorithm is used for JWS and for the underlying key etc)
    private class TestingDPoPGenerator extends DPoPGenerator {

        @Override
        protected KeyWrapper getKeyWrapper(JWSHeader jwsHeader, PrivateKey privateKey) {
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setKid(jwsHeader.getKeyId());
            keyWrapper.setAlgorithm(jwsHeader.getAlgorithm().toString());
            keyWrapper.setPrivateKey(privateKey);
            keyWrapper.setType(privateKey.getAlgorithm());
            keyWrapper.setUse(KeyUse.SIG);
            return keyWrapper;
        }

    }
}
