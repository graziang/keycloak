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

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testsuite.util.AccountHelper;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.UserInfoResponse;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.MediaType;

import org.apache.http.client.methods.HttpGet;
import org.junit.jupiter.api.Test;

import static org.keycloak.OAuth2Constants.DPOP_HTTP_HEADER;
import static org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE;
import static org.keycloak.OAuthErrorException.INVALID_TOKEN;
import static org.keycloak.services.util.DPoPUtil.DPOP_SCHEME;
import static org.keycloak.services.util.DPoPUtil.DPOP_TOKEN_TYPE;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@KeycloakIntegrationTest
public class DPoPAPITest extends BaseDPoPTest {

    // UserInfo endpoint tests

    @Test
    public void testDuplicatedAuthorizationHeaderOnUserInfo() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateRsaKeyPair(2048);
        AccessTokenResponse response = getDPoPBindAccessToken(rsaKeyPair);

        HttpGet get = new HttpGet(oauth.getEndpoints().getUserInfo());
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

    // Admin Client tests

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

    // Account API tests

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
}
