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
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.testframework.admin.AdminClientFactory;
import org.keycloak.testframework.annotations.InjectAdminClientFactory;
import org.keycloak.testframework.annotations.InjectClient;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectSimpleHttp;
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

import org.junit.jupiter.api.BeforeEach;

import static org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE;
import static org.keycloak.jose.jwk.JWKUtil.toIntegerBytes;
import static org.keycloak.models.Constants.CREATE_DEFAULT_CLIENT_SCOPES;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public abstract class BaseDPoPTest {

    protected static final String TEST_CONFIDENTIAL_CLIENT_ID = "dpop-confidential-client";
    protected static final String TEST_CONFIDENTIAL_CLIENT_SECRET = "password";
    protected static final String TEST_PUBLIC_CLIENT_ID = "dpop-public-client";
    protected static final String TEST_USER_NAME = "test-user@localhost";
    protected static final String TEST_USER_PASSWORD = "password";

    @InjectRealm(config = DPoPRealm.class)
    protected ManagedRealm realm;

    @InjectOAuthClient
    protected OAuthClient oauth;

    @InjectClient(attachTo = TEST_CONFIDENTIAL_CLIENT_ID)
    protected ManagedClient confidentialClient;

    @InjectClient(attachTo = TEST_PUBLIC_CLIENT_ID)
    protected ManagedClient publicClient;

    @InjectEvents
    protected Events events;

    @InjectTimeOffSet
    protected TimeOffSet timeOffSet;

    @InjectKeycloakUrls
    protected KeycloakUrls keycloakUrls;

    @InjectSimpleHttp
    protected SimpleHttp simpleHttp;

    @InjectAdminClientFactory
    protected AdminClientFactory adminClientFactory;

    protected KeyPair ecKeyPair;
    protected KeyPair rsaKeyPair;
    protected JWK jwkRsa;
    protected JWK jwkEc;
    protected JWSHeader jwsRsaHeader;
    protected JWSHeader jwsEcHeader;
    protected String jktRsa;
    protected String jktEc;

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

    protected static JWK createRsaJwk(java.security.Key publicKey) {
        return JWKBuilder.create()
                .rsa(publicKey, KeyUse.SIG);
    }

    protected static JWK createEcJwk(java.security.Key publicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;

        int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
        ECPublicJWK k = new ECPublicJWK();
        k.setKeyType(KeyType.EC);
        k.setCrv("P-" + fieldSize);
        k.setX(Base64Url.encode(toIntegerBytes(ecKey.getW().getAffineX(), fieldSize)));
        k.setY(Base64Url.encode(toIntegerBytes(ecKey.getW().getAffineY(), fieldSize)));

        return k;
    }

    protected static KeyPair generateEcdsaKey(String ecDomainParamName) throws Exception {
        return KeyUtils.generateEcKeyPair(ecDomainParamName);
    }

    protected static String generateSignedDPoPProof(String jti, String htm, String htu, Long iat,
                                                   String algorithm, JWSHeader jwsHeader,
                                                   PrivateKey privateKey, String accessToken) throws IOException {
        return generateSignedDPoPProof(jti, htm, htu, iat, algorithm, jwsHeader, privateKey, accessToken, new DPoPGenerator());
    }

    protected static String generateSignedDPoPProof(String jti, String htm, String htu, Long iat, String algorithm, JWSHeader jwsHeader, PrivateKey privateKey, String accessToken, DPoPGenerator dpopGenerator) throws IOException {
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

    protected void sendAuthorizationRequestWithDPoPJkt(String dpopJkt) {
        oauth.client(TEST_PUBLIC_CLIENT_ID);
        oauth.loginForm().dpopJkt(dpopJkt).doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
    }

    protected AccessTokenResponse successTokenProceduresWithDPoP(String dpopProofEncoded, String jkt, boolean accessTokenBound, boolean refreshTokenBound) throws Exception {
        return successTokenProceduresWithDPoP(dpopProofEncoded, jkt, accessTokenBound, refreshTokenBound, true);
    }

    protected AccessTokenResponse successTokenProceduresWithDPoP(String dpopProofEncoded, String jkt, boolean accessTokenBound,
                                                           boolean refreshTokenBound, boolean performLogout) throws Exception {
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();
        assertEquals(accessTokenBound ? TokenUtil.TOKEN_TYPE_DPOP : TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
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

        assertEquals(jakarta.ws.rs.core.Response.Status.OK.getStatusCode(), response.getStatusCode());
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

    protected void failureTokenProceduresWithDPoP(String dpopProofEncoded, String error) throws Exception {
        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEncoded).send();
        assertEquals(400, response.getStatusCode());
        assertEquals(error, response.getErrorDescription());
        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    // DPoPGenerator with the ability to inject KeyWrapper. Useful for testing purposes of failure scenarios (EG. when different algorithm is used for JWS and for the underlying key etc)
    protected static class TestingDPoPGenerator extends DPoPGenerator {

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
