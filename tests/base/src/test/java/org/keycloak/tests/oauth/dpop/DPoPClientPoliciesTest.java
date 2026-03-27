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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientpolicy.condition.AnyClientConditionFactory;
import org.keycloak.services.clientpolicy.condition.ClientAccessTypeCondition;
import org.keycloak.services.clientpolicy.condition.ClientAccessTypeConditionFactory;
import org.keycloak.services.clientpolicy.executor.DPoPBindEnforcerExecutor;
import org.keycloak.services.clientpolicy.executor.DPoPBindEnforcerExecutorFactory;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ClientPolicyBuilder;
import org.keycloak.testframework.realm.ClientProfileBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testsuite.util.AccountHelper;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.testsuite.util.oauth.IntrospectionResponse;
import org.keycloak.testsuite.util.oauth.UserInfoResponse;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

import org.junit.jupiter.api.Test;

import static org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@KeycloakIntegrationTest
public class DPoPClientPoliciesTest extends BaseDPoPTest {

    @InjectRealm(config = DPoPRealm.class)
    protected ManagedRealm realm;

    @InjectOAuthClient
    protected OAuthClient oauth;

    private ClientRegistration reg;

    @Test
    public void testDPoPBindEnforcerExecutor() throws Exception {
        setInitialAccessTokenForDynamicClientRegistration();

        KeyPair ecKeyPairLocal = generateEcdsaKey("secp256r1");
        KeyPair rsaKeyPairLocal = KeyUtils.generateRsaKeyPair(2048);
        JWK jwkRsaLocal = createRsaJwk(rsaKeyPairLocal.getPublic());
        JWK jwkEcLocal = createEcJwk(ecKeyPairLocal.getPublic());

        // register profiles
        DPoPBindEnforcerExecutor.Configuration dpopConfig =
                new DPoPBindEnforcerExecutor.Configuration();
        dpopConfig.setAutoConfigure(false);
        dpopConfig.setEnforceAuthorizationCodeBindingToDpop(false);
        dpopConfig.setAllowOnlyRefreshTokenBinding(false);

        realm.updateClientProfile(List.of(ClientProfileBuilder.create()
                .name("MyProfile")
                .description("Le Premier Profil")
                .executor(DPoPBindEnforcerExecutorFactory.PROVIDER_ID, dpopConfig)
                .build()));

        // register policies
        ClientAccessTypeCondition.Configuration accessTypeConfig =
                new ClientAccessTypeCondition.Configuration();
        accessTypeConfig.setType(List.of(ClientAccessTypeConditionFactory.TYPE_PUBLIC));

        realm.updateClientPolicy(List.of(ClientPolicyBuilder.create()
                .name("MyPolicy")
                .description("La Primera Plitica")
                .condition(ClientAccessTypeConditionFactory.PROVIDER_ID, accessTypeConfig)
                .profile("MyProfile")
                .build()));

        // register by Admin REST API - fail
        try {
            createClientByAdmin(generateSuffixedName("App-by-Admin"), (ClientRepresentation rep) -> rep.setPublicClient(Boolean.TRUE));
            fail();
        } catch (ClientPolicyException e) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, e.getError());
        }

        // register by Admin REST API - success
        String cAppAdminAlphaId = createClientByAdmin(generateSuffixedName("App-by-Admin-Alpha"), (ClientRepresentation clientRep) -> {
            clientRep.setPublicClient(Boolean.TRUE);
            clientRep.setAttributes(new HashMap<>());
            clientRep.getAttributes().put(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS, Boolean.TRUE.toString());
        });

        // update by Admin REST API - fail
        try {
            updateClientByAdmin(cAppAdminAlphaId, (ClientRepresentation clientRep) -> clientRep.getAttributes().put(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS, Boolean.FALSE.toString()));
        } catch (ClientPolicyException cpe) {
            assertEquals(OAuthErrorException.INVALID_CLIENT_METADATA, cpe.getError());
        }
        ClientRepresentation cRep = getClientByAdmin(cAppAdminAlphaId);
        assertEquals(Boolean.TRUE.toString(), cRep.getAttributes().get(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS));
        String appAlphaClientId = cRep.getClientId();

        dpopConfig = new DPoPBindEnforcerExecutor.Configuration();
        dpopConfig.setAutoConfigure(true);
        dpopConfig.setEnforceAuthorizationCodeBindingToDpop(false);
        dpopConfig.setAllowOnlyRefreshTokenBinding(false);

        realm.updateClientProfile(List.of(ClientProfileBuilder.create()
                .name("MyProfile")
                .description("Le Premier Profil")
                .executor(DPoPBindEnforcerExecutorFactory.PROVIDER_ID, dpopConfig)
                .build()));

        // register by Dynamic Client Registration - success
        String cAppDynamicBetaId = createClientDynamically(generateSuffixedName("App-in-Dynamic-Beta"), (OIDCClientRepresentation clientRep) -> {
            clientRep.setTokenEndpointAuthMethod("none");
            clientRep.setDpopBoundAccessTokens(Boolean.FALSE);
        });
        EventAssertion.assertSuccess(events.poll()).type(EventType.CLIENT_REGISTER).clientId(cAppDynamicBetaId);
        OIDCClientRepresentation oidcClientRep = getClientDynamically(cAppDynamicBetaId);
        assertEquals(Boolean.TRUE, oidcClientRep.getDpopBoundAccessTokens());

        // token request without a DPoP proof - fail
        oauth.client(appAlphaClientId);
        oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
        String code = oauth.parseLoginResponse().getCode();

        AccessTokenResponse response = oauth.doAccessTokenRequest(code);
        assertEquals(400, response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("DPoP proof is missing", response.getErrorDescription());

        // token request with a valid DPoP proof - success
        // EC key for client alpha
        oauth.openLoginForm();
        code = oauth.parseLoginResponse().getCode();

        JWSHeader jwsEcHeaderLocal = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, DPOP_JWT_HEADER_TYPE, jwkEcLocal.getKeyId(), jwkEcLocal);
        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeaderLocal, ecKeyPairLocal.getPrivate(), null);
        response = oauth.accessTokenRequest(code).dpopProof(dpopProofEcEncoded).send();

        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        String encodedAccessToken = response.getAccessToken();
        String encodedRefreshToken = response.getRefreshToken();
        String encodedIdToken = response.getIdToken();
        AccessToken accessToken = oauth.verifyToken(encodedAccessToken);
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.CRV, ((ECPublicJWK) jwkEcLocal).getCrv());
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.X, ((ECPublicJWK) jwkEcLocal).getX());
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.Y, ((ECPublicJWK) jwkEcLocal).getY());
        String jkt = JWKSUtils.computeThumbprint(jwkEcLocal);
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());
        RefreshToken refreshToken = oauth.parseRefreshToken(encodedRefreshToken);
        assertEquals(jkt, refreshToken.getConfirmation().getKeyThumbprint());

        // userinfo request without a DPoP proof - fail
        UserInfoResponse userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(null).send();
        assertEquals(401, userInfoResponse.getStatusCode());

        // userinfo request with a valid DPoP proof - success
        jwsEcHeaderLocal = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, DPOP_JWT_HEADER_TYPE, jwkEcLocal.getKeyId(), jwkEcLocal);
        dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.GET, oauth.getEndpoints().getUserInfo(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeaderLocal, ecKeyPairLocal.getPrivate(), response.getAccessToken());
        userInfoResponse = oauth.userInfoRequest(response.getAccessToken()).dpop(dpopProofEcEncoded).send();
        assertEquals(200, userInfoResponse.getStatusCode());
        assertEquals(TEST_USER_NAME, userInfoResponse.getUserInfo().getPreferredUsername());

        // token refresh without a DPoP Proof - fail
        response = oauth.doRefreshTokenRequest(encodedRefreshToken);
        assertEquals(400, response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("DPoP proof is missing", response.getErrorDescription());

        // token refresh with a valid DPoP Proof - success
        dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeaderLocal, ecKeyPairLocal.getPrivate(), response.getIdToken());
        response = oauth.refreshRequest(encodedRefreshToken).dpopProof(dpopProofEcEncoded).send();
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
        encodedAccessToken = response.getAccessToken();
        encodedRefreshToken = response.getRefreshToken();
        accessToken = oauth.verifyToken(encodedAccessToken);
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.CRV, ((ECPublicJWK) jwkEcLocal).getCrv());
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.X, ((ECPublicJWK) jwkEcLocal).getX());
        jwkEcLocal.getOtherClaims().put(ECPublicJWK.Y, ((ECPublicJWK) jwkEcLocal).getY());
        jkt = JWKSUtils.computeThumbprint(jwkEcLocal);
        assertEquals(jkt, accessToken.getConfirmation().getKeyThumbprint());
        refreshToken = oauth.parseRefreshToken(encodedRefreshToken);
        assertEquals(jkt, refreshToken.getConfirmation().getKeyThumbprint());

        // revoke token without a valid DPoP proof - fail
        JWSHeader jwsRsaHeaderLocal = new JWSHeader(org.keycloak.jose.jws.Algorithm.PS256, DPOP_JWT_HEADER_TYPE, jwkRsaLocal.getKeyId(), jwkRsaLocal);
        String dpopProofRsaEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getRevocation(), (long) Time.currentTime(), Algorithm.PS256, jwsRsaHeaderLocal, rsaKeyPairLocal.getPrivate(), response.getAccessToken());
        assertEquals(400, oauth.tokenRevocationRequest(encodedAccessToken).accessToken().dpopProof(dpopProofRsaEncoded).send().getStatusCode());

        // revoke token with a valid DPoP proof - success
        dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getRevocation(), (long) Time.currentTime(), Algorithm.ES256, jwsEcHeaderLocal, ecKeyPairLocal.getPrivate(), response.getAccessToken());
        assertTrue(oauth.tokenRevocationRequest(encodedAccessToken).accessToken().dpopProof(dpopProofEcEncoded).send().isSuccess());
        IntrospectionResponse introspectionResponse = oauth.doIntrospectionAccessTokenRequest(encodedAccessToken);
        assertFalse(introspectionResponse.isSuccess());
        assertEquals("Client not allowed.", introspectionResponse.getErrorDescription());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testDPoPBindEnforcerExecutorWithEnforcedAuthzCodeBinding() throws Exception {
        // register profiles
        DPoPBindEnforcerExecutor.Configuration dpopConfig =
                new DPoPBindEnforcerExecutor.Configuration();
        dpopConfig.setAutoConfigure(false);
        dpopConfig.setEnforceAuthorizationCodeBindingToDpop(true);
        dpopConfig.setAllowOnlyRefreshTokenBinding(false);

        realm.updateClientProfile(List.of(ClientProfileBuilder.create()
                .name("dpop-authz-profile")
                .description("DPoP with AuthZ Code Binding")
                .executor(DPoPBindEnforcerExecutorFactory.PROVIDER_ID, dpopConfig)
                .build()));

        // register policies
        ClientAccessTypeCondition.Configuration accessTypeConfig =
                new ClientAccessTypeCondition.Configuration();
        accessTypeConfig.setType(List.of(ClientAccessTypeConditionFactory.TYPE_PUBLIC));

        realm.updateClientPolicy(List.of(ClientPolicyBuilder.create()
                .name("dpop-authz-policy")
                .description("DPoP Policy with AuthZ Binding")
                .condition(ClientAccessTypeConditionFactory.PROVIDER_ID, accessTypeConfig)
                .profile("dpop-authz-profile")
                .build()));

        // Login without dpop_jkt - failure
        oauth.client(TEST_PUBLIC_CLIENT_ID);
        oauth.openLoginForm();
        AuthorizationEndpointResponse authResponse = oauth.parseLoginResponse();
        assertEquals(OAuthErrorException.INVALID_REQUEST, authResponse.getError());
        assertEquals("Missing parameter: dpop_jkt", authResponse.getErrorDescription());
        EventAssertion.assertError(events.poll())
                .type(EventType.LOGIN_ERROR)
                .error(OAuthErrorException.INVALID_REQUEST)
                .clientId(TEST_PUBLIC_CLIENT_ID)
                .details(Details.CLIENT_POLICY_ERROR, OAuthErrorException.INVALID_REQUEST);

        // Login with dpop_jkt -- should be OK
        long clockSkew = 10;
        sendAuthorizationRequestWithDPoPJkt(jktEc);
        String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);

        String code = oauth.parseLoginResponse().getCode();
        AccessTokenResponse response = oauth.accessTokenRequest(code).dpopProof(dpopProofEcEncoded).send();
        assertEquals(Status.OK.getStatusCode(), response.getStatusCode());

        AccountHelper.logout(realm.admin(), TEST_USER_NAME);
    }

    @Test
    public void testBindOnlyRefreshTokenDPoPEnforcerExecutor() throws Exception {
        publicClient.update(c -> c.dpop(false));
        confidentialClient.update(c -> c.dpop(false));

        try {
            // register profiles
            DPoPBindEnforcerExecutor.Configuration dpopConfig =
                    new DPoPBindEnforcerExecutor.Configuration();
            dpopConfig.setAutoConfigure(false);
            dpopConfig.setEnforceAuthorizationCodeBindingToDpop(false);
            dpopConfig.setAllowOnlyRefreshTokenBinding(true);

            realm.updateClientProfile(List.of(ClientProfileBuilder.create()
                    .name("dpop-refresh-profile")
                    .description("DPoP Refresh Token Only")
                    .executor(DPoPBindEnforcerExecutorFactory.PROVIDER_ID, dpopConfig)
                    .build()));

            // register policies
            realm.updateClientPolicy(List.of(ClientPolicyBuilder.create()
                    .name("dpop-refresh-policy")
                    .description("DPoP Refresh Policy")
                    .condition(AnyClientConditionFactory.PROVIDER_ID, null)
                    .profile("dpop-refresh-profile")
                    .build()));

            int clockSkew = 10;

            // public client without proof - should fail
            sendAuthorizationRequestWithDPoPJkt(null);
            failureTokenProceduresWithDPoP(null, "DPoP proof is missing");

            // public client with proof - should succeed
            sendAuthorizationRequestWithDPoPJkt(null);
            String dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);
            successTokenProceduresWithDPoP(dpopProofEcEncoded, jktEc, false, true);

            // confidential client without proof
            oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
            oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
            successTokenProceduresWithDPoP(null, jktEc, false, false);

            // confidential client with proof
            oauth.client(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET);
            oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
            dpopProofEcEncoded = generateSignedDPoPProof(UUID.randomUUID().toString(), HttpMethod.POST, oauth.getEndpoints().getToken(), (long) (Time.currentTime() + clockSkew), Algorithm.ES256, jwsEcHeader, ecKeyPair.getPrivate(), null);
            successTokenProceduresWithDPoP(dpopProofEcEncoded, jktEc, true, false);
        } finally {
            publicClient.update(c -> c.dpop(true));
            confidentialClient.update(c -> c.dpop(true));
        }
    }

    private void setInitialAccessTokenForDynamicClientRegistration() {
        // get initial access token for Dynamic Client Registration with authentication
        reg = oauth.clientRegistration();
        ClientInitialAccessPresentation token = realm.admin().clientInitialAccess().create(new ClientInitialAccessCreatePresentation(0, 10));
        reg.auth(Auth.token(token));
    }

    private String createClientDynamically(String clientName, java.util.function.Consumer<OIDCClientRepresentation> op) throws Exception {
        OIDCClientRepresentation clientRep = new OIDCClientRepresentation();
        clientRep.setClientName(clientName);
        clientRep.setClientUri(realm.getBaseUrl());
        clientRep.setRedirectUris(List.of(realm.getBaseUrl() + "/app/auth"));
        op.accept(clientRep);
        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        reg.auth(Auth.token(response));
        return response.getClientId();
    }

    private OIDCClientRepresentation getClientDynamically(String clientId) throws Exception {
        return reg.oidc().get(clientId);
    }

    private String generateSuffixedName(String name) {
        return name + "-" + UUID.randomUUID().toString().substring(0, 7);
    }

    private String createClientByAdmin(String clientName, java.util.function.Consumer<ClientRepresentation> op) throws ClientPolicyException {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(clientName);
        clientRep.setName(clientName);
        clientRep.setProtocol("openid-connect");
        clientRep.setBearerOnly(Boolean.FALSE);
        clientRep.setPublicClient(Boolean.FALSE);
        clientRep.setServiceAccountsEnabled(Boolean.TRUE);
        clientRep.setRedirectUris(Collections.singletonList("*"));
        clientRep.setWebOrigins(Collections.singletonList("*"));
        OIDCAdvancedConfigWrapper.fromClientRepresentation(clientRep).setPostLogoutRedirectUris(Collections.singletonList("+"));
        op.accept(clientRep);
        Response resp = realm.admin().clients().create(clientRep);
        if (resp.getStatus() == Response.Status.BAD_REQUEST.getStatusCode()) {
            String respBody = resp.readEntity(String.class);
            Map<String, String> responseJson;
            try {
                responseJson = JsonSerialization.readValue(respBody, Map.class);
            } catch (IOException e) {
                fail("Failed to parse error response");
                throw new RuntimeException(e);
            }
            throw new ClientPolicyException(responseJson.get(OAuth2Constants.ERROR), responseJson.get(OAuth2Constants.ERROR_DESCRIPTION));
        }
        assertEquals(Response.Status.CREATED.getStatusCode(), resp.getStatus());
        String location = resp.getHeaderString("Location");
        String cId = location.substring(location.lastIndexOf('/') + 1);
        resp.close();
        return cId;
    }

    private void updateClientByAdmin(String cId, java.util.function.Consumer<ClientRepresentation> op) throws ClientPolicyException {
        ClientResource clientResource = realm.admin().clients().get(cId);
        ClientRepresentation clientRep = clientResource.toRepresentation();
        op.accept(clientRep);
        try {
            clientResource.update(clientRep);
        } catch (BadRequestException bre) {
            processClientPolicyExceptionByAdmin(bre);
        }
    }

    private void processClientPolicyExceptionByAdmin(BadRequestException bre) throws ClientPolicyException {
        Response resp = bre.getResponse();
        if (resp.getStatus() != Response.Status.BAD_REQUEST.getStatusCode()) {
            resp.close();
            return;
        }

        String respBody = resp.readEntity(String.class);
        Map<String, String> responseJson;
        try {
            responseJson = JsonSerialization.readValue(respBody, Map.class);
        } catch (IOException e) {
            fail("Failed to parse error response");
            throw new RuntimeException(e);
        }
        throw new ClientPolicyException(responseJson.get(OAuth2Constants.ERROR), responseJson.get(OAuth2Constants.ERROR_DESCRIPTION));
    }

    private ClientRepresentation getClientByAdmin(String cId) throws ClientPolicyException {
        ClientResource clientResource = realm.admin().clients().get(cId);
        try {
            return clientResource.toRepresentation();
        } catch (BadRequestException bre) {
            processClientPolicyExceptionByAdmin(bre);
        }
        return null;
    }

    // Exception class for client policy errors
    private static class ClientPolicyException extends Exception {
        private final String error;

        public ClientPolicyException(String error, String errorDescription) {
            super(errorDescription);
            this.error = error;
        }

        public String getError() {
            return error;
        }
    }
}
