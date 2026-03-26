/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.tests.oauth.tokenexchange;

import java.util.List;

import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.encode.AccessTokenContext;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.util.ApiUtil;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.TokenExchangeRequest;
import org.keycloak.testsuite.util.oauth.TokenRevocationResponse;
import org.keycloak.util.TokenUtil;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;


@KeycloakIntegrationTest
public class StandardTokenExchangeV2Test extends BaseAbstractTokenExchangeTest {

    @Test
    public void testRealmConfiguration() {
        // Verify users exist
        UserRepresentation alice = realm.admin().users().search("alice").get(0);
        assertNotNull(alice);
        assertEquals("Alice", alice.getFirstName());
        assertEquals("Doe", alice.getLastName());
        assertEquals("alice@email.cz", alice.getEmail());

        UserRepresentation mike = realm.admin().users().search("mike").get(0);
        assertNotNull(mike);
        assertEquals("Mike", mike.getFirstName());
        assertEquals("Bar", mike.getLastName());
        assertEquals("mike@email.cz", mike.getEmail());

        assertNotNull(john);
        assertEquals("John", john.getFirstName());
        assertEquals("Bar", john.getLastName());
        assertEquals("john@email.cz", john.getEmail());

        // Verify john has correct client roles
        UserResource johnResource = realm.admin().users().get(john.getId());
        List<RoleRepresentation> johnTargetClient1Roles = johnResource.roles().clientLevel(
                realm.admin().clients().findByClientId("target-client1").get(0).getId()).listEffective();
        assertEquals(1, johnTargetClient1Roles.stream().filter(r -> r.getName().equals("target-client1-role")).count());

        List<RoleRepresentation> johnTargetClient2Roles = johnResource.roles().clientLevel(
                realm.admin().clients().findByClientId("target-client2").get(0).getId()).listEffective();
        assertEquals(1, johnTargetClient2Roles.stream().filter(r -> r.getName().equals("target-client2-role")).count());

        // Verify alice has correct client roles
        UserResource aliceResource = realm.admin().users().get(alice.getId());
        List<RoleRepresentation> aliceRequesterRoles = aliceResource.roles().clientLevel(
                realm.admin().clients().findByClientId("requester-client").get(0).getId()).listEffective();
        assertEquals(1, aliceRequesterRoles.stream().filter(r -> r.getName().equals("requester-client-role")).count());

        List<RoleRepresentation> aliceRequester2Roles = aliceResource.roles().clientLevel(
                realm.admin().clients().findByClientId("requester-client-2").get(0).getId()).listEffective();
        assertEquals(1, aliceRequester2Roles.stream().filter(r -> r.getName().equals("requester-client-2-role")).count());

        // Verify mike has correct realm and client roles
        UserResource mikeResource = realm.admin().users().get(mike.getId());
        List<RoleRepresentation> mikeRealmRoles = mikeResource.roles().realmLevel().listEffective();
        assertEquals(1, mikeRealmRoles.stream().filter(r -> r.getName().equals("all-target")).count());

        List<RoleRepresentation> mikeTargetClient1Roles = mikeResource.roles().clientLevel(
                realm.admin().clients().findByClientId("target-client1").get(0).getId()).listEffective();
        assertEquals(1, mikeTargetClient1Roles.stream().filter(r -> r.getName().equals("target-client1-role")).count());
    }

    @Test
    public void testSubjectTokenType() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();

        TokenExchangeRequest request = oauth.tokenExchangeRequest(accessToken, OAuth2Constants.ACCESS_TOKEN_TYPE);
        AccessTokenResponse response = request.send();
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());

        request = oauth.tokenExchangeRequest(accessToken, OAuth2Constants.REFRESH_TOKEN_TYPE);
        response = request.send();
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());

        request = oauth.tokenExchangeRequest(accessToken, OAuth2Constants.ID_TOKEN_TYPE);
        response = request.send();
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());

        request = oauth.tokenExchangeRequest(accessToken, OAuth2Constants.SAML2_TOKEN_TYPE);
        response = request.send();
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());

        request = oauth.tokenExchangeRequest(accessToken, OAuth2Constants.JWT_TOKEN_TYPE);
        response = request.send();
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());

        request = oauth.tokenExchangeRequest(accessToken, "WRONG_TOKEN_TYPE");
        response = request.send();
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
    }

    @Test
    public void testRequestedTokenType() throws Exception {
        String accessToken = resourceOwnerLogin(john.getUsername(), "password", "subject-client", "secret").getAccessToken();

        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ACCESS_TOKEN_TYPE);
        assertAudiencesAndScopes(response, john, List.of("target-client1"), List.of("default-scope1"));
        assertNotNull(response.getAccessToken());
        assertEquals(TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());

        requesterClient.update(c-> c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name()));

        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("requested_token_type unsupported", response.getErrorDescription());
        EventRepresentation event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(john.getId())
                .details(Details.REASON, "requested_token_type unsupported")
                .details(Details.REQUESTED_TOKEN_TYPE, OAuth2Constants.REFRESH_TOKEN_TYPE)
                .details(Details.SUBJECT_TOKEN_CLIENT_ID, "subject-client");
        assertNotNull(event.getSessionId());

     //   realm.admin().clients().findByClientId("requester-client").getFirst().getAttributes()
        requesterClient.update(c-> c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name()));

        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
        assertAudiencesAndScopes(response, john, List.of("target-client1"), List.of("default-scope1"), OAuth2Constants.REFRESH_TOKEN_TYPE, "subject-client");
        assertNotNull(response.getAccessToken());
        assertEquals(TokenUtil.TOKEN_TYPE_BEARER, response.getTokenType());
        assertEquals(OAuth2Constants.REFRESH_TOKEN_TYPE, response.getIssuedTokenType());

        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ID_TOKEN_TYPE);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
        assertNotNull(response.getAccessToken());
        assertEquals(TokenUtil.TOKEN_TYPE_NA, response.getTokenType());
        assertEquals(OAuth2Constants.ID_TOKEN_TYPE, response.getIssuedTokenType());
        event = events.poll();
        EventAssertion.assertSuccess(event)
                .type(EventType.TOKEN_EXCHANGE)
                .clientId("requester-client")
                .userId(john.getId())
                .details(Details.REQUESTED_TOKEN_TYPE, OAuth2Constants.ID_TOKEN_TYPE)
                .details(Details.SUBJECT_TOKEN_CLIENT_ID, "subject-client");
        assertNotNull(event.getSessionId());

        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.JWT_TOKEN_TYPE);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("requested_token_type unsupported", response.getErrorDescription());
        event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(john.getId())
                .details(Details.REASON, "requested_token_type unsupported")
                .details(Details.REQUESTED_TOKEN_TYPE, OAuth2Constants.JWT_TOKEN_TYPE)
                .details(Details.SUBJECT_TOKEN_CLIENT_ID, "subject-client");
        assertNotNull(event.getSessionId());

        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.SAML2_TOKEN_TYPE);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("requested_token_type unsupported", response.getErrorDescription());
        event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(john.getId())
                .details(Details.REASON, "requested_token_type unsupported")
                .details(Details.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE)
                .details(Details.SUBJECT_TOKEN_CLIENT_ID, "subject-client");
        assertNotNull(event.getSessionId());

        response = tokenExchange(accessToken, "requester-client", "secret", null, "WRONG_TOKEN_TYPE");
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("requested_token_type unsupported", response.getErrorDescription());
        event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(john.getId())
                .details(Details.REASON, "requested_token_type unsupported")
                .details(Details.REQUESTED_TOKEN_TYPE, "WRONG_TOKEN_TYPE")
                .details(Details.SUBJECT_TOKEN_CLIENT_ID, "subject-client");
        assertNotNull(event.getSessionId());

        requesterClient.update(c-> c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name()));
    }

    @Test
    public void testExchange() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();

        // Test successful exchange
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, null);
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        AccessToken exchangedToken = verifier.parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());

        EventRepresentation event = events.poll();
        EventAssertion.assertSuccess(event)
                .type(EventType.TOKEN_EXCHANGE)
                .clientId(exchangedToken.getIssuedFor())
                .userId(john.getId())
                .sessionId(exchangedToken.getSessionId())
                .details(Details.USERNAME, john.getUsername());

        // Test exchange not allowed - invalid client is not in the subject-client audience
        response = tokenExchange(accessToken, "invalid-requester-client", "secret", null, null);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatusCode());

        event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("invalid-requester-client")
                .error(Errors.NOT_ALLOWED)
                .userId(john.getId())
                .details(Details.REASON, "client is not within the token audience");
        assertNotNull(event.getSessionId());
    }

    @Test
    public void testTransientSessionForRequester() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();

        oauth.scope(OAuth2Constants.SCOPE_OPENID); // add openid scope for the user-info request
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, null);
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        AccessToken exchangedToken = TokenVerifier.create(exchangedTokenString, AccessToken.class).parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());
        assertAccessTokenContext(exchangedToken.getId(), AccessTokenContext.SessionType.ONLINE_TRANSIENT_CLIENT,
                AccessTokenContext.TokenType.REGULAR, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE);

        // assert introspection and user-info works
        assertIntrospectSuccess(exchangedTokenString, "requester-client", "secret", john.getId());
        assertUserInfoSuccess(exchangedTokenString, "requester-client", "secret", john.getId());

        // assert introspection and user-info works in 10s
        timeOffSet.set(10);
        assertIntrospectSuccess(exchangedTokenString, "requester-client", "secret", john.getId());
        assertUserInfoSuccess(exchangedTokenString, "requester-client", "secret", john.getId());

        // assert introspection and user-info fails with session deleted
        realm.admin().deleteSession(exchangedToken.getSessionId(), false);
        assertIntrospectError(exchangedTokenString, "requester-client", "secret");
        assertUserInfoError(exchangedTokenString, "requester-client", "secret", "invalid_token", Errors.USER_SESSION_NOT_FOUND);
    }

    @Test
    public void testExchangeRequestAccessTokenType() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ACCESS_TOKEN_TYPE);
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        AccessToken exchangedToken = verifier.parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());
    }

    @Test
    public void testExchangeForIdToken() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();

        // Exchange request with "scope=oidc" . ID Token should be issued in addition to access-token
        oauth.openid(true);
        oauth.scope(OAuth2Constants.SCOPE_OPENID);
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ACCESS_TOKEN_TYPE);
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        AccessToken exchangedToken = TokenVerifier.create(response.getAccessToken(), AccessToken.class)
                .parse().getToken();
        assertEquals(TokenUtil.TOKEN_TYPE_BEARER, exchangedToken.getType());

        IDToken exchangedIdToken = TokenVerifier.create(response.getIdToken(), IDToken.class)
                .parse().getToken();
        assertEquals(TokenUtil.TOKEN_TYPE_ID, exchangedIdToken.getType());
        assertEquals(getSessionIdFromToken(accessToken), exchangedIdToken.getSessionId());
        assertEquals("requester-client", exchangedIdToken.getIssuedFor());

        // Exchange request without "scope=oidc" . Only access-token should be issued, but not ID Token
        oauth.openid(false);
        oauth.scope(null);
        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ACCESS_TOKEN_TYPE);
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        assertNotNull(response.getAccessToken());
        assertNull(response.getIdToken(), "ID Token was present, but should not be present");

        // Exchange request requesting id-token. ID Token should be issued inside "access_token" parameter (as per token-exchange specification https://datatracker.ietf.org/doc/html/rfc8693#name-successful-response - parameter "access_token")
        response = tokenExchange(accessToken, "requester-client", "secret", null, OAuth2Constants.ID_TOKEN_TYPE);
        assertEquals(OAuth2Constants.ID_TOKEN_TYPE, response.getIssuedTokenType());
        assertEquals(TokenUtil.TOKEN_TYPE_NA, response.getTokenType());
        assertNotNull(response.getAccessToken());
        assertNull(response.getIdToken(), "ID Token was present, but should not be present");

        exchangedIdToken = TokenVerifier.create(response.getAccessToken(), IDToken.class)
                .parse().getToken();
        assertEquals(TokenUtil.TOKEN_TYPE_ID, exchangedIdToken.getType());
        assertEquals(getSessionIdFromToken(accessToken), exchangedIdToken.getSessionId());
        assertEquals("requester-client", exchangedIdToken.getIssuedFor());

    }

    @Test
    public void testExchangeUsingServiceAccount() throws Exception {
        final UserRepresentation user = subjectClient.admin().getServiceAccountUser();

        oauth.client("subject-client", "secret");

        AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest();
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        assertNull(token.getSessionId());

        EventRepresentation event = events.poll();
        EventAssertion.assertSuccess(event)
                .type(EventType.CLIENT_LOGIN)
                .clientId("subject-client")
                .userId(user.getId())
                .sessionId(token.getSessionId())
                .details(Details.USERNAME, user.getUsername())
                .details(Details.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS);

        response = tokenExchange(accessToken, "requester-client", "secret", null, null);
        assertAudiencesAndScopes(response, user, List.of("target-client1"), List.of("default-scope1"));
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        AccessToken exchangedToken = verifier.parse().getToken();
        assertNull(exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());

        requesterClient.update(c-> c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name()));

        response = tokenExchange(accessToken, "requester-client", "secret", null,
                OAuth2Constants.REFRESH_TOKEN_TYPE);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(Errors.INVALID_REQUEST, response.getError());
        assertEquals("Refresh token not valid as requested_token_type because creating a new session is needed", response.getErrorDescription());

        event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(user.getId())
                .details(Details.REASON, "Refresh token not valid as requested_token_type because creating a new session is needed");

        requesterClient.update(c-> c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name()));
    }

    @Test
    public void testExchangeNoRefreshToken() throws Exception {

        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();
        {
            AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, null);
            assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
            String exchangedTokenString = response.getAccessToken();
            String refreshTokenString = response.getRefreshToken();
            assertNotNull(exchangedTokenString);
            assertNull(refreshTokenString);
        }
        requesterClient.update(c-> c
                .attribute(OIDCConfigAttributes.USE_REFRESH_TOKEN, Boolean.FALSE.toString())
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name()));

        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null,
                OAuth2Constants.REFRESH_TOKEN_TYPE);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("requested_token_type unsupported", response.getErrorDescription());

        requesterClient.update(c-> c
                .attribute(OIDCConfigAttributes.USE_REFRESH_TOKEN, Boolean.TRUE.toString())
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name()));
    }

    @Test
    public void testClientExchangeToItself() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();

        AccessTokenResponse response = tokenExchange(accessToken, "subject-client", "secret", null, null);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());

        response = tokenExchange(accessToken, "subject-client", "secret", List.of("subject-client"), null);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
    }

    @Test
    public void testClientExchangeToItselfWithConsents() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();

        subjectClient.update(c-> c.consentRequired(Boolean.TRUE));
        AccessTokenResponse response = tokenExchange(accessToken, "subject-client", "secret", null, null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
        assertEquals("Missing consents for Token Exchange in client subject-client", response.getErrorDescription());

        response = tokenExchange(accessToken, "subject-client", "secret", List.of("subject-client"), null);
        assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
        assertEquals("Missing consents for Token Exchange in client subject-client", response.getErrorDescription());
        subjectClient.update(c-> c.consentRequired(Boolean.FALSE));
    }

    @Test
    public void testExchangeWithPublicClient() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client-public", null,  null, null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_CLIENT, response.getError());
        assertEquals("Public client is not allowed to exchange token", response.getErrorDescription());
    }

    @Test
    public void testOptionalScopeParamRequestedWithoutAudience() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();
        oauth.scope("optional-scope2");
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", null, null);
        assertAudiencesAndScopes(response, john, List.of("target-client1", "target-client2"), List.of("default-scope1", "optional-scope2"));
    }

    @Test
    public void testAudienceRequested() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), null);
        assertAudiencesAndScopes(response, john, List.of("target-client1"), List.of("default-scope1"));
    }

    @Test
    public void testUnavailableAudienceRequested() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password","subject-client", "secret").getAccessToken();
        // request invalid client audience
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1", "invalid-client"), null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_CLIENT, response.getError());
        assertEquals("Audience not found", response.getErrorDescription());
        // The "target-client3" is valid client, but audience unavailable to the user. Request not allowed
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1", "target-client3"), null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("Requested audience not available: target-client3", response.getErrorDescription());
    }

    @Test
    public void testScopeNotAllowed() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();

        //scope not allowed
        oauth.scope("optional-scope3");
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1", "target-client3"), null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
        assertEquals("Invalid scopes: optional-scope3", response.getErrorDescription());

        //scope that doesn't exist
        oauth.scope("bad-scope");
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1", "target-client3"), null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
        assertEquals("Invalid scopes: bad-scope", response.getErrorDescription());
    }

    @Test
    public void testScopeFilter() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client2"), null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("Requested audience not available: target-client2", response.getErrorDescription());

        EventRepresentation event = events.poll();
        EventAssertion.assertError(event)
                .type(EventType.TOKEN_EXCHANGE_ERROR)
                .clientId("requester-client")
                .error(Errors.INVALID_REQUEST)
                .userId(john.getId())
                .details(Details.REASON, "Requested audience not available: target-client2");
        assertNotNull(event.getSessionId());

        oauth.scope("optional-scope2");
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1"), null);
        assertAudiencesAndScopes(response, john, List.of("target-client1"), List.of("default-scope1"));

        oauth.scope("optional-scope2");
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client2"), null);
        assertAudiencesAndScopes(response, john, List.of("target-client2"), List.of("optional-scope2"));

        oauth.scope("optional-scope2");
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1", "target-client2"), null);
        assertAudiencesAndScopes(response, john, List.of("target-client1", "target-client2"), List.of("default-scope1", "optional-scope2"));

        //just check that the exchanged token contains the optional-scope2 mapped by the realm role
        accessToken = resourceOwnerLogin("mike", "password","subject-client", "secret").getAccessToken();
        oauth.scope("optional-scope2");
        response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
        assertAudiencesAndScopes(response, mike, List.of("target-client1"), List.of("default-scope1", "optional-scope2"));

        accessToken = resourceOwnerLogin("mike", "password","subject-client", "secret").getAccessToken();
        oauth.scope("optional-scope2");
        response = tokenExchange(accessToken, "requester-client", "secret",  List.of("target-client1"), null);
        assertAudiencesAndScopes(response,  mike, List.of("target-client1"), List.of("default-scope1", "optional-scope2"));
    }

    @Test
    public void testScopeParamIncludedAudienceIncludedRefreshToken() throws Exception {
        requesterClient.update(client -> client
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name())
        );

        String accessToken = resourceOwnerLogin("mike", "password", "subject-client", "secret").getAccessToken();
        oauth.scope("optional-scope2");
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), OAuth2Constants.REFRESH_TOKEN_TYPE);
        assertAudiencesAndScopes(response, mike, List.of("target-client1"), List.of("default-scope1", "optional-scope2"), OAuth2Constants.REFRESH_TOKEN_TYPE, "subject-client");
        assertNotNull(response.getRefreshToken());

        oauth.client("requester-client", "secret");
        response = oauth.doRefreshTokenRequest(response.getRefreshToken());
        AccessToken exchangedToken = assertAudiencesAndScopes(response, List.of("target-client1"), List.of("default-scope1", "optional-scope2"));
        EventRepresentation event = events.poll();
        EventAssertion.assertSuccess(event)
                .type(EventType.REFRESH_TOKEN)
                .details(Details.TOKEN_ID, exchangedToken.getId())
                .details(Details.REFRESH_TOKEN_TYPE, TokenUtil.TOKEN_TYPE_REFRESH)
                .sessionId(exchangedToken.getSessionId());

        oauth.client("requester-client", "secret");
        response = oauth.doRefreshTokenRequest(response.getRefreshToken());
        exchangedToken = assertAudiencesAndScopes(response, List.of("target-client1"), List.of("default-scope1", "optional-scope2"));
        event = events.poll();
        EventAssertion.assertSuccess(event)
                .type(EventType.REFRESH_TOKEN)
                .details(Details.TOKEN_ID, exchangedToken.getId())
                .details(Details.REFRESH_TOKEN_TYPE, TokenUtil.TOKEN_TYPE_REFRESH)
                .sessionId(exchangedToken.getSessionId());

        requesterClient.update(client -> client
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name())
        );
    }

    // TODO: Requires TestingClient support for feature flags
    // @Test
    // public void testExchangeWithDynamicScopesEnabled() throws Exception {
    //     testingClient.enableFeature(Profile.Feature.DYNAMIC_SCOPES);
    //     testExchange();
    //     testingClient.disableFeature(Profile.Feature.DYNAMIC_SCOPES);
    // }

    @Test
    public void testExchangeDisabledOnClient() throws Exception {
        String accessToken = resourceOwnerLogin("john", "password", "subject-client", "secret").getAccessToken();
        AccessTokenResponse response = tokenExchange(accessToken, "disabled-requester-client", "secret", null, null);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
        assertEquals("Standard token exchange is not enabled for the requested client", response.getErrorDescription());
    }

    @Test
    public void testConsents() throws Exception {
        requesterClient.update(client -> client.consentRequired(true));
        try {
            // initial TE without any consent should fail
            String accessToken = resourceOwnerLogin("mike", "password", "subject-client", "secret").getAccessToken();
            AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
            assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
            assertEquals("Missing consents for Token Exchange in client requester-client", response.getErrorDescription());
            EventAssertion.assertError(events.poll())
                    .type(EventType.TOKEN_EXCHANGE_ERROR)
                    .clientId("requester-client")
                    .error(Errors.CONSENT_DENIED)
                    .userId(mike.getId())
                    .details(Details.REASON, "Missing consents for Token Exchange in client requester-client");

            // logout
            realm.admin().users().get(mike.getId()).logout();

            // perform a login and allow consent for default scopes, TE should work now
            accessToken = loginWithConsents(mike, "password", "requester-client", "secret");
            response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
            assertAudiencesAndScopes(response, mike, List.of("target-client1"), List.of("default-scope1"), OAuth2Constants.ACCESS_TOKEN_TYPE, "requester-client");

            // request TE with optional-scope2 whose consent is missing, should fail
            oauth.scope("optional-scope2");
            response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
            assertEquals(OAuthErrorException.INVALID_SCOPE, response.getError());
            assertEquals("Missing consents for Token Exchange in client requester-client", response.getErrorDescription());
            EventAssertion.assertError(events.poll())
                    .type(EventType.TOKEN_EXCHANGE_ERROR)
                    .clientId("requester-client")
                    .error(Errors.CONSENT_DENIED)
                    .userId(mike.getId())
                    .details(Details.REASON, "Missing consents for Token Exchange in client requester-client");

            // logout
            realm.admin().users().get(mike.getId()).logout();

            // consent the additional scope, TE should work now
            accessToken = loginWithConsents(mike, "password", "requester-client", "secret");
            response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
            assertAudiencesAndScopes(response, mike, List.of("target-client1"), List.of("default-scope1", "optional-scope2"),
                    OAuth2Constants.ACCESS_TOKEN_TYPE, "requester-client");
        } finally {
            requesterClient.update(client -> client.consentRequired(false));
        }
    }

     @Test
     public void testOfflineAccessNotAllowed() throws Exception {
         requesterClient.update(client -> client
                 .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name())
         );
         try {
             String accessToken = resourceOwnerLogin("mike", "password", "subject-client", "secret").getAccessToken();
             String sessionId = TokenVerifier.create(accessToken, AccessToken.class).parse().getToken().getSessionId();
             assertEquals(getClientSessionsCountInUserSession(sessionId), Integer.valueOf(1));

             oauth.scope("offline_access");
             AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), OAuth2Constants.REFRESH_TOKEN_TYPE);
             assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
             assertEquals(OAuthErrorException.INVALID_REQUEST, response.getError());
             assertEquals("Scope offline_access not allowed for token exchange", response.getErrorDescription());

             // Check that client session was not created
             assertEquals(getClientSessionsCountInUserSession(sessionId), Integer.valueOf(1));
         } finally {
             requesterClient.update(client -> client
                     .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name())
             );
         }
     }

     @Test
     public void testOfflineAccessLoginWithRegularTokenExchange() throws Exception {
         requesterClient.update(client -> client
                 .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name())
         );
         subjectClient.update(client -> client
                 .optionalClientScopes(OAuth2Constants.OFFLINE_ACCESS)
         );
         try {
             // Login with "scope=offline_access" . Will create offline user-session
             String accessToken = resourceOwnerLogin("mike", "password", "subject-client", "secret", OAuth2Constants.OFFLINE_ACCESS).getAccessToken();
             TokenVerifier<AccessToken> verifier = TokenVerifier.create(accessToken, AccessToken.class);
             AccessToken originalToken = verifier.parse().getToken();

             AccessTokenContext ctx = getAccessTokenContext(originalToken.getId());
             assertEquals(AccessTokenContext.SessionType.OFFLINE, ctx.getSessionType());

             // normal access token exchange is allowed for the offline session
             oauth.scope(null);
             AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), null);
             AccessToken exchangedToken = assertAudiencesAndScopes(response, mike, List.of("target-client1"), List.of("default-scope1"));
             assertEquals(originalToken.getSessionId(), exchangedToken.getSessionId());

             // Refresh token-exchange without "scope=offline_access". Not allowed cos a new new "online" user session is needed (as previous one was offline)
             oauth.scope(null);
             response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), OAuth2Constants.REFRESH_TOKEN_TYPE);
             assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
             assertEquals(Errors.INVALID_REQUEST, response.getError());
             assertEquals("Refresh token not valid as requested_token_type because creating a new session is needed", response.getErrorDescription());
             EventAssertion.assertError(events.poll())
                     .type(EventType.TOKEN_EXCHANGE_ERROR)
                     .clientId("requester-client")
                     .error(Errors.INVALID_REQUEST)
                     .userId(mike.getId())
                     .sessionId(originalToken.getSessionId())
                     .details(Details.REASON, "Refresh token not valid as requested_token_type because creating a new session is needed");
         } finally {
             requesterClient.update(client -> client
                     .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name())
             );
         }
     }

    @Test
    public void testOfflineAccessNotAllowedAfterOfflineAccessLogin() throws Exception {
        requesterClient.update(client -> client
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name())
        );
        try {
            // Login with "scope=offline_access" . Will create offline user-session
            String accessToken = resourceOwnerLogin("mike", "password", "subject-client", "secret", OAuth2Constants.OFFLINE_ACCESS).getAccessToken();

            // Doublecheck count of sessions
            String subjectClientUuid = subjectClient.getId();
            String requesterClientUuid = requesterClient.getId();
            UserResource user = realm.admin().users().get(mike.getId());
            assertEquals(0, user.getUserSessions().size());
            assertEquals(1, user.getOfflineSessions(subjectClientUuid).size());
            assertEquals(0, user.getOfflineSessions(requesterClientUuid).size());

            // Token exchange with scope=offline-access should not be allowed
            oauth.scope("offline_access");
            AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("target-client1"), OAuth2Constants.REFRESH_TOKEN_TYPE);
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());

            // Make sure not new user sessions persisted
            assertEquals(0, user.getUserSessions().size());
            assertEquals(1, user.getOfflineSessions(subjectClientUuid).size());
            assertEquals(0, user.getOfflineSessions(requesterClientUuid).size());
        } finally {
            oauth.scope("openid");
            requesterClient.update(client -> client.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name())
            );
        }
    }

    @Test
    public void testIntrospectionWithExchangedTokenAfterSSOLoginOfRequesterClient() throws Exception {
        // Login with "subject-client" and create SSO session
        subjectClient.update(client -> client.consentRequired(true));
        try {
            String accessToken = loginWithConsents(mike, "password", "subject-client", "secret");

            // Token exchange access-token for "Requester-client" . No client session yet for "requester-client" at this stage
            AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret",  null, null);
            String exchangedToken = response.getAccessToken();
            assertNotNull(exchangedToken);

            // Set time offset
            timeOffSet.set(10);

            // SSO login to "requester-client". Will create client session for "requester-client"
            oauth.client("requester-client", "secret").openLoginForm();
            assertNotNull(oauth.parseLoginResponse().getCode());
            response = oauth.doAccessTokenRequest(oauth.parseLoginResponse().getCode());
            assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
            String requesterClientToken = response.getAccessToken();

            // Token introspection with the previously exchanged token should success. Also with the new token should success
            assertIntrospectSuccess(exchangedToken, "requester-client", "secret", mike.getId());
            assertIntrospectSuccess(requesterClientToken, "requester-client", "secret", mike.getId());
        } finally {
            timeOffSet.set(0);
            subjectClient.update(client -> client.consentRequired(false));
        }
    }

    @Test
    public void testTokenRevocation() throws Exception {
        requesterClient.update(client -> client
                .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name())
        );
        try {
            AccessTokenResponse accessTokenResponse = resourceOwnerLogin("john", "password", "subject-client", "secret");

            //revoke the exchanged access token
            AccessTokenResponse tokenExchangeResponse = tokenExchange(accessTokenResponse.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            oauth.client("requester-client", "secret");
            events.clear();
            oauth.doTokenRevoke(tokenExchangeResponse.getAccessToken());
            EventAssertion.assertSuccess(events.poll())
                    .type(EventType.REVOKE_GRANT)
                    .clientId("requester-client")
                    .userId(john.getId());
            isAccessTokenEnabled(accessTokenResponse.getAccessToken(), "subject-client", "secret");
            isAccessTokenDisabled(tokenExchangeResponse.getAccessToken(), "requester-client", "secret");

            //revoke the exchanged refresh token
            tokenExchangeResponse = tokenExchange(accessTokenResponse.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            events.clear();
            oauth.doTokenRevoke(tokenExchangeResponse.getRefreshToken());
            EventAssertion.assertSuccess(events.poll())
                    .type(EventType.REVOKE_GRANT)
                    .clientId("requester-client")
                    .userId(john.getId())
                    .sessionId(tokenExchangeResponse.getSessionState());
            isTokenDisabled(tokenExchangeResponse, "requester-client", "secret");

            //revoke the subject access token
            tokenExchangeResponse = tokenExchange(accessTokenResponse.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            oauth.client("subject-client", "secret");
            events.clear();
            oauth.doTokenRevoke(accessTokenResponse.getAccessToken());
            EventAssertion.assertSuccess(events.poll())
                    .type(EventType.REVOKE_GRANT)
                    .clientId("subject-client")
                    .userId(john.getId())
                    .details(Details.TOKEN_EXCHANGE_REVOKED_CLIENTS, "requester-client");
            isAccessTokenDisabled(accessTokenResponse.getAccessToken(), "subject-client", "secret");
            isTokenDisabled(tokenExchangeResponse, "requester-client", "secret");

            //revoke the subject refresh token
            accessTokenResponse = resourceOwnerLogin("john", "password", "subject-client", "secret");
            tokenExchangeResponse = tokenExchange(accessTokenResponse.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            assertEquals(Response.Status.OK.getStatusCode(), tokenExchangeResponse.getStatusCode());
            oauth.client("subject-client", "secret");
            events.clear();
            oauth.doTokenRevoke(accessTokenResponse.getRefreshToken());
            EventAssertion.assertSuccess(events.poll())
                    .type(EventType.REVOKE_GRANT)
                    .clientId("subject-client")
                    .userId(john.getId())
                    .sessionId(tokenExchangeResponse.getSessionState())
                    .details(Details.TOKEN_EXCHANGE_REVOKED_CLIENTS, "requester-client");
            isTokenDisabled(accessTokenResponse, "subject-client", "secret");
            isTokenDisabled(tokenExchangeResponse, "requester-client", "secret");

            //revoke multiple access token
            AccessTokenResponse accessTokenResponse1 = resourceOwnerLogin("john", "password", "subject-client", "secret");
            AccessTokenResponse accessTokenResponse2 = oauth.doRefreshTokenRequest(accessTokenResponse1.getRefreshToken());
            AccessTokenResponse accessTokenResponse3 = oauth.doRefreshTokenRequest(accessTokenResponse1.getRefreshToken());

            AccessTokenResponse tokenExchangeResponse1 = tokenExchange(accessTokenResponse1.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            assertEquals(Response.Status.OK.getStatusCode(), tokenExchangeResponse1.getStatusCode());
            AccessTokenResponse tokenExchangeResponse2 = tokenExchange(accessTokenResponse2.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
            assertEquals(Response.Status.OK.getStatusCode(), tokenExchangeResponse2.getStatusCode());

            oauth.client("subject-client", "secret");
            events.clear();
            oauth.doTokenRevoke(accessTokenResponse3.getAccessToken());
            EventAssertion.assertSuccess(events.poll())
                    .type(EventType.REVOKE_GRANT)
                    .clientId("subject-client")
                    .userId(john.getId())
                    .details(Details.TOKEN_EXCHANGE_REVOKED_CLIENTS, "requester-client");
            isAccessTokenEnabled(accessTokenResponse1.getAccessToken(), "subject-client", "secret");
            isAccessTokenEnabled(accessTokenResponse2.getAccessToken(), "subject-client", "secret");
            isAccessTokenDisabled(accessTokenResponse3.getAccessToken(), "subject-client", "secret");
            isTokenDisabled(tokenExchangeResponse1, "requester-client", "secret");
            isTokenDisabled(tokenExchangeResponse2, "requester-client", "secret");

            //revoke exchange chain if an already exchanged token is used for token exchange
            // Create protocol mapper and save its ID for cleanup
            ProtocolMapperRepresentation mapper = ModelToRepresentation.toRepresentation(
                    AudienceProtocolMapper.createClaimMapper("requester-client-2", "requester-client-2", null, true, false, true)
            );
            Response createMapperResponse = requesterClient.admin().getProtocolMappers().createMapper(mapper);
            final String mapperId = ApiUtil.getCreatedId(createMapperResponse);
            createMapperResponse.close();

            requesterClient2.update(c->c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION.name()));
            try {
                accessTokenResponse = resourceOwnerLogin("john", "password", "subject-client", "secret");
                tokenExchangeResponse1 = tokenExchange(accessTokenResponse.getAccessToken(), "requester-client", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
                assertEquals(Response.Status.OK.getStatusCode(), tokenExchangeResponse1.getStatusCode());

                tokenExchangeResponse2 = tokenExchange(tokenExchangeResponse1.getAccessToken(), "requester-client-2", "secret", null, OAuth2Constants.REFRESH_TOKEN_TYPE);
                assertEquals(Response.Status.OK.getStatusCode(), tokenExchangeResponse2.getStatusCode());

                oauth.client("subject-client", "secret");
                events.clear();
                oauth.doTokenRevoke(accessTokenResponse.getAccessToken());
                EventAssertion.assertSuccess(events.poll())
                        .type(EventType.REVOKE_GRANT)
                        .clientId("subject-client")
                        .userId(john.getId())
                        .detailsAsList(Details.TOKEN_EXCHANGE_REVOKED_CLIENTS,"requester-client-2,requester-client");

                isTokenDisabled(tokenExchangeResponse1, "requester-client", "secret");
                isTokenDisabled(tokenExchangeResponse2, "requester-client-2", "secret");
            } finally {
                // Delete the protocol mapper and restore requester-client-2 attribute
                requesterClient.admin().getProtocolMappers().delete(mapperId);
                requesterClient2.update(c->c.attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name()));
            }
        } finally {
            requesterClient.update(client -> client
                    .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.NO.name())
            );
        }
    }

    @Test
    public void testExchangeChainRequesters() throws Exception {
        String accessToken = resourceOwnerLogin("alice", "password", "subject-client", "secret", "optional-requester-scope").getAccessToken();

        // exchange with requester-client
        AccessTokenResponse response = tokenExchange(accessToken, "requester-client", "secret", List.of("requester-client-2"), null);
        assertAudiencesAndScopes(response, alice, List.of("requester-client-2"), List.of("optional-requester-scope"));
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        AccessToken exchangedToken = verifier.parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());

        // exchange now with requester-client-2
        response = tokenExchange(exchangedTokenString, "requester-client-2", "secret", List.of("requester-client"), null);
        assertAudiencesAndScopes(response, alice, List.of("requester-client"), List.of("optional-requester-scope"),
                OAuth2Constants.ACCESS_TOKEN_TYPE, "requester-client");
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        exchangedTokenString = response.getAccessToken();
        verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        exchangedToken = verifier.parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client-2", exchangedToken.getIssuedFor());

        // exchange again with requester-client
        response = tokenExchange(exchangedTokenString, "requester-client", "secret", List.of("requester-client-2"), null);
        assertAudiencesAndScopes(response, alice, List.of("requester-client-2"), List.of("optional-requester-scope"),
                OAuth2Constants.ACCESS_TOKEN_TYPE, "requester-client-2");
        assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        exchangedTokenString = response.getAccessToken();
        verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        exchangedToken = verifier.parse().getToken();
        assertEquals(getSessionIdFromToken(accessToken), exchangedToken.getSessionId());
        assertEquals("requester-client", exchangedToken.getIssuedFor());

        // test revocation endpoint
        isAccessTokenEnabled(response.getAccessToken(), "requester-client", "secret");
        TokenRevocationResponse revocationResponse = oauth.client("requester-client", "secret").doTokenRevoke(response.getAccessToken());
        assertNull(revocationResponse.getError());
        EventAssertion.assertSuccess(events.poll())
                .type(EventType.REVOKE_GRANT)
                .clientId("requester-client")
                .userId(alice.getId());
        isAccessTokenDisabled(response.getAccessToken(), "requester-client", "secret");
    }


}
