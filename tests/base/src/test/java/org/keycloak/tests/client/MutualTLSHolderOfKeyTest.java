/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.tests.client;

import java.io.IOException;
import java.util.Collections;
import javax.net.ssl.SSLContext;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.https.CertificatesConfig;
import org.keycloak.testframework.https.CertificatesConfigBuilder;
import org.keycloak.testframework.https.InjectCertificates;
import org.keycloak.testframework.https.ManagedCertificates;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.tests.utils.admin.AdminApiUtil;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Verifies that OAuth 2.0 Mutual TLS certificate bound access tokens (RFC 8705) are validated by the Keycloak
 * endpoints, which accept an access token as the credential authorizing the request.
 *
 * @author <a href="mailto:ggrazian@redhat.com">Giuseppe Graziano</a>
 */
@KeycloakIntegrationTest
public class MutualTLSHolderOfKeyTest {

    private static final String HOK_CLIENT_ID = "hok-client";
    private static final String PLAIN_CLIENT_ID = "plain-client";
    private static final String CLIENT_SECRET = "hok-client-secret";
    private static final String ADMIN_USER = "hok-admin@localhost";
    private static final String ADMIN_PASSWORD = "password";

    @InjectCertificates(config = HoKCertificatesConfig.class)
    ManagedCertificates managedCertificates;

    @InjectRealm(config = HoKRealmConfig.class)
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @Test
    public void testAdminRestWithCertificateBoundToken() throws Exception {
        AccessTokenResponse response = getHoKAccessToken(HOK_CLIENT_ID);

        // The very same certificate the token is bound to
        Assertions.assertEquals(Status.OK.getStatusCode(), adminRealmRequest(response.getAccessToken(), clientCertificateSslContext()));

        // No client certificate at all
        Assertions.assertEquals(Status.UNAUTHORIZED.getStatusCode(), adminRealmRequest(response.getAccessToken(), noClientCertificateSslContext()));
    }

    @Test
    public void testAdminRestWithPlainBearerTokenIsNotAffected() throws Exception {
        AccessTokenResponse response = getAccessToken(PLAIN_CLIENT_ID, clientCertificateSslContext());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        Assertions.assertNull(accessToken.getConfirmation());

        Assertions.assertEquals(Status.OK.getStatusCode(), adminRealmRequest(response.getAccessToken(), noClientCertificateSslContext()));
    }

    @Test
    public void testUserInfoWithCertificateBoundToken() throws Exception {
        AccessTokenResponse response = getHoKAccessToken(HOK_CLIENT_ID);

        Assertions.assertEquals(Status.OK.getStatusCode(), userInfoRequest(response.getAccessToken(), clientCertificateSslContext()));
        Assertions.assertEquals(Status.UNAUTHORIZED.getStatusCode(), userInfoRequest(response.getAccessToken(), noClientCertificateSslContext()));
    }

    @Test
    public void testClientRegistrationWithCertificateBoundToken() throws Exception {
        AccessTokenResponse response = getHoKAccessToken(HOK_CLIENT_ID);

        // Without the client certificate the registration request is rejected
        Assertions.assertEquals(Status.UNAUTHORIZED.getStatusCode(),
                registerClientRequest(response.getAccessToken(), noClientCertificateSslContext()).status());

        // With the client certificate the token is bound to, the client is registered
        RegistrationResult result = registerClientRequest(response.getAccessToken(), clientCertificateSslContext());
        Assertions.assertEquals(Status.CREATED.getStatusCode(), result.status());

        String registeredClientId = result.clientId();
        Assertions.assertNotNull(registeredClientId);
        realm.cleanup().add(r -> {
            ClientResource clientResource = AdminApiUtil.findClientByClientId(r, registeredClientId);
            if (clientResource != null) {
                clientResource.remove();
            }
        });
    }

    private AccessTokenResponse getHoKAccessToken(String clientId) throws IOException {
        AccessTokenResponse response = getAccessToken(clientId, clientCertificateSslContext());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        Assertions.assertNotNull(accessToken.getConfirmation(), "Access token is not bound to the client certificate");
        Assertions.assertNotNull(accessToken.getConfirmation().getCertThumbprint(), "Access token is missing the x5t#S256 confirmation");
        return response;
    }

    private AccessTokenResponse getAccessToken(String clientId, SSLContext sslContext) throws IOException {
        try (CloseableHttpClient httpClient = newHttpClient(sslContext)) {
            oauth.httpClient().set(httpClient);
            AccessTokenResponse response = oauth.client(clientId, CLIENT_SECRET)
                    .passwordGrantRequest(ADMIN_USER, ADMIN_PASSWORD).send();
            Assertions.assertEquals(Status.OK.getStatusCode(), response.getStatusCode());
            return response;
        } finally {
            oauth.httpClient().reset();
        }
    }

    private int adminRealmRequest(String accessToken, SSLContext sslContext) throws IOException {
        return getRequestStatus(keycloakUrls.getAdmin() + "/realms/" + realm.getName(), accessToken, sslContext);
    }

    private int userInfoRequest(String accessToken, SSLContext sslContext) throws IOException {
        return getRequestStatus(oauth.getEndpoints().getUserInfo(), accessToken, sslContext);
    }

    private int getRequestStatus(String url, String accessToken, SSLContext sslContext) throws IOException {
        try (CloseableHttpClient httpClient = newHttpClient(sslContext)) {
            HttpGet get = new HttpGet(url);
            get.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
            get.addHeader(HttpHeaders.ACCEPT, "application/json");
            try (CloseableHttpResponse response = httpClient.execute(get)) {
                return response.getStatusLine().getStatusCode();
            }
        }
    }

    private RegistrationResult registerClientRequest(String accessToken, SSLContext sslContext) throws IOException {
        OIDCClientRepresentation clientRep = new OIDCClientRepresentation();
        clientRep.setClientName("hok-dcr-" + KeycloakModelUtils.generateId());
        clientRep.setRedirectUris(Collections.singletonList(oauth.getRedirectUri()));

        try (CloseableHttpClient httpClient = newHttpClient(sslContext)) {
            HttpPost post = new HttpPost(keycloakUrls.getBase() + "/realms/" + realm.getName() + "/clients-registrations/openid-connect");
            post.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
            post.setEntity(new StringEntity(JsonSerialization.writeValueAsString(clientRep), ContentType.APPLICATION_JSON));
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                int status = response.getStatusLine().getStatusCode();
                if (status != Status.CREATED.getStatusCode()) {
                    return new RegistrationResult(status, null);
                }
                OIDCClientRepresentation registered = JsonSerialization.readValue(response.getEntity().getContent(), OIDCClientRepresentation.class);
                return new RegistrationResult(status, registered.getClientId());
            }
        }
    }

    private SSLContext clientCertificateSslContext() {
        return managedCertificates.getClientSSLContext();
    }

    private SSLContext noClientCertificateSslContext() {
        try {
            return SSLContextBuilder.create().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private CloseableHttpClient newHttpClient(SSLContext sslContext) {
        return HttpClientBuilder.create()
                .setSSLSocketFactory(new SSLConnectionSocketFactory(sslContext))
                .build();
    }

    private record RegistrationResult(int status, String clientId) {
    }

    private static class HoKCertificatesConfig implements CertificatesConfig {

        @Override
        public CertificatesConfigBuilder configure(CertificatesConfigBuilder config) {
            return config
                    .tlsEnabled(true)
                    .mTlsEnabled(true)
                    .keystoreFormat(KeystoreUtil.KeystoreFormat.PKCS12);
        }
    }

    private static class HoKRealmConfig implements RealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            realm.users(UserBuilder.create()
                    .id(KeycloakModelUtils.generateId())
                    .username(ADMIN_USER)
                    .email(ADMIN_USER)
                    .emailVerified(true)
                    .name("HoK", "Admin")
                    .password(ADMIN_PASSWORD)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.REALM_ADMIN));

            realm.clients(ClientBuilder.create(HOK_CLIENT_ID)
                    .secret(CLIENT_SECRET)
                    .directAccessGrantsEnabled()
                    .redirectUris("*")
                    .attribute(OIDCConfigAttributes.USE_MTLS_HOK_TOKEN, Boolean.TRUE.toString()));

            realm.clients(ClientBuilder.create(PLAIN_CLIENT_ID)
                    .secret(CLIENT_SECRET)
                    .directAccessGrantsEnabled()
                    .redirectUris("*"));

            return realm;
        }
    }
}
