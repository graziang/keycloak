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
package org.keycloak.validation;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.CibaConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.context.AdminClientUpdateContext;
import org.keycloak.services.clientpolicy.context.ClientCRUDContext;
import org.keycloak.services.clientpolicy.context.DynamicClientUpdateContext;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisExecutor;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisPatternExecutor;
import org.keycloak.services.clientregistration.DefaultClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicyFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

/** Exercise the same client metadata through the registration and client policy entry points. */
@RunWith(Parameterized.class)
public class ClientUriPolicyTest {

    private static final String TRUSTED = "https://localhost/callback";
    private static final String UNTRUSTED = "https://untrusted.example/callback";

    @Parameterized.Parameters(name = "{0} ({1})")
    public static List<Object[]> fields() {
        List<Object[]> fields = new ArrayList<>();
        fields.add(field("rootUrl", ClientRepresentation::setRootUrl));
        fields.add(field("baseUrl", ClientRepresentation::setBaseUrl));
        fields.add(field("adminUrl", ClientRepresentation::setAdminUrl));
        fields.add(field("redirectUris", (c, u) -> c.setRedirectUris(List.of(u))));
        fields.add(field("webOrigins", (c, u) -> c.setWebOrigins(List.of(u))));
        fields.add(attribute("jwksUri", OIDCConfigAttributes.JWKS_URL));
        fields.add(attribute("requestUris", OIDCConfigAttributes.REQUEST_URIS));
        fields.add(attribute("backchannelLogoutUrl", OIDCConfigAttributes.BACKCHANNEL_LOGOUT_URL));
        fields.add(attribute("frontChannelLogoutUrl", OIDCConfigAttributes.FRONT_CHANNEL_LOGOUT_URI));
        fields.add(attribute("postLogoutRedirectUris", OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS));
        fields.add(attribute("cibaClientNotificationEndpoint", CibaConfig.CIBA_BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT));
        fields.add(attribute("logoUri", OIDCConfigAttributes.LOGO_URI));
        fields.add(attribute("policyUri", OIDCConfigAttributes.POLICY_URI));
        fields.add(attribute("tosUri", OIDCConfigAttributes.TOS_URI));
        fields.add(attribute("sectorIdentifierUri", OIDCConfigAttributes.SECTOR_IDENTIFIER_URI));
        fields.add(new Object[]{"adminUrl", SamlProtocol.LOGIN_PROTOCOL, (BiConsumer<ClientRepresentation, String>) ClientRepresentation::setAdminUrl});
        for (String attribute : List.of(
                SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
                SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE,
                SamlProtocol.SAML_ASSERTION_CONSUMER_URL_ARTIFACT_ATTRIBUTE,
                SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE,
                SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE,
                SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE,
                SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE,
                SamlProtocol.SAML_ARTIFACT_RESOLUTION_SERVICE_URL_ATTRIBUTE,
                SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL)) {
            Object[] field = attribute(attribute, attribute);
            field[1] = SamlProtocol.LOGIN_PROTOCOL;
            fields.add(field);
        }
        return fields;
    }

    private static Object[] field(String name, BiConsumer<ClientRepresentation, String> setter) {
        return new Object[]{name, "openid-connect", setter};
    }

    private static Object[] attribute(String name, String attribute) {
        return field(name, (c, u) -> c.setAttributes(Map.of(attribute, u)));
    }

    private final String field;
    private final String protocol;
    private final BiConsumer<ClientRepresentation, String> setter;

    public ClientUriPolicyTest(String field, String protocol, BiConsumer<ClientRepresentation, String> setter) {
        this.field = field;
        this.protocol = protocol;
        this.setter = setter;
    }

    @Test
    public void trustedHostAcceptsTrustedUri() {
        ClientRepresentation client = client(TRUSTED);
        var context = new DefaultClientRegistrationContext(null, client, null);
        trustedHostPolicy().beforeRegister(context);
        trustedHostPolicy().beforeUpdate(context, null);
    }

    @Test
    public void trustedHostRejectsUntrustedUriOnCreateAndUpdate() {
        var context = new DefaultClientRegistrationContext(null, client(UNTRUSTED), null);
        assertThrows(ClientRegistrationPolicyException.class, () -> trustedHostPolicy().beforeRegister(context));
        assertThrows(ClientRegistrationPolicyException.class, () -> trustedHostPolicy().beforeUpdate(context, null));
    }

    @Test
    public void secureUrisAcceptsHttps() throws ClientPolicyException {
        var executor = new SecureClientUrisExecutor(null);
        executor.executeOnEvent(new AdminClientRegisterContext(client(TRUSTED), null));
        executor.executeOnEvent(new AdminClientUpdateContext(client(TRUSTED), null, null));
    }

    @Test
    public void secureUrisRejectsHttpOnCreateAndUpdate() {
        var executor = new SecureClientUrisExecutor(null);
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client("http://localhost/callback"), null)));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientUpdateContext(client("http://localhost/callback"), null, null)));
    }

    @Test
    public void secureUrisRejectsWildcards() {
        var executor = new SecureClientUrisExecutor(null);
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client(TRUSTED + "/*"), null)));
    }

    @Test
    public void patternAcceptsMatchingUri() throws ClientPolicyException {
        var executor = patternPolicy(null);
        executor.executeOnEvent(new AdminClientRegisterContext(client(TRUSTED), null));
        executor.executeOnEvent(new AdminClientUpdateContext(client(TRUSTED), null, null));
    }

    @Test
    public void patternRejectsUnmatchedUriOnCreateAndUpdate() {
        var executor = patternPolicy(null);
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client(UNTRUSTED), null)));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientUpdateContext(client(UNTRUSTED), null, null)));
    }

    @Test
    public void patternHonorsConfiguredFieldNames() {
        var executor = patternPolicy(List.of(field));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client(UNTRUSTED), null)));
    }

    @Test
    public void updatesWithoutProtocolAcceptTrustedUris() throws Exception {
        var proposed = client(TRUSTED);
        proposed.setProtocol(null);
        ClientModel target = existingClient(protocol);
        var registration = new DefaultClientRegistrationContext(null, proposed, null);
        trustedHostPolicy().beforeUpdate(registration, target);
        for (ClientCRUDContext context : List.of(new AdminClientUpdateContext(proposed, target, null),
                new DynamicClientUpdateContext(registration, target, null, null))) {
            new SecureClientUrisExecutor(null).executeOnEvent(context);
            patternPolicy(List.of(field)).executeOnEvent(context);
        }
        assertNull(proposed.getProtocol());
    }

    @Test
    public void updatesWithoutProtocolRejectUntrustedUris() {
        var proposed = client(UNTRUSTED);
        proposed.setProtocol(null);
        ClientModel target = existingClient(protocol);
        var registration = new DefaultClientRegistrationContext(null, proposed, null);
        assertThrows(ClientRegistrationPolicyException.class, () -> trustedHostPolicy().beforeUpdate(registration, target));
        for (ClientCRUDContext context : List.of(new AdminClientUpdateContext(proposed, target, null),
                new DynamicClientUpdateContext(registration, target, null, null))) {
            assertThrows(ClientPolicyException.class, () -> patternPolicy(List.of(field)).executeOnEvent(context));
            setter.accept(proposed, "http://localhost/callback");
            assertThrows(ClientPolicyException.class, () -> new SecureClientUrisExecutor(null).executeOnEvent(context));
            setter.accept(proposed, UNTRUSTED);
        }
        assertNull(proposed.getProtocol());
    }

    @Test
    public void updatesUseExplicitProtocolInsteadOfExistingProtocol() {
        var proposed = client(UNTRUSTED);
        ClientModel target = existingClient(SamlProtocol.LOGIN_PROTOCOL.equals(protocol) ? "openid-connect" : SamlProtocol.LOGIN_PROTOCOL);
        var registration = new DefaultClientRegistrationContext(null, proposed, null);
        assertThrows(ClientRegistrationPolicyException.class, () -> trustedHostPolicy().beforeUpdate(registration, target));
        for (ClientCRUDContext context : List.of(new AdminClientUpdateContext(proposed, target, null),
                new DynamicClientUpdateContext(registration, target, null, null))) {
            assertThrows(ClientPolicyException.class, () -> patternPolicy(List.of(field)).executeOnEvent(context));
            setter.accept(proposed, "http://localhost/callback");
            assertThrows(ClientPolicyException.class, () -> new SecureClientUrisExecutor(null).executeOnEvent(context));
            setter.accept(proposed, UNTRUSTED);
        }
        assertEquals(protocol, proposed.getProtocol());
    }

    private static ClientModel existingClient(String protocol) {
        return (ClientModel) Proxy.newProxyInstance(ClientUriPolicyTest.class.getClassLoader(), new Class<?>[]{ClientModel.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getProtocol")) {
                        return protocol;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private ClientRepresentation client(String uri) {
        var client = new ClientRepresentation();
        client.setProtocol(protocol);
        setter.accept(client, uri);
        return client;
    }

    static TrustedHostClientRegistrationPolicy trustedHostPolicy() {
        var component = new ComponentModel();
        component.getConfig().putSingle(TrustedHostClientRegistrationPolicyFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH, "false");
        component.getConfig().putSingle(TrustedHostClientRegistrationPolicyFactory.TRUSTED_HOSTS, "localhost");
        return new TrustedHostClientRegistrationPolicy(null, component);
    }

    static SecureClientUrisPatternExecutor patternPolicy(List<String> fields) {
        var executor = new SecureClientUrisPatternExecutor(null);
        var configuration = new SecureClientUrisPatternExecutor.Configuration();
        configuration.setAllowedPatterns(List.of("https://localhost/.*"));
        configuration.setClientUriFields(fields);
        executor.setupConfiguration(configuration);
        return executor;
    }
}
