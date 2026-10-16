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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.component.ComponentModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.context.AdminClientUpdateContext;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisExecutor;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisPatternExecutor;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisPatternExecutorFactory;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.DefaultClientRegistrationContext;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;
import org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicyFactory;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ClientUriFieldTest {

    @Test
    public void absentAttributesAndNullListEntriesAreSafe() {
        var client = new ClientRepresentation();
        client.setRedirectUris(Arrays.asList(null, "", "https://localhost/callback"));
        for (ClientUriField field : ClientUriField.values()) {
            assertEquals(field == ClientUriField.REDIRECT_URIS ? List.of("https://localhost/callback") : List.of(), field.getValues(client));
        }
    }

    @Test
    public void multivaluedAttributesPreserveAllUris() {
        var client = new ClientRepresentation();
        client.setAttributes(Map.of(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, "+##https://untrusted.example/logout##https://localhost/logout"));
        assertEquals(Set.of("https://untrusted.example/logout", "https://localhost/logout"), Set.copyOf(ClientUriField.POST_LOGOUT_REDIRECT_URIS.getPolicyValues(null, client)));
        assertThrows(ClientRegistrationPolicyException.class,
                () -> ClientUriPolicyTest.trustedHostPolicy().beforeRegister(new DefaultClientRegistrationContext(null, client, null)));
    }

    @Test
    public void redirectReferencesAndDisabledPostLogoutRedirectsAreAccepted() throws Exception {
        var client = new ClientRepresentation();
        client.setRedirectUris(List.of("https://localhost/callback"));
        client.setWebOrigins(List.of("+"));
        client.setAttributes(Map.of(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, "+##-"));
        assertEquals(List.of("https://localhost/callback"), ClientUriField.POST_LOGOUT_REDIRECT_URIS.getPolicyValues(null, client));
        assertEquals(List.of("https://localhost"), ClientUriField.WEB_ORIGINS.getPolicyValues(null, client));
        ClientUriPolicyTest.trustedHostPolicy().beforeRegister(new DefaultClientRegistrationContext(null, client, null));
        new SecureClientUrisExecutor(null).executeOnEvent(new AdminClientRegisterContext(client, null));
    }

    @Test
    public void relativeLogoutUrisUseTrustedRoot() {
        var client = new ClientRepresentation();
        client.setRootUrl("https://localhost");
        client.setAttributes(Map.of(OIDCConfigAttributes.FRONT_CHANNEL_LOGOUT_URI, "/logout"));
        ClientUriPolicyTest.trustedHostPolicy().beforeRegister(new DefaultClientRegistrationContext(null, client, null));
    }

    @Test
    public void schemeRelativeUrisCannotHideTheirAuthority() {
        for (String root : Arrays.asList(null, "https://localhost")) {
            var client = new ClientRepresentation();
            client.setRootUrl(root);
            for (String attribute : List.of(OIDCConfigAttributes.FRONT_CHANNEL_LOGOUT_URI, OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, OIDCConfigAttributes.REQUEST_URIS)) {
                client.setAttributes(Map.of(attribute, "//untrusted.example/logout"));
                var context = new DefaultClientRegistrationContext(null, client, null);
                assertThrows(ClientRegistrationPolicyException.class, () -> ClientUriPolicyTest.trustedHostPolicy().beforeRegister(context));
                assertThrows(ClientRegistrationPolicyException.class, () -> ClientUriPolicyTest.trustedHostPolicy().beforeUpdate(context, null));
            }
        }
    }

    @Test
    public void specialValuesAreSpecificToTheirField() {
        assertTrue(ClientUriField.POST_LOGOUT_REDIRECT_URIS.isSpecialValue("+"));
        assertTrue(ClientUriField.POST_LOGOUT_REDIRECT_URIS.isSpecialValue("-"));
        var client = new ClientRepresentation();
        client.setAttributes(Map.of(OIDCConfigAttributes.REQUEST_URIS, "+"));
        assertThrows(ClientRegistrationPolicyException.class,
                () -> ClientUriPolicyTest.trustedHostPolicy().beforeRegister(new DefaultClientRegistrationContext(null, client, null)));
    }

    @Test
    public void trustedHostUpdatesUseValidationHook() {
        var component = new ComponentModel();
        component.getConfig().putSingle(TrustedHostClientRegistrationPolicyFactory.HOST_SENDING_REGISTRATION_REQUEST_MUST_MATCH, "false");
        var policy = new TrustedHostClientRegistrationPolicy(null, component) {
            @Override
            protected void verifyClientUrls(ClientRegistrationContext context) {
                throw new ClientRegistrationPolicyException("Custom URI validation");
            }
        };
        var context = new DefaultClientRegistrationContext(null, new ClientRepresentation(), null);
        assertEquals("Custom URI validation", assertThrows(ClientRegistrationPolicyException.class,
                () -> policy.beforeUpdate(context, null)).getMessage());
    }

    @Test
    public void patternSelectionLeavesOtherFieldsUnrestricted() throws Exception {
        var client = new ClientRepresentation();
        client.setBaseUrl("https://untrusted.example/home");
        client.setAttributes(Map.of(OIDCConfigAttributes.LOGO_URI, "https://localhost/logo"));
        var executor = ClientUriPolicyTest.patternPolicy(List.of("logoUri"));
        assertEquals(SecureClientUrisPatternExecutorFactory.PROVIDER_ID, executor.getProviderId());
        executor.executeOnEvent(new AdminClientRegisterContext(client, null));
    }

    @Test
    public void patternMatchesLiteralWebOrigins() throws Exception {
        var client = new ClientRepresentation();
        client.setRedirectUris(List.of("https://untrusted.example/callback"));
        client.setWebOrigins(List.of("+", "*", "null"));
        var executor = literalMarkerPattern(List.of("webOrigins"));
        executor.executeOnEvent(new AdminClientRegisterContext(client, null));
        executor.executeOnEvent(new AdminClientUpdateContext(client, null, null));
        client.setWebOrigins(List.of("+", "https://untrusted.example"));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client, null)));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientUpdateContext(client, null, null)));
    }

    @Test
    public void patternMatchesLiteralPostLogoutUris() throws Exception {
        var client = new ClientRepresentation();
        client.setRedirectUris(List.of("https://untrusted.example/callback"));
        client.setAttributes(Map.of(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, "+##-##*##https://localhost/logout"));
        var executor = literalMarkerPattern(List.of("postLogoutRedirectUris"));
        executor.executeOnEvent(new AdminClientRegisterContext(client, null));
        executor.executeOnEvent(new AdminClientUpdateContext(client, null, null));
        client.setAttributes(Map.of(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, "+##-##https://untrusted.example/logout"));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientRegisterContext(client, null)));
        assertThrows(ClientPolicyException.class, () -> executor.executeOnEvent(new AdminClientUpdateContext(client, null, null)));
    }

    @Test
    public void patternDoesNotResolveOrSkipLiteralMarkers() {
        var client = new ClientRepresentation();
        client.setRedirectUris(List.of("https://localhost/callback"));
        client.setWebOrigins(List.of("+"));
        var origins = ClientUriPolicyTest.patternPolicy(List.of("webOrigins"));
        assertThrows(ClientPolicyException.class, () -> origins.executeOnEvent(new AdminClientRegisterContext(client, null)));
        assertThrows(ClientPolicyException.class, () -> origins.executeOnEvent(new AdminClientUpdateContext(client, null, null)));
        var logout = ClientUriPolicyTest.patternPolicy(List.of("postLogoutRedirectUris"));
        for (String marker : List.of("+", "-", "*")) {
            client.setAttributes(Map.of(OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, marker));
            assertThrows(ClientPolicyException.class, () -> logout.executeOnEvent(new AdminClientRegisterContext(client, null)));
            assertThrows(ClientPolicyException.class, () -> logout.executeOnEvent(new AdminClientUpdateContext(client, null, null)));
        }
    }

    private static SecureClientUrisPatternExecutor literalMarkerPattern(List<String> fields) {
        var executor = new SecureClientUrisPatternExecutor(null);
        var configuration = new SecureClientUrisPatternExecutor.Configuration();
        configuration.setAllowedPatterns(List.of("\\+", "-", "\\*", "null", "https://localhost/.*"));
        configuration.setClientUriFields(fields);
        executor.setupConfiguration(configuration);
        return executor;
    }
}
