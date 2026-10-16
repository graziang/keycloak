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
package org.keycloak.tests.client.policies;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.BadRequestException;

import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.idm.ClientPolicyConditionConfigurationRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.condition.AnyClientConditionFactory;
import org.keycloak.services.clientpolicy.executor.SamlSecureClientUrisExecutor;
import org.keycloak.services.clientpolicy.executor.SamlSecureClientUrisExecutorFactory;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisExecutor;
import org.keycloak.services.clientpolicy.executor.SecureClientUrisExecutorFactory;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedRealm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KeycloakIntegrationTest
public class SamlClientUrisExecutorTest extends AbstractClientPoliciesTest {

    @InjectRealm
    ManagedRealm realm;

    @Test
    public void metadataDescriptorMustUseHttpsOnCreateAndUpdate() throws Exception {
        setupPolicy(false);
        var error = assertThrows(ClientPolicyException.class, () -> createClientByAdmin(realm,
                generateSuffixedName("insecure-metadata"), SamlProtocol.LOGIN_PROTOCOL, client -> {
                    client.setRedirectUris(List.of("https://localhost/callback"));
                    client.getAttributes().put(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, "http://localhost/metadata");
                }));
        assertEquals("Non secure scheme for Metadata descriptor URL", error.getErrorDetail());

        String id = createClientByAdmin(realm, generateSuffixedName("secure-metadata"), SamlProtocol.LOGIN_PROTOCOL, client -> {
            client.setRedirectUris(List.of("https://localhost/callback"));
            client.getAttributes().put(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, "https://localhost/metadata");
        });
        error = assertThrows(ClientPolicyException.class, () -> updateClientByAdmin(realm, id,
                client -> client.getAttributes().put(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, "http://localhost/metadata")));
        assertEquals("Non secure scheme for Metadata descriptor URL", error.getErrorDetail());
        assertEquals("https://localhost/metadata", realm.admin().clients().get(id).toRepresentation().getAttributes().get(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL));
    }

    @Test
    public void wildcardRedirectsRemainConfigurable() throws Exception {
        setupPolicy(false);
        assertThrows(ClientPolicyException.class, () -> createClientByAdmin(realm,
                generateSuffixedName("wildcard-rejected"), SamlProtocol.LOGIN_PROTOCOL,
                client -> client.setRedirectUris(List.of("https://localhost/*"))));
        setupPolicy(true);
        String id = createClientByAdmin(realm, generateSuffixedName("wildcard-allowed"), SamlProtocol.LOGIN_PROTOCOL,
                client -> client.setRedirectUris(List.of("https://localhost/*")));
        updateClientByAdmin(realm, id, client -> client.setRedirectUris(List.of("https://localhost/updated/*")));
    }

    @Test
    public void secureClientUrisMustCheckPartialSamlUpdates() throws Exception {
        setupPolicy(realm, SecureClientUrisExecutorFactory.PROVIDER_ID, new SecureClientUrisExecutor.Configuration(),
                AnyClientConditionFactory.PROVIDER_ID, new ClientPolicyConditionConfigurationRepresentation());
        String id = createClientByAdmin(realm, generateSuffixedName("partial-saml"), SamlProtocol.LOGIN_PROTOCOL,
                client -> client.setRedirectUris(List.of("https://localhost/callback")));
        var resource = realm.admin().clients().get(id);
        for (String attribute : List.of(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL,
                SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE)) {
            var update = new ClientRepresentation();
            update.setAttributes(Map.of(attribute, "http://localhost/endpoint"));
            assertThrows(BadRequestException.class, () -> resource.update(update));
            assertNotEquals("http://localhost/endpoint", resource.toRepresentation().getAttributes().get(attribute));

            update.setAttributes(Map.of(attribute, "https://localhost/endpoint"));
            resource.update(update);
            assertEquals("https://localhost/endpoint", resource.toRepresentation().getAttributes().get(attribute));
            assertEquals(SamlProtocol.LOGIN_PROTOCOL, resource.toRepresentation().getProtocol());
        }
    }

    private void setupPolicy(boolean allowWildcards) throws Exception {
        setupPolicy(realm, SamlSecureClientUrisExecutorFactory.PROVIDER_ID,
                new SamlSecureClientUrisExecutor.Configuration(allowWildcards),
                AnyClientConditionFactory.PROVIDER_ID, new ClientPolicyConditionConfigurationRepresentation());
    }
}
