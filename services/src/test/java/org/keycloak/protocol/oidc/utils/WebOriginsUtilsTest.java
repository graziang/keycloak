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
package org.keycloak.protocol.oidc.utils;

import java.lang.reflect.Proxy;
import java.util.Set;

import org.keycloak.models.ClientModel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class WebOriginsUtilsTest {

    @Test
    public void redirectReferenceIncludesOnlyHttpOrigins() {
        var client = client(Set.of("+", "https://explicit.example", "*", "null"),
                Set.of("https://redirect.example/callback", "HTTP://mixed.example/callback", "myapp:/callback"));
        assertEquals(Set.of("https://explicit.example", "*", "null", "https://redirect.example", "HTTP://mixed.example"),
                WebOriginsUtils.resolveValidWebOrigins(null, client));
    }

    @Test
    public void explicitOriginsDoNotIncludeRedirectsWithoutReference() {
        assertEquals(Set.of("https://explicit.example"), WebOriginsUtils.resolveValidWebOrigins(null,
                client(Set.of("https://explicit.example"), Set.of("https://redirect.example/callback"))));
    }

    @Test
    public void missingOriginsAndRedirectsAreSafe() {
        assertEquals(Set.of(), WebOriginsUtils.resolveValidWebOrigins(null, client(null, null)));
        assertEquals(Set.of(), WebOriginsUtils.resolveValidWebOrigins(null, client(Set.of("+"), null)));
    }

    private static ClientModel client(Set<String> origins, Set<String> redirects) {
        return (ClientModel) Proxy.newProxyInstance(WebOriginsUtilsTest.class.getClassLoader(), new Class<?>[]{ClientModel.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getWebOrigins" -> origins;
                    case "getRedirectUris" -> redirects;
                    case "getRootUrl" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
