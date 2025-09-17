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

package org.keycloak.services.clientpolicy.executor;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.common.Profile;
import org.keycloak.common.Profile.Feature;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DPoPBindEnforcerExecutorFactory  implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "dpop-bind-enforcer";

    public static final String AUTO_CONFIGURE = "auto-configure";

    public static final String ALLOW_ONLY_REFRESH_BINDING = "allow-only-refresh-token-binding";

    private static final ProviderConfigProperty AUTO_CONFIGURE_PROPERTY = new ProviderConfigProperty(
            AUTO_CONFIGURE, "Auto-configure", "If On, then the during client creation or update, the configuration of the client will be auto-configured to use DPoP bind token", ProviderConfigProperty.BOOLEAN_TYPE, false);

    private static final ProviderConfigProperty ALLOW_ONLY_REFRESH_BINDING_PROPERTY = new ProviderConfigProperty(
            ALLOW_ONLY_REFRESH_BINDING, "Allow Only refresh token binding", "If On and the client is public the DPoP binding is enforced only for refresh token, this option is ignored if the DPoP is enforced in client settings",
            ProviderConfigProperty.BOOLEAN_TYPE, false);


    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session) {
        return new DPoPBindEnforcerExecutor(session);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "It enforces a client to enable DPoP bind token setting and  can be also used to enable DPoP binding only for refresh token when the client is public.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(AUTO_CONFIGURE_PROPERTY, ALLOW_ONLY_REFRESH_BINDING_PROPERTY);
    }
}
