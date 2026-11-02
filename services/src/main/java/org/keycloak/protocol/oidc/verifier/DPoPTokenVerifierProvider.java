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
package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.Profile;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.util.DPoPUtil;

/**
 * Verifies that DPoP bound access tokens (RFC 9449) are accompanied by a valid DPoP proof whenever the token is used as
 * the credential authorizing the current request. Registering this as a {@link TokenVerifierProvider} makes every
 * endpoint, which validates access tokens through the {@link TokenVerifierProviderManager}, enforce the DPoP binding
 * without any endpoint specific code.
 *
 * @author <a href="mailto:ggrazian@redhat.com">Giuseppe Graziano</a>
 */
public class DPoPTokenVerifierProvider implements TokenVerifierProvider {

    private final KeycloakSession session;

    public DPoPTokenVerifierProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void additionalAccessTokenVerifications(TokenVerifierProviderContext context) {
        if (!Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
            return;
        }

        // DPoP binds the token to the party, which presents it. It is therefore validated only when the token is used
        // as the credential of the current request. Token introspection and token exchange have their own rules.
        if (context.callingContext() != CallingContext.REQUEST_AUTHORIZATION) {
            return;
        }

        HttpRequest request = session.getContext().getHttpRequest();
        if (request == null) {
            return;
        }

        DPoPUtil.Validator validator = new DPoPUtil.Validator(session)
                .request(request)
                .accessToken(context.rawAccessToken());
        if (context.uriInfo() != null) {
            validator.uriInfo(context.uriInfo());
        }

        DPoPUtil.withDPoPVerifier(context.accessTokenVerifier(), context.realm(), validator);
    }
}
