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

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.exceptions.TokenVerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.MtlsHoKTokenUtil;

/**
 * Verifies OAuth 2.0 Mutual TLS certificate bound access tokens (RFC 8705) whenever the access token is used as the
 * credential authorizing the current request. Registering this as a {@link TokenVerifierProvider} makes every endpoint,
 * which validates access tokens through the {@link TokenVerifierProviderManager}, enforce the certificate binding
 * without any endpoint specific code.
 *
 * @author <a href="mailto:ggrazian@redhat.com">Giuseppe Graziano</a>
 */
public class MtlsHoKTokenVerifierProvider implements TokenVerifierProvider {

    private final KeycloakSession session;

    public MtlsHoKTokenVerifierProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void additionalAccessTokenVerifications(TokenVerifierProviderContext context) {
        // The certificate binding constrains the party, which presents the token. It is therefore validated only when
        // the token is used as the credential of the current request. Token introspection and token exchange have
        // their own rules.
        if (context.callingContext() != CallingContext.REQUEST_AUTHORIZATION) {
            return;
        }

        HttpRequest request = session.getContext().getHttpRequest();
        if (request == null) {
            return;
        }

        RealmModel realm = context.realm();
        context.accessTokenVerifier().withChecks(new MtlsHoKTokenCheck(session, realm, request));
    }

    private record MtlsHoKTokenCheck(KeycloakSession session, RealmModel realm,
                                     HttpRequest request) implements TokenVerifier.Predicate<AccessToken> {

        @Override
        public boolean test(AccessToken token) throws VerificationException {
            AccessToken.Confirmation confirmation = token.getConfirmation();
            boolean certificateBoundToken = confirmation != null && confirmation.getCertThumbprint() != null;

            if (!certificateBoundToken && !isMtlsHoKTokenRequiredByClient(token)) {
                return true;
            }

            if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, request, session)) {
                throw new TokenVerificationException(token, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
            }

            return true;
        }

        private boolean isMtlsHoKTokenRequiredByClient(AccessToken token) {
            String clientId = token.getIssuedFor();
            if (clientId == null) {
                return false;
            }
            ClientModel client = realm.getClientByClientId(clientId);
            return client != null && OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken();
        }
    }
}
