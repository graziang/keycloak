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

package org.keycloak.protocol.oidc.tokenexchange;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.UserSessionManager;

import java.util.Arrays;
import java.util.List;

/**
 * Provider for external-internal token exchange
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ExternalToInternalTokenExchangeProvider extends StandardTokenExchangeProvider {

    @Override
    public boolean supports(TokenExchangeContext context) {
        return isExternalInternalTokenExchangeRequest(context);
    }

    @Override
    public int getVersion() {
        return 2;
    }

    @Override
    protected Response tokenExchange() {
        String subjectToken = context.getParams().getSubjectToken();
        String subjectTokenType = context.getParams().getSubjectTokenType();
        String subjectIssuer = getSubjectIssuer(this.context, subjectToken, subjectTokenType);
        return exchangeExternalToken(subjectIssuer, subjectToken);
    }

    @Override
    protected List<String> getSupportedOAuthResponseTokenTypes() {
        return Arrays.asList(OAuth2Constants.ACCESS_TOKEN_TYPE, OAuth2Constants.ID_TOKEN_TYPE);
    }

    @Override
    protected String getRequestedTokenType() {
        String requestedTokenType = params.getRequestedTokenType();
        if (requestedTokenType == null) {
            requestedTokenType = OAuth2Constants.ACCESS_TOKEN_TYPE;
            return requestedTokenType;
        }
        if (requestedTokenType.equals(OAuth2Constants.ACCESS_TOKEN_TYPE)
                || requestedTokenType.equals(OAuth2Constants.ID_TOKEN_TYPE)
                || requestedTokenType.equals(OAuth2Constants.SAML2_TOKEN_TYPE)) {
            return requestedTokenType;
        }

        event.detail(Details.REASON, "requested_token_type unsupported");
        event.error(Errors.INVALID_REQUEST);
        throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "requested_token_type unsupported", Response.Status.BAD_REQUEST);
    }

    protected Response exchangeExternalToken(String subjectIssuer, String subjectToken) {

        // try to find the IDP whose alias matches the issuer or the subject issuer in the form params.
        ExternalExchangeContext externalExchangeContext = this.locateExchangeExternalTokenByAlias(subjectIssuer);

        if (externalExchangeContext == null) {
            event.error(Errors.INVALID_ISSUER);
            throw new CorsErrorResponseException(cors, Errors.INVALID_ISSUER, "Invalid " + OAuth2Constants.SUBJECT_TOKEN_TYPE + " parameter", Response.Status.BAD_REQUEST);
        }
        BrokeredIdentityContext context = externalExchangeContext.provider().exchangeExternal(this, this.context);
        if (context == null) {
            event.error(Errors.INVALID_ISSUER);
            throw new CorsErrorResponseException(cors, Errors.INVALID_ISSUER, "Invalid " + OAuth2Constants.SUBJECT_TOKEN_TYPE + " parameter", Response.Status.BAD_REQUEST);
        }

        UserModel user = importUserFromExternalIdentity(context);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(realm, user, user.getUsername(), clientConnection.getRemoteHost(), "external-exchange", false, null, null);
        externalExchangeContext.provider().exchangeExternalComplete(userSession, context, formParams);

        // this must exist so that we can obtain access token from user session if idp's store tokens is off
        userSession.setNote(IdentityProvider.EXTERNAL_IDENTITY_PROVIDER, externalExchangeContext.idpModel().getAlias());
        userSession.setNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, subjectToken);

        context.addSessionNotesToUserSession(userSession);

        return exchangeClientToClient(user, userSession, null, false);
    }

    protected String getSubjectIssuer(TokenExchangeContext context, String subjectToken, String subjectTokenType) {
        String subjectIssuer = context.getFormParams().getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
        if (subjectIssuer != null && subjectIssuer.startsWith(Constants.TOKEN_EXCHANGE_EXTERNAL_IDP_URN_PREFIX) && subjectIssuer.length() > Constants.TOKEN_EXCHANGE_EXTERNAL_IDP_URN_PREFIX.length()) {
            return subjectIssuer.substring(Constants.TOKEN_EXCHANGE_EXTERNAL_IDP_URN_PREFIX.length() );
        }
        if (OAuth2Constants.JWT_TOKEN_TYPE.equals(subjectTokenType)) {
            try {
                JWSInput jws = new JWSInput(subjectToken);
                JsonWebToken jwt = jws.readJsonContent(JsonWebToken.class);
                return jwt.getIssuer();
            } catch (JWSInputException e) {
                context.getEvent().detail(Details.REASON, "unable to parse jwt subject_token");
                context.getEvent().error(Errors.INVALID_TOKEN);
                throw new CorsErrorResponseException(context.getCors(), OAuthErrorException.INVALID_REQUEST, "Invalid token type, must be access token", Response.Status.BAD_REQUEST);
            }
        }

        try {
            UriUtils.checkUrl(SslRequired.EXTERNAL, subjectIssuer, subjectIssuer);
            return subjectIssuer;
        }
        catch (Exception e) {
            return null;
        }
    }

}
