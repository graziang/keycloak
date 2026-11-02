package org.keycloak.protocol.oidc.verifier;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.TokenVerifier;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;
import org.keycloak.representations.AccessToken;

/**
 * Provider allows to inject custom token verifiers, which will be used during verifications of Keycloak tokens (EG. during admin REST or account REST calls)
 */
public interface TokenVerifierProvider extends Provider {

    /**
     * Additional verifications of access token provided by this provider
     *
     * @param context for the token verification
     */
    void additionalAccessTokenVerifications(TokenVerifierProviderContext context);

    @Override
    default void close() {
    }

    /**
     * Describes in which context the access token is verified. Token verifiers can use it to decide whether particular
     * checks are relevant for the endpoint, which triggered the verification. For instance checks of sender-constrained
     * tokens (DPoP or OAuth 2.0 mutual TLS certificate bound access tokens) apply only when the token is really used as
     * the credential, which authorizes the current request.
     */
    enum CallingContext {

        /**
         * The access token is presented by its holder (usually in the {@code Authorization} header) as the credential,
         * which authorizes the current HTTP request. For example admin REST API, account REST API, userinfo endpoint or
         * dynamic client registration endpoint.
         */
        REQUEST_AUTHORIZATION,

        /**
         * The access token is sent as a request parameter and is inspected on behalf of another, separately
         * authenticated, party. For example token introspection endpoint or the CIBA authentication channel callback.
         * The caller of the endpoint is not required to be the holder of the token.
         */
        TOKEN_INSPECTION,

        /**
         * The access token is used as the {@code subject_token} or {@code actor_token} of a token exchange request.
         * Token exchange has its own rules for sender-constrained tokens, hence generic checks are skipped here.
         */
        TOKEN_EXCHANGE
    }

    // Add more fields if needed...

    /**
     * @param accessTokenVerifier verifier, where additional checks can be added
     * @param session current session
     * @param realm current realm
     * @param uriInfo URI info of the current request
     * @param rawAccessToken the serialized access token, which is being verified. Can be {@code null} if not available
     *                       (EG. when the token was not received in the serialized form)
     * @param callingContext context in which the token is verified. Never {@code null}
     */
    record TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm, UriInfo uriInfo,
                                        String rawAccessToken, CallingContext callingContext) {

        public TokenVerifierProviderContext {
            if (callingContext == null) {
                callingContext = CallingContext.REQUEST_AUTHORIZATION;
            }
        }

        public TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm, UriInfo uriInfo) {
            this(accessTokenVerifier, session, realm, uriInfo, null, CallingContext.REQUEST_AUTHORIZATION);
        }
    }
}
