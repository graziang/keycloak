package org.keycloak.protocol.oidc.verifier;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.http.HttpRequest;
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
    default void additionalAccessTokenVerifications(TokenVerifierProviderContext context) {
    }

    /**
     * Verifies the binding after token validation. Resource requests invoke this automatically;
     * token exchange invokes it after authorizing the requesting client. Introspection and CIBA callbacks skip it.
     */
    default void verifyTokenBinding(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
    }

    @Override
    default void close() {
    }

    enum TokenVerificationContext {
        /** Access token supplied in the Authorization header of a resource request. */
        RESOURCE,
        /** Access token supplied in a form parameter, independently of client authentication. */
        RESOURCE_WITH_FORM_TOKEN,
        /** Token status inspection without proof of possession from the token holder. */
        INTROSPECTION,
        /** Binding is verified after the grant authorizes exchange by the requesting client. */
        TOKEN_EXCHANGE,
        /** Authentication channel token, rather than an OAuth access token. */
        CIBA_CALLBACK;

        public boolean isResourceRequest() {
            return this == RESOURCE || this == RESOURCE_WITH_FORM_TOKEN;
        }

        public boolean requiresProofOfPossession() {
            return isResourceRequest() || this == TOKEN_EXCHANGE;
        }
    }

    /**
     * The serialized token is required for resource DPoP proofs to verify the {@code ath} claim.
     */
    record TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm,
                                        UriInfo uriInfo, String tokenString, TokenVerificationContext verificationContext, HttpRequest request) {
        public TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm,
                                            UriInfo uriInfo, String tokenString, TokenVerificationContext verificationContext) {
            this(accessTokenVerifier, session, realm, uriInfo, tokenString, verificationContext, session.getContext().getHttpRequest());
        }

        /** Compatibility constructor. Resource DPoP validation requires the overload accepting the serialized token. */
        public TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm, UriInfo uriInfo) {
            this(accessTokenVerifier, session, realm, uriInfo, null, TokenVerificationContext.RESOURCE);
        }
    }
}
