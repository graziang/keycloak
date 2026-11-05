package org.keycloak.protocol.oidc.verifier;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
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
     * Verifies that whoever presented the token holds the key the token is bound to.
     * <p>
     * Called while the token is verified when the context requires the proof of possession, and called by the caller
     * itself when the context defers it.
     *
     * @param token the token that was verified
     * @param context for the token verification
     */
    default void verifyTokenBinding(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
    }

    @Override
    default void close() {
    }

    /**
     * How the access token reached the server.
     */
    enum TokenPresentation {

        /**
         * Presented as a credential to a protected resource. A bound access token is accepted only with the DPoP
         * authorization scheme, as required by RFC 9449, Section 7.1, which rules out the ways of sending a bearer
         * token described in RFC 6750, Sections 2.2 and 2.3.
         */
        PROTECTED_RESOURCE,

        /**
         * Passed as a parameter of a grant, which authenticates the client by its own means. The authorization scheme
         * describes those credentials rather than the token, so the proof is matched to the token by its hash.
         */
        GRANT_PARAMETER
    }

    /**
     * Whether whoever presented the token has to prove possession of the key the token is bound to.
     */
    enum ProofOfPossession {

        /**
         * Proven while the token is verified.
         */
        REQUIRED,

        /**
         * Proven once the caller has authorized the request, as token exchange does.
         */
        DEFERRED,

        /**
         * Not proven, because the caller is not the holder of the token, as for introspection, where the confirmation
         * claim is returned to the resource server so that it can verify the proof itself, or because the token is not
         * an OAuth access token, as for the CIBA authentication channel.
         */
        NOT_APPLICABLE
    }

    /**
     * The realm, the URI and the request default to the ones of the session context when not set.
     *
     * @param tokenString the serialized token, required to verify a DPoP proof against its hash
     * @param authorizationScheme the scheme of the Authorization header, or {@code null} when the token did not arrive in that header
     */
    record TokenVerifierProviderContext(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session, RealmModel realm,
                                        UriInfo uriInfo, HttpRequest request, String tokenString, String authorizationScheme,
                                        TokenPresentation presentation, ProofOfPossession proofOfPossession) {

        public static Builder builder(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session) {
            return new Builder(accessTokenVerifier, session);
        }

        @Override
        public RealmModel realm() {
            return realm != null ? realm : session.getContext().getRealm();
        }

        @Override
        public UriInfo uriInfo() {
            return uriInfo != null ? uriInfo : session.getContext().getUri();
        }

        @Override
        public HttpRequest request() {
            return request != null ? request : session.getContext().getHttpRequest();
        }

        /**
         * The client the token was issued for, or {@code null} if it no longer exists.
         */
        public ClientModel client(AccessToken token) {
            RealmModel realm = realm();
            return realm == null ? null : realm.getClientByClientId(token.getIssuedFor());
        }

        public static final class Builder {

            private final TokenVerifier<AccessToken> accessTokenVerifier;
            private final KeycloakSession session;
            private RealmModel realm;
            private UriInfo uriInfo;
            private HttpRequest request;
            private String tokenString;
            private String authorizationScheme;
            private TokenPresentation presentation = TokenPresentation.PROTECTED_RESOURCE;
            private ProofOfPossession proofOfPossession = ProofOfPossession.REQUIRED;

            private Builder(TokenVerifier<AccessToken> accessTokenVerifier, KeycloakSession session) {
                this.accessTokenVerifier = accessTokenVerifier;
                this.session = session;
            }

            public Builder realm(RealmModel realm) {
                this.realm = realm;
                return this;
            }

            public Builder uriInfo(UriInfo uriInfo) {
                this.uriInfo = uriInfo;
                return this;
            }

            public Builder request(HttpRequest request) {
                this.request = request;
                return this;
            }

            public Builder tokenString(String tokenString) {
                this.tokenString = tokenString;
                return this;
            }

            public Builder authorizationScheme(String authorizationScheme) {
                this.authorizationScheme = authorizationScheme;
                return this;
            }

            public Builder presentation(TokenPresentation presentation) {
                this.presentation = presentation;
                return this;
            }

            public Builder proofOfPossession(ProofOfPossession proofOfPossession) {
                this.proofOfPossession = proofOfPossession;
                return this;
            }

            public TokenVerifierProviderContext build() {
                return new TokenVerifierProviderContext(accessTokenVerifier, session, realm, uriInfo, request, tokenString,
                        authorizationScheme, presentation, proofOfPossession);
            }
        }
    }
}
