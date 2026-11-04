package org.keycloak.protocol.oidc.verifier;

import java.util.Objects;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Request data shared by token validation and binding verification. It deliberately contains no verifier:
 * a grant can verify the binding of an already validated token after authorizing its use.
 *
 * @param tokenString the serialized token, required when verifying the access token hash in a resource proof
 * @param authorizationScheme the scheme used to present this token, not the scheme used for client authentication
 */
public record TokenVerificationContext(KeycloakSession session, RealmModel realm, UriInfo uriInfo, HttpRequest request,
                                       String tokenString, String authorizationScheme, TokenUse tokenUse) {

    public TokenVerificationContext {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(tokenUse, "tokenUse");
    }

    public enum TokenUse {
        /** Access token authenticating a resource request through the Authorization header. */
        RESOURCE_AUTHORIZATION,
        /** Access token in an UMA or broker parameter, independently of client authentication. */
        PARAMETER_AUTHORIZATION,
        /** Input to token exchange; the grant authorizes the client before verifying the binding. */
        TOKEN_EXCHANGE,
        /** Token status inspection by a caller that need not hold the token's key. */
        INTROSPECTION,
        /** Authentication channel credential, rather than an OAuth access token. */
        AUTHENTICATION_CHANNEL;

        public boolean isResourceAuthorization() {
            return this == RESOURCE_AUTHORIZATION || this == PARAMETER_AUTHORIZATION;
        }

        public boolean requiresProofOfPossession() {
            return isResourceAuthorization() || this == TOKEN_EXCHANGE;
        }
    }

    public static TokenVerificationContext forResource(KeycloakSession session, String tokenString, String authorizationScheme) {
        return fromSession(session, tokenString, authorizationScheme, TokenUse.RESOURCE_AUTHORIZATION);
    }

    public static TokenVerificationContext forTokenExchange(KeycloakSession session) {
        return fromSession(session, null, null, TokenUse.TOKEN_EXCHANGE);
    }

    public static TokenVerificationContext forIntrospection(KeycloakSession session) {
        return fromSession(session, null, null, TokenUse.INTROSPECTION);
    }

    public static TokenVerificationContext forAuthenticationChannel(KeycloakSession session) {
        return fromSession(session, null, null, TokenUse.AUTHENTICATION_CHANNEL);
    }

    private static TokenVerificationContext fromSession(KeycloakSession session, String tokenString, String authorizationScheme, TokenUse tokenUse) {
        return new TokenVerificationContext(session, session.getContext().getRealm(), session.getContext().getUri(),
                session.getContext().getHttpRequest(), tokenString, authorizationScheme, tokenUse);
    }
}
