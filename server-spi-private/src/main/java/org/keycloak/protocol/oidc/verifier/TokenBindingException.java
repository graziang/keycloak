package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;

/**
 * Thrown when whoever presented an access token did not prove possession of the key the token is bound to.
 * <p>
 * Carries the error to report, so that a caller can record the outcome without knowing which binding mechanism failed.
 */
public class TokenBindingException extends VerificationException {

    private final String error;

    public TokenBindingException(String error, String message) {
        super(message);
        this.error = error;
    }

    /**
     * The error to report, as defined in {@code org.keycloak.events.Errors}.
     */
    public String getError() {
        return error;
    }
}
