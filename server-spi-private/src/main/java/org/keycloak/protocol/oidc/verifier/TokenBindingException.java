package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;

/** A binding failure with the event error to report, independent of the binding mechanism. */
public class TokenBindingException extends VerificationException {

    private final String error;

    public TokenBindingException(String error, String message) {
        super(message);
        this.error = error;
    }

    public TokenBindingException(String error, VerificationException cause) {
        super(cause.getMessage(), cause);
        this.error = error;
    }

    public String getError() {
        return error;
    }
}
