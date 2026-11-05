package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.MtlsHoKTokenUtil;

public class MtlsTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void verifyTokenBinding(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
        boolean boundToken = token.getConfirmation() != null && token.getConfirmation().getCertThumbprint() != null;

        if (!boundToken && !clientRequiresCertificate(token, context)) {
            return;
        }
        if (!boundToken || !MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, context.request(), context.session())) {
            throw new TokenBindingException(Errors.NOT_ALLOWED, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
        }
    }

    /**
     * A client that issues certificate bound tokens also requires the certificate for the tokens it issued before the
     * setting was enabled, which carry no confirmation claim and could otherwise be replayed by disabling it again.
     */
    private boolean clientRequiresCertificate(AccessToken token, TokenVerifierProviderContext context) {
        if (context.proofOfPossession() != ProofOfPossession.REQUIRED) {
            return false;
        }
        ClientModel client = context.client(token);
        return client != null && OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken();
    }
}
