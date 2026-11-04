package org.keycloak.protocol.oidc.verifier;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.MtlsHoKTokenUtil;

public class MtlsTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void additionalAccessTokenVerifications(TokenVerifier<AccessToken> verifier, TokenVerificationContext context) {
        // mTLS adds only a binding check against the certificate presented in the request.
    }

    @Override
    public void verifyTokenBinding(AccessToken token, TokenVerificationContext context) throws VerificationException {
        boolean certificateBound = token.getConfirmation() != null && token.getConfirmation().getCertThumbprint() != null;
        boolean certificateRequired = certificateBound;
        if (context.tokenUse().isResourceAuthorization()) {
            ClientModel client = context.realm().getClientByClientId(token.getIssuedFor());
            certificateRequired = certificateBound || (client != null && OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken());
        }
        if (certificateRequired && (!certificateBound || !MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, context.request(), context.session()))) {
            throw new TokenBindingException(Errors.NOT_ALLOWED, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
        }
    }
}
