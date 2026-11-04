package org.keycloak.protocol.oidc.verifier;

import org.keycloak.common.VerificationException;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.MtlsHoKTokenUtil;

public class MtlsTokenVerifierProvider implements TokenVerifierProvider {

    @Override
    public void verifyTokenBinding(AccessToken token, TokenVerifierProviderContext context) throws VerificationException {
        boolean certificateBound = token.getConfirmation() != null && token.getConfirmation().getCertThumbprint() != null;
        boolean certificateRequired = certificateBound;
        if (context.verificationContext().isResourceRequest()) {
            ClientModel client = context.realm().getClientByClientId(token.getIssuedFor());
            certificateRequired = certificateBound || (client != null && OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken());
        }
        if (certificateRequired && (!certificateBound || !MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, context.request(), context.session()))) {
            throw new VerificationException(MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
        }
    }
}
