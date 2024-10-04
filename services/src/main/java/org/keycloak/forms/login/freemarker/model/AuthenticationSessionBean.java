/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.forms.login.freemarker.model;

import org.keycloak.common.util.Base64;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;
import java.nio.charset.StandardCharsets;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticationSessionBean {

    private final String authSessionId;

    private final String authSessionIdHash;

    private final String tabId;

    public AuthenticationSessionBean(String authSessionId, String tabId) {
        this.authSessionId = authSessionId;
        this.tabId = tabId;
        this.authSessionIdHash = Base64.encodeBytes(HashUtils.hash(JavaAlgorithm.SHA256, authSessionId.getBytes(StandardCharsets.UTF_8)));
    }

    public String getAuthSessionId() {
        return authSessionId;
    }

    public String getTabId() {
        return tabId;
    }

    public String getAuthSessionIdHash() {
        return authSessionIdHash;
    }
}
