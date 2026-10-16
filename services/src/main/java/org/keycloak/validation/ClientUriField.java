/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.validation;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.keycloak.models.CibaConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.idm.ClientRepresentation;

/**
 * Shared metadata for client URI validation. Field names are also used in client policy configuration;
 * field IDs and message keys preserve the errors exposed by the default client validator.
 */
public enum ClientUriField {
    ROOT_URL("rootUrl", Source.ROOT, null, true, "rootUrl",
            "Root URL is not a valid URL", "clientRootURLInvalid",
            "Root URL must not contain an URL fragment", "clientRootURLFragmentError",
            "Root URL uses an illegal scheme", "clientRootURLIllegalSchemeError", "Root URL"),

    BASE_URL("baseUrl", Source.BASE, null, true, "baseUrl",
            "Base URL is not a valid URL", "clientBaseURLInvalid",
            null, null,
            "Base URL uses an illegal scheme", "clientBaseURLIllegalSchemeError", "Home URL"),

    REDIRECT_URIS("redirectUris", Source.REDIRECTS, null, true, "redirectUris",
            "A redirect URI is not a valid URI", "clientRedirectURIsInvalid",
            "A redirect URI must not contain an URL fragment", "clientRedirectURIsFragmentError",
            "A redirect URI uses an illegal scheme", "clientRedirectURIsIllegalSchemeError", "Valid redirect URIs"),

    POST_LOGOUT_REDIRECT_URIS("postLogoutRedirectUris", Source.MULTIVALUED, OIDCConfigAttributes.POST_LOGOUT_REDIRECT_URIS, true, "postLogoutUris",
            "A post-logout redirect URI is not a valid URI", "clientPostLogoutRedirectURIsInvalid",
            "A post-logout redirect URI must not contain an URL fragment", "clientPostLogoutRedirectURIsFragmentError",
            "A post-logout redirect URI uses an illegal scheme", "clientPostLogoutRedirectURIsIllegalSchemeError"),

    REQUEST_URIS("requestUris", Source.MULTIVALUED, OIDCConfigAttributes.REQUEST_URIS, true, "requestUris",
            "Valid request URIs has an invalid value", "requestUrisAreInvalid",
            null, null,
            "Valid request URIs has a value with illegal scheme", "requestUrisHasIllegalSchemeError"),

    BACKCHANNEL_LOGOUT_URL("backchannelLogoutUrl", Source.ATTRIBUTE, OIDCConfigAttributes.BACKCHANNEL_LOGOUT_URL, true, "backchannelLogoutUrl",
            "Backchannel logout URL is not a valid URL", "backchannelLogoutUrlIsInvalid",
            null, null,
            "Backchannel logout URL uses an illegal scheme", "backchannelLogoutUrlIllegalSchemeError"),

    LOGO_URI("logoUri", Source.ATTRIBUTE, ClientModel.LOGO_URI, false, ClientModel.LOGO_URI,
            "Logo URL is not a valid URL", "logoURLInvalid",
            null, null,
            "Logo URL uses an illegal scheme", "logoURLIllegalSchemeError"),

    POLICY_URI("policyUri", Source.ATTRIBUTE, ClientModel.POLICY_URI, false, ClientModel.POLICY_URI,
            "Policy URL is not a valid URL", "policyURLInvalid",
            null, null,
            "Policy URL uses an illegal scheme", "policyURLIllegalSchemeError"),

    TOS_URI("tosUri", Source.ATTRIBUTE, ClientModel.TOS_URI, false, ClientModel.TOS_URI,
            "Terms of service URL is not a valid URL", "tosURLInvalid",
            null, null,
            "Terms of service URL uses an illegal scheme", "tosURLIllegalSchemeError"),

    ADMIN_URL("adminUrl", Source.ADMIN, null, true, "adminUrl",
            "Admin URL is not a valid URL", "adminURLInvalid",
            null, null,
            "Admin URL uses an illegal scheme", "adminURLIllegalSchemeError"),

    JWKS_URL("jwksUri", Source.ATTRIBUTE, OIDCConfigAttributes.JWKS_URL, true, "jwksUrl",
            "JWKS URL is not a valid URL", "jwksURLInvalid",
            null, null,
            "JWKS URL uses an illegal scheme", "jwksURLIllegalSchemeError"),

    FRONTCHANNEL_LOGOUT_URL("frontChannelLogoutUrl", Source.ATTRIBUTE, OIDCConfigAttributes.FRONT_CHANNEL_LOGOUT_URI, true, "frontchannelLogoutUrl",
            "Front-channel logout URL is not a valid URL", "frontchannelLogoutUrlInvalid",
            null, null,
            "Front-channel logout URL uses an illegal scheme", "frontchannelLogoutUrlIllegalSchemeError"),

    SAML_ADMIN_URL("adminUrl", Source.ADMIN, null, false, "masterSamlProcessingUrl",
            "Master SAML Processing URL is not a valid URL", "adminUrlURLInvalid",
            null, null,
            "Master SAML Processing URL uses an illegal scheme", "adminUrlURLIllegalSchemeError", "Master SAML Processing URL"),

    SAML_ASSERTION_CONSUMER_URL_POST_URI(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, false, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
            "Assertion Consumer Service POST Binding URL is not a valid URL", "samlAssertionConsumerUrlPostURLInvalid",
            null, null,
            "Assertion Consumer Service POST Binding URL uses an illegal scheme", "samlAssertionConsumerUrlPostURLIllegalSchemeError", "Assertion Consumer Service POST Binding URL"),

    SAML_ASSERTION_CONSUMER_URL_REDIRECT_URI(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE, false, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE,
            "Assertion Consumer Service Redirect Binding URL is not a valid URL", "samlAssertionConsumerUrlRedirectURLInvalid",
            null, null,
            "Assertion Consumer Service Redirect Binding URL uses an illegal scheme", "samlAssertionConsumerUrlRedirectURLIllegalSchemeError", "Assertion Consumer Service Redirect Binding URL"),

    SAML_ASSERTION_CONSUMER_URL_ARTIFACT_URI(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_ARTIFACT_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_ARTIFACT_ATTRIBUTE, false, SamlProtocol.SAML_ASSERTION_CONSUMER_URL_ARTIFACT_ATTRIBUTE,
            "Artifact Binding URL is not a valid URL", "samlAssertionConsumerUrlArtifactURLInvalid",
            null, null,
            "Artifact Binding URL uses an illegal scheme", "samlAssertionConsumerUrlArtifactURLIllegalSchemeError", "Artifact Binding URL"),

    SAML_SINGLE_LOGOUT_SERVICE_URL_POST_URI(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, false, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE,
            "Logout Service POST Binding URL is not a valid URL", "samlLogoutServiceUrlPostURLInvalid",
            null, null,
            "Logout Service POST Binding URL uses an illegal scheme", "samlLogoutServiceUrlPostURLIllegalSchemeError", "Logout Service POST Binding URL"),

    SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_URI(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE, false, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE,
            "Logout Service ARTIFACT Binding URL is not a valid URL", "samlLogoutServiceUrlArtifactURLInvalid",
            null, null,
            "Logout Service ARTIFACT Binding URL uses an illegal scheme", "samlLogoutServiceUrlArtifactURLIllegalSchemeError", "Logout Service ARTIFACT Binding URL"),

    SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_URI(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE, false, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE,
            "Logout Service Redirect Binding URL is not a valid URL", "samlLogoutServiceUrlRedirectURLInvalid",
            null, null,
            "Logout Service Redirect Binding URL uses an illegal scheme", "samlLogoutServiceUrlRedirectURLIllegalSchemeError", "Logout Service Redirect Binding URL"),

    SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_URI(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE, false, SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE,
            "Logout Service SOAP Binding URL is not a valid URL", "samlLogoutServiceUrlSoapURLInvalid",
            null, null,
            "Logout Service SOAP Binding URL uses an illegal scheme", "samlAssertionConsumerUrlPostURLIllegalSchemeError", "Logout Service SOAP Binding URL"),

    SAML_ARTIFACT_RESOLUTION_SERVICE_URL_URI(SamlProtocol.SAML_ARTIFACT_RESOLUTION_SERVICE_URL_ATTRIBUTE, Source.ATTRIBUTE, SamlProtocol.SAML_ARTIFACT_RESOLUTION_SERVICE_URL_ATTRIBUTE, false, SamlProtocol.SAML_ARTIFACT_RESOLUTION_SERVICE_URL_ATTRIBUTE,
            "Artifact Resolution Service is not a valid URL", "samlAssertionConsumerUrlPostURLInvalid",
            null, null,
            "Artifact Resolution Service uses an illegal scheme", "samlAssertionConsumerUrlPostURLIllegalSchemeError", "Artifact Resolution Service"),

    SAML_METADATA_DESCRIPTOR_URL(SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, Source.ATTRIBUTE, SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, false, SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL,
            "Metadata descriptor URL is not a valid URL", SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL,
            null, null,
            "Metadata descriptor URL uses an illegal scheme", SamlConfigAttributes.SAML_METADATA_DESCRIPTOR_URL, "Metadata descriptor URL"),

    WEB_ORIGINS("webOrigins", Source.ORIGINS, null, false, "webOrigins",
            "A web origin is not a valid URI", "webOriginsInvalid", null, null,
            "A web origin uses an illegal scheme", "webOriginsIllegalSchemeError"),

    CIBA_NOTIFICATION_ENDPOINT("cibaClientNotificationEndpoint", Source.ATTRIBUTE, CibaConfig.CIBA_BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT, false, "cibaBackchannelClientNotificationEndpoint",
            "CIBA notification endpoint is not a valid URL", "invalidBackchannelClientNotificationEndpoint", null, null,
            "CIBA notification endpoint uses an illegal scheme", "invalidBackchannelClientNotificationEndpoint"),

    SECTOR_IDENTIFIER_URI("sectorIdentifierUri", Source.ATTRIBUTE, OIDCConfigAttributes.SECTOR_IDENTIFIER_URI, false, "sectorIdentifierUri",
            "Sector identifier URI is not a valid URL", "sectorIdentifierUriInvalid", null, null,
            "Sector identifier URI uses an illegal scheme", "sectorIdentifierUriIllegalSchemeError");

    private enum Source {
        ROOT, BASE, ADMIN, REDIRECTS, ORIGINS, ATTRIBUTE, MULTIVALUED
    }

    private final String name;
    private final Source source;
    private final String attribute;
    private final boolean relative;
    private final String fieldId;
    private final String displayName;
    private final String invalid;
    private final String invalidKey;
    private final String fragment;
    private final String fragmentKey;
    private final String scheme;
    private final String schemeKey;

    ClientUriField(String name, Source source, String attribute, boolean relative, String fieldId,
                   String invalid, String invalidKey, String fragment, String fragmentKey, String scheme, String schemeKey) {
        this(name, source, attribute, relative, fieldId, invalid, invalidKey, fragment, fragmentKey, scheme, schemeKey, name);
    }

    ClientUriField(String name, Source source, String attribute, boolean relative, String fieldId,
                   String invalid, String invalidKey, String fragment, String fragmentKey, String scheme, String schemeKey, String displayName) {
        this.displayName = displayName;
        this.name = name;
        this.source = source;
        this.attribute = attribute;
        this.relative = relative;
        this.fieldId = fieldId;
        this.invalid = invalid;
        this.invalidKey = invalidKey;
        this.fragment = fragment;
        this.fragmentKey = fragmentKey;
        this.scheme = scheme;
        this.schemeKey = schemeKey;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getFieldId() {
        return fieldId;
    }

    public String getInvalid() {
        return invalid;
    }

    public String getInvalidKey() {
        return invalidKey;
    }

    public String getFragment() {
        return fragment;
    }

    public String getFragmentKey() {
        return fragmentKey;
    }

    public String getScheme() {
        return scheme;
    }

    public String getSchemeKey() {
        return schemeKey;
    }

    public boolean allowsRelativeUri() {
        return relative;
    }

    public boolean checksFragment() {
        return fragment != null;
    }

    public boolean requiresUrl() {
        return this != REDIRECT_URIS && this != POST_LOGOUT_REDIRECT_URIS && this != REQUEST_URIS && this != WEB_ORIGINS;
    }

    public boolean appliesTo(String protocol) {
        boolean saml = SamlProtocol.LOGIN_PROTOCOL.equals(protocol);
        return isSamlField() ? saml : this != ADMIN_URL || !saml;
    }

    /** A partial update retains the existing protocol when none is supplied. */
    public static String getEffectiveProtocol(ClientRepresentation proposedClient, ClientModel existingClient) {
        return proposedClient.getProtocol() == null && existingClient != null
                ? existingClient.getProtocol() : proposedClient.getProtocol();
    }

    public boolean isSamlField() {
        return name().startsWith("SAML_");
    }

    public static List<String> getNames() {
        return Arrays.stream(values()).map(ClientUriField::getName).distinct().toList();
    }

    public List<String> getValues(ClientRepresentation client) {
        return switch (source) {
            case ROOT -> singleton(client.getRootUrl());
            case BASE -> singleton(client.getBaseUrl());
            case ADMIN -> singleton(client.getAdminUrl());
            case REDIRECTS -> nonEmpty(client.getRedirectUris());
            case ORIGINS -> nonEmpty(client.getWebOrigins());
            case ATTRIBUTE, MULTIVALUED -> attributeValues(client.getAttributes() == null ? null : client.getAttributes().get(attribute));
        };
    }

    public List<String> getValues(ClientModel client) {
        return switch (source) {
            case ROOT -> singleton(client.getRootUrl());
            case BASE -> singleton(client.getBaseUrl());
            case ADMIN -> singleton(client.getManagementUrl());
            case REDIRECTS -> nonEmpty(client.getRedirectUris());
            case ORIGINS -> nonEmpty(client.getWebOrigins());
            case ATTRIBUTE, MULTIVALUED -> attributeValues(client.getAttribute(attribute));
        };
    }

    /** Resolve redirect references for policy checks; '-' disables post-logout redirects. */
    public List<String> getPolicyValues(KeycloakSession session, ClientRepresentation client) {
        List<String> uris = getValues(client);
        if (this == WEB_ORIGINS || this == POST_LOGOUT_REDIRECT_URIS) {
            uris = uris.stream().filter(u -> this != POST_LOGOUT_REDIRECT_URIS || !"-".equals(u)).toList();
            return List.copyOf(RedirectUtils.resolveUrlsWithRedirects(session, uris, client.getRootUrl(), client.getRedirectUris(), this == WEB_ORIGINS));
        }
        return uris;
    }

    public boolean isSpecialValue(String uri) {
        return (this == POST_LOGOUT_REDIRECT_URIS && ("+".equals(uri) || "-".equals(uri) || "*".equals(uri)))
                || (this == WEB_ORIGINS && ("+".equals(uri) || "*".equals(uri)));
    }

    private List<String> attributeValues(String value) {
        return source == Source.MULTIVALUED && value != null
                ? nonEmpty(Arrays.asList(Constants.CFG_DELIMITER_PATTERN.split(value))) : singleton(value);
    }

    private static List<String> singleton(String value) {
        return value == null || value.isEmpty() ? Collections.emptyList() : List.of(value);
    }

    private static List<String> nonEmpty(Collection<String> values) {
        return values == null ? Collections.emptyList() : values.stream().filter(v -> v != null && !v.isEmpty()).toList();
    }
}
