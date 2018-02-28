/*******************************************************************************
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package com.virgilsecurity.sdk.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * Virgil Client Context contains common configuration parameters of Virgil Client.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilClientContext {

    private static final String AUTH_SERVICE_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZzd0ZRWUhLb1pJemowQ0FRWUtLd1lCQkFHWFZRRUZBUU5DQUFRRGNONFR4endIV0VOR00zQmJxb1VuTWFVdQpLbTc4Sk9DWFhKN3I1ejdOalFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

    private String accessToken;

    private URL cardsServiceURL;

    private URL readOnlyCardsServiceURL;

    private URL identityServiceURL;

    private URL raServiceURL;

    private URL authServiceURL;

    /**
     * Create new instance of {@link VirgilClientContext}.
     */
    public VirgilClientContext() {
        try {
            this.cardsServiceURL = new URL("https://cards.virgilsecurity.com");
            this.readOnlyCardsServiceURL = new URL("https://cards-ro.virgilsecurity.com");
            this.identityServiceURL = new URL("https://identity.virgilsecurity.com");
            this.raServiceURL = new URL("https://ra.virgilsecurity.com");
            this.authServiceURL = new URL("https://auth.virgilsecurity.com");
        } catch (MalformedURLException e) {
            // This should never happen
        }
    }

    /**
     * Create a new instance of {@code VirgilClientContext}
     *
     * @param accessToken
     *            The application access token.
     */
    public VirgilClientContext(String accessToken) {
        this();
        this.accessToken = accessToken;
    }

    /**
     * Gets the access token.
     * 
     * @return the accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * @param accessToken
     *            the accessToken to set
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Verify is URI well-formed.
     * 
     * @param uri
     *            The URI to be verified.
     * @return {@code true} if URI is well-formed, {@code false} in other case.
     */
    public static boolean isValidURI(String uri) {
        if (StringUtils.isBlank(uri)) {
            return false;
        }
        try {
            URI theUri = URI.create(uri);
            return theUri.isAbsolute();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @return the readOnlyCardsServiceURL
     */
    public URL getReadOnlyCardsServiceURL() {
        return readOnlyCardsServiceURL;
    }

    /**
     * @param readOnlyCardsServiceURL
     *            the readOnlyCardsServiceURL to set
     */
    public void setReadOnlyCardsServiceURL(URL readOnlyCardsServiceURL) {
        this.readOnlyCardsServiceURL = readOnlyCardsServiceURL;
    }

    /**
     * @return the cardsServiceURL
     */
    public URL getCardsServiceURL() {
        return cardsServiceURL;
    }

    /**
     * @param cardsServiceURL
     *            the cardsServiceURL to set
     */
    public void setCardsServiceURL(URL cardsServiceURL) {
        this.cardsServiceURL = cardsServiceURL;
    }

    /**
     * @return the identityServiceURL
     */
    public URL getIdentityServiceURL() {
        return identityServiceURL;
    }

    /**
     * @param identityServiceURL
     *            the identityServiceURL to set
     */
    public void setIdentityServiceURL(URL identityServiceURL) {
        this.identityServiceURL = identityServiceURL;
    }

    /**
     * @return the raServiceURL
     */
    public URL getRaServiceURL() {
        return raServiceURL;
    }

    /**
     * @param raServiceURL
     *            the raServiceURL to set
     */
    public void setRaServiceURL(URL raServiceURL) {
        this.raServiceURL = raServiceURL;
    }

    /**
     * @return the authServiceURL
     */
    public URL getAuthServiceURL() {
        return authServiceURL;
    }

    /**
     * @param authServiceURL
     *            the authServiceURL to set
     */
    public void setAuthServiceURL(URL authServiceURL) {
        this.authServiceURL = authServiceURL;
    }

}
