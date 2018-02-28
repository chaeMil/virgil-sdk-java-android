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
package com.virgilsecurity.sdk.client.model.dto;

import java.util.Collection;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.CardScope;

/**
 * Performs the search of a Virgil Cards by search criteria:
 * <ul>
 * <li>the {@code identities} request parameter is mandatory.</li>
 * <li>the {@code type} optional request parameter is optional and specifies the identity type of a Virgil Card.</li>
 * <li>the {@code scope} optional request parameter specifies the scope to perform search on. Either 'global' or
 * 'application'. The default value is "application".</li>
 * <li>the {@code confirmed} optional request parameter specifies whether apply filtering on 'is_confirmed' parameter or
 * not.</li>
 * </ul>
 *
 * @author Andrii Iakovenko
 *
 */
public class SearchRequest {

    @SerializedName("identities")
    private Collection<String> identities;

    @SerializedName("identity_type")
    private String identityType;

    @SerializedName("is_confirmed")
    private Boolean confirmed;

    @SerializedName("scope")
    private CardScope scope;

    /**
     * Create a new instance of {@code SearchRequest}
     *
     */
    public SearchRequest() {
    }

    /**
     * @return the identities
     */
    public Collection<String> getIdentities() {
        return identities;
    }

    /**
     * @param identities
     *            the identities to set
     */
    public void setIdentities(Collection<String> identities) {
        this.identities = identities;
    }

    /**
     * @return the type
     */
    public String getIdentityType() {
        return identityType;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setIdentityType(String type) {
        this.identityType = type;
    }

    /**
     * @return the confirmed
     */
    public Boolean getConfirmed() {
        return confirmed;
    }

    /**
     * @param confirmed
     *            the confirmed to set
     */
    public void setConfirmed(Boolean confirmed) {
        this.confirmed = confirmed;
    }

    /**
     * @return the scope
     */
    public CardScope getScope() {
        return scope;
    }

    /**
     * @param scope
     *            the scope to set
     */
    public void setScope(CardScope scope) {
        this.scope = scope;
    }

}
