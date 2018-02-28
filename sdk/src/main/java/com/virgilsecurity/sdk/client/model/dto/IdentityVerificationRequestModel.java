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

import java.util.Map;

import com.google.gson.annotations.SerializedName;

/**
 * Represents Virgil verify request.
 * 
 * @author Andrii Iakovenko
 *
 */
public class IdentityVerificationRequestModel {

    @SerializedName("type")
    private String identityType;

    @SerializedName("value")
    private String identity;

    @SerializedName("extra_fields")
    private Map<String, String> extraFields;

    /**
     * Create new instance of {@link IdentityVerificationRequestModel}. 
     */
    public IdentityVerificationRequestModel() {
    }

    /**
     * Create new instance of {@link IdentityVerificationRequestModel}.
     * @param idenity The identity.
     * @param identityType The identity type.
     * @param extraFields The extra fields.
     */
    public IdentityVerificationRequestModel(String idenity, String identityType, Map<String, String> extraFields) {
        this.identity = idenity;
        this.identityType = identityType;
        this.extraFields = extraFields;
    }

    /**
     * @return the identity type.
     */
    public String getIdentityType() {
        return identityType;
    }

    /**
     * @param identityType
     *            the identity type to set.
     */
    public void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    /**
     * @return the identity
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * @param identity
     *            the identity to set
     */
    public void setIdentity(String identity) {
        this.identity = identity;
    }

    /**
     * @return the extra fields.
     */
    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    /**
     * @param extraFields
     *            the extra fields to set.
     */
    public void setExtraFields(Map<String, String> extraFields) {
        this.extraFields = extraFields;
    }

}
