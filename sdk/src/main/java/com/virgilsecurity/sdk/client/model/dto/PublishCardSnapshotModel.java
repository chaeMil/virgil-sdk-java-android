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

import java.util.HashMap;
import java.util.Map;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.CardInfoModel;
import com.virgilsecurity.sdk.client.model.CardScope;

/**
 * This class is DTO used for creating a new Virgil Card.
 *
 * @author Andrii Iakovenko
 *
 */
public class PublishCardSnapshotModel {

    @SerializedName("identity")
    private String identity;

    @SerializedName("identity_type")
    private String identityType;

    @SerializedName("public_key")
    private byte[] publicKeyData;

    @SerializedName("scope")
    private CardScope scope;

    @SerializedName("data")
    private Map<String, String> data;

    @SerializedName("info")
    private CardInfoModel info;

    /**
     * Create a new instance of {@code CreateCardModel}
     *
     */
    public PublishCardSnapshotModel() {
        this.data = new HashMap<>();
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
     * @return the identityType
     */
    public String getIdentityType() {
        return identityType;
    }

    /**
     * @param identityType
     *            the identityType to set
     */
    public void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    /**
     * @return the publicKey
     */
    public byte[] getPublicKeyData() {
        return publicKeyData;
    }

    /**
     * @param publicKey
     *            the publicKey to set
     */
    public void setPublicKeyData(byte[] publicKey) {
        this.publicKeyData = publicKey;
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

    /**
     * @return the data
     */
    public Map<String, String> getData() {
        return data;
    }

    /**
     * @param data
     *            the data to set
     */
    public void setData(Map<String, String> data) {
        this.data = data;
    }

    /**
     * @return the info
     */
    public CardInfoModel getInfo() {
        return info;
    }

    /**
     * @param info
     *            the info to set
     */
    public void setInfo(CardInfoModel info) {
        this.info = info;
    }

}
