/*
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
 */

package com.virgilsecurity.sdk.cards.model;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.io.IOException;
import java.util.Date;

public class RawCardContent {

    @SerializedName("identity")
    private String identity;

    @SerializedName("public_key")
    private String publicKey;

    @SerializedName("version")
    private String version;

    @SerializedName("created_at")
    private long createdAt;

    @SerializedName("previous_card_id")
    private String previousCardId;

    public RawCardContent() {

    }

    public RawCardContent(String identity, String publicKey, String version, Date createdAt) {
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt.getTime() / 1000;
    }

    public RawCardContent(String identity,
                          String publicKey,
                          String version,
                          Date createdAt,
                          String previousCardId) {
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt.getTime() / 1000;
        this.previousCardId = previousCardId;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKeyData) {
        this.publicKey = publicKeyData;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Date getCreatedAtDate() {
        return new Date(createdAt * 1000);
    }

    public void setCreatedAtDate(Date createdAt) {
        this.createdAt = createdAt.getTime() / 1000;
    }

    /**
     *
     * @return in seconds (Unix time)
     */
    public long getCreatedAtTimestamp() {
        return createdAt;
    }

    /**
     *
     * @param createdAt in seconds (Unix time)
     */
    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public String getPreviousCardId() {
        return previousCardId;
    }

    public void setPreviousCardId(String previousCardId) {
        this.previousCardId = previousCardId;
    }

    public String exportAsString() throws IOException {
        return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(this));
    }

    public String exportAsJson() throws IOException {
        return ConvertionUtils.serializeToJson(this);
    }

    public static RawCardContent fromString(String cardModel) {
        return ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(cardModel), RawCardContent.class);
    }

    public static RawCardContent fromJson(String cardModel) {
        return ConvertionUtils.deserializeFromJson(cardModel, RawCardContent.class);
    }
}
