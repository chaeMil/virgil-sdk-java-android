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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * The Raw signed model.
 */
public class RawSignedModel {

    @SerializedName("content_snapshot")
    private byte[] contentSnapshot;

    @SerializedName("signatures")
    private List<RawSignature> signatures;

    /**
     * Instantiates a new Raw signed model.
     *
     * @param contentSnapshot the content snapshot
     */
    public RawSignedModel(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;

        signatures = new ArrayList<>();
    }

    /**
     * Instantiates a new Raw signed model.
     *
     * @param contentSnapshot the content snapshot
     * @param signatures      the list of signatures
     */
    public RawSignedModel(byte[] contentSnapshot,
                          List<RawSignature> signatures) {
        this.contentSnapshot = contentSnapshot;
        this.signatures = signatures;
    }

    /**
     * Get content snapshot.
     *
     * @return the byte [ ]
     */
    public byte[] getContentSnapshot() {
        return contentSnapshot;
    }

    /**
     * Sets content snapshot.
     *
     * @param contentSnapshot the content snapshot
     */
    public void setContentSnapshot(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Gets list of signatures.
     *
     * @return the signatures
     */
    public List<RawSignature> getSignatures() {
        return signatures;
    }

    /**
     * Sets list of signatures.
     *
     * @param signatures the list of signatures
     */
    public void setSignatures(List<RawSignature> signatures) {
        this.signatures = signatures;
    }

    /**
     * Export as base64 string.
     *
     * @return the string
     * @throws IOException the io exception
     */
    public String exportAsString() throws IOException {
        return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(this));
    }

    /**
     * Export as json in string format.
     *
     * @return the string
     * @throws IOException the io exception
     */
    public String exportAsJson() throws IOException {
        return ConvertionUtils.serializeToJson(this);
    }

    /**
     * Instantiate {@link RawSignedModel} from provided base64 string.
     *
     * @param cardModel the card model
     * @return the raw signed model
     */
    public static RawSignedModel fromString(String cardModel) {
        return ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(cardModel), RawSignedModel.class);
    }

    /**
     * Instantiate {@link RawSignedModel} from provided string.
     *
     * @param cardModel the card model
     * @return the raw signed model
     */
    public static RawSignedModel fromJson(String cardModel) {
        return ConvertionUtils.deserializeFromJson(cardModel, RawSignedModel.class);
    }
}
