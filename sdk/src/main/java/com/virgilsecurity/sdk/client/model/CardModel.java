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
package com.virgilsecurity.sdk.client.model;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.client.model.dto.PublishCardSnapshotModel;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * The {@linkplain CardModel} class represents an information about Virgil Card entity.
 * 
 * @author Andrii Iakovenko
 *
 */
public class CardModel {

    @SerializedName("id")
    private String id;

    @SerializedName("content_snapshot")
    private byte[] snapshot;

    @SerializedName("meta")
    private CardMetaModel meta;

    private transient PublishCardSnapshotModel snapshotModel;

    /**
     * Create new instance of {@link CardModel}.
     */
    public CardModel() {
    }

    /**
     * Create new instance of {@link CardModel}.
     * 
     * @param snapshotModel The snapshot model.
     */
    public CardModel(PublishCardSnapshotModel snapshotModel) {
        this.snapshotModel = snapshotModel;
    }

    /**
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return the snapshot
     */
    public byte[] getSnapshot() {
        return snapshot;
    }

    /**
     * @param snapshot
     *            the snapshot to set
     */
    public void setSnapshot(byte[] snapshot) {
        this.snapshot = snapshot;
    }

    /**
     * @return the meta
     */
    public CardMetaModel getMeta() {
        if (meta == null) {
            meta = new CardMetaModel();
        }
        return meta;
    }

    /**
     * @param meta
     *            the meta to set
     */
    public void setMeta(CardMetaModel meta) {
        this.meta = meta;
    }

    /**
     * @return the snapshotModel
     */
    public PublishCardSnapshotModel getSnapshotModel() {
        if (this.snapshotModel != null || this.snapshot == null) {
            return this.snapshotModel;
        }

        String snapshotModelJson = ConvertionUtils.toString(this.snapshot);
        this.snapshotModel = ConvertionUtils.getGson().fromJson(snapshotModelJson, PublishCardSnapshotModel.class);

        return this.snapshotModel;
    }
}
