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
package com.virgilsecurity.sdk.client.requests;

import java.util.HashMap;
import java.util.Map;

import com.virgilsecurity.sdk.client.model.CardInfoModel;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.dto.PublishCardSnapshotModel;

/**
 * Request used for creating a Virgil Card.
 *
 * @author Andrii Iakovenko
 *
 */
public class PublishCardRequest extends GenericSignableRequest<PublishCardSnapshotModel> {

    /**
     * Create new instance of {@link PublishCardRequest} by specified snapshot and signatures.
     * 
     * @param snapshot
     *            The snapshot of the card request.
     * @param signatures
     *            The signatures.
     */
    public PublishCardRequest(byte[] snapshot, Map<String, byte[]> signatures) {
        this.takenSnapshot = snapshot;
        this.acceptedSignatures = new HashMap<>(signatures);
        this.type = PublishCardSnapshotModel.class;
    }

    /**
     * Create new instance of {@link PublishCardRequest}.
     * 
     * @param stringifiedRequest
     *            The stringified request.
     */
    public PublishCardRequest(String stringifiedRequest) {
        super(stringifiedRequest);
    }

    /**
     * Create a new instance of {@code CreateCardRequest}
     *
     * @param identity
     *            The identity.
     * @param identityType
     *            The identity type.
     * @param publicKeyData
     *            The public key DER.
     */
    public PublishCardRequest(String identity, String identityType, byte[] publicKeyData) {
        this(identity, identityType, publicKeyData, null, null);
    }

    /**
     * Create a new instance of {@code CreateCardRequest}
     *
     * @param identity
     *            The identity.
     * @param identityType
     *            The identity type.
     * @param publicKeyData
     *            The public key DER.
     * @param info
     *            The card info.
     */
    public PublishCardRequest(String identity, String identityType, byte[] publicKeyData, CardInfoModel info) {
        this(identity, identityType, publicKeyData, info, null);
    }

    /**
     * Create a new instance of {@code CreateCardRequest}
     *
     * @param identity
     *            The identity.
     * @param identityType
     *            The identity type.
     * @param publicKeyData
     *            The public key DER.
     * @param info
     *            The card information.
     * @param customFields
     *            The card custom fields.
     * @param info
     *            The card info.
     */
    public PublishCardRequest(String identity, String identityType, byte[] publicKeyData, CardInfoModel info,
            Map<String, String> customFields) {
        PublishCardSnapshotModel snapshotModel = new PublishCardSnapshotModel();
        snapshotModel.setIdentity(identity);
        snapshotModel.setIdentityType(identityType);
        snapshotModel.setPublicKeyData(publicKeyData);
        snapshotModel.setInfo(info);
        snapshotModel.setData(customFields);
        snapshotModel.setScope(CardScope.APPLICATION);

        init(snapshotModel);
    }

}
