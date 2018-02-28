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
 * Represents a signable request that uses to publish new Card to the Virgil Services.
 * 
 * @author Andrii Iakovenko
 *
 */
public class PublishGlobalCardRequest extends GenericSignableRequest<PublishCardSnapshotModel> {

    /**
     * Create new instance of {@link PublishGlobalCardRequest}.
     * 
     * @param snapshot
     *            The snapshot.
     * @param validationToken
     *            The identity validation token.
     * @param signatures
     *            The signatures.
     */
    public PublishGlobalCardRequest(byte[] snapshot, String validationToken, Map<String, byte[]> signatures) {
        this.takenSnapshot = snapshot;
        this.acceptedSignatures = new HashMap<>(signatures);
        this.validationToken = validationToken;
    }

    /**
     * Create new instance of {@link PublishGlobalCardRequest}.
     * 
     * @param stringifiedRequest
     *            The stringified request.
     */
    public PublishGlobalCardRequest(String stringifiedRequest) {
        super(stringifiedRequest);
    }

    /**
     * Create new instance of {@link PublishGlobalCardRequest}.
     * 
     * @param identity
     *            The identity.
     * @param identityType
     *            Type of the identity.
     * @param publicKeyData
     *            The public key data.
     * @param validationToken
     *            The identity validation token.
     */
    public PublishGlobalCardRequest(String identity, String identityType, byte[] publicKeyData,
            String validationToken) {
        this(identity, identityType, publicKeyData, validationToken, null);
    }

    /**
     * Create new instance of {@link PublishGlobalCardRequest}.
     * 
     * @param identity
     *            The identity.
     * @param identityType
     *            Type of the identity.
     * @param publicKeyData
     *            The public key data.
     * @param validationToken
     *            The identity validation token.
     * @param info
     *            The information.
     */
    public PublishGlobalCardRequest(String identity, String identityType, byte[] publicKeyData, String validationToken,
            CardInfoModel info) {
        this(identity, identityType, publicKeyData, validationToken, info, null);
    }

    /**
     * Create new instance of {@link PublishGlobalCardRequest}.
     * 
     * @param identity
     *            The identity.
     * @param identityType
     *            Type of the identity.
     * @param publicKeyData
     *            The public key data.
     * @param validationToken
     *            The identity validation token.
     * @param info
     *            The information.
     * @param customFields
     *            The custom fields.
     */
    public PublishGlobalCardRequest(String identity, String identityType, byte[] publicKeyData, String validationToken,
            CardInfoModel info, Map<String, String> customFields) {

        PublishCardSnapshotModel snapshotModel = new PublishCardSnapshotModel();
        snapshotModel.setIdentity(identity);
        snapshotModel.setIdentityType(identityType);
        snapshotModel.setPublicKeyData(publicKeyData);
        snapshotModel.setInfo(info);
        snapshotModel.setData(customFields);
        snapshotModel.setScope(CardScope.GLOBAL);
        init(snapshotModel);

        this.validationToken = validationToken;
    }

}
