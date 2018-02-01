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
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

package com.virgilsecurity.sdk.cards;

import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.common.StringEncoding;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class ModelSigner {

    private CardCrypto crypto;

    public ModelSigner(CardCrypto crypto) {
        this.crypto = crypto;
    }

    public void sign(RawSignedModel cardModel,
                     String id,
                     SignerType type,
                     PrivateKey privateKey) throws CryptoException {

        byte[] fingerprint = crypto.generateSHA256(cardModel.getContentSnapshot());
        byte[] signature = crypto.generateSignature(fingerprint, privateKey);

        RawSignature rawSignature = new RawSignature(id,
                                                     type.getRawValue(),
                                                     ConvertionUtils.toBase64String(signature));

        cardModel.getSignatures().add(rawSignature);
    }

    public void sign(RawSignedModel cardModel,
                     String id,
                     SignerType type,
                     byte[] additionalData,
                     PrivateKey privateKey) throws CryptoException {

        byte[] combinedSnapshot = new byte[cardModel.getContentSnapshot().length + additionalData.length];
        System.arraycopy(cardModel.getContentSnapshot(),
                         0,
                         combinedSnapshot,
                         0,
                         cardModel.getContentSnapshot().length);
        System.arraycopy(additionalData,
                         0,
                         combinedSnapshot,
                         cardModel.getContentSnapshot().length,
                         additionalData.length);

        byte[] fingerprint = crypto.generateSHA256(combinedSnapshot);
        byte[] signature = crypto.generateSignature(fingerprint, privateKey);

        RawSignature rawSignature = new RawSignature(id,
                                                     ConvertionUtils.toBase64String(additionalData),
                                                     type.getRawValue(),
                                                     ConvertionUtils.toBase64String(signature));

        cardModel.getSignatures().add(rawSignature);
    }

    public void selfSign(RawSignedModel cardModel, byte[] additionalData, PrivateKey privateKey) throws CryptoException {
        byte[] combinedSnapshot = new byte[cardModel.getContentSnapshot().length + additionalData.length];
        System.arraycopy(cardModel.getContentSnapshot(),
                         0,
                         combinedSnapshot,
                         0,
                         cardModel.getContentSnapshot().length);
        System.arraycopy(additionalData,
                         0,
                         combinedSnapshot,
                         cardModel.getContentSnapshot().length,
                         additionalData.length);

        String signerId = ConvertionUtils.toString(crypto.generateSHA256(combinedSnapshot),
                                                   StringEncoding.HEX);

        sign(cardModel, signerId, SignerType.SELF, additionalData, privateKey);
    }

    public void selfSign(RawSignedModel cardModel, PrivateKey privateKey) throws CryptoException {
        String signerId = ConvertionUtils.toString(crypto.generateSHA256(cardModel.getContentSnapshot()),
                                                   StringEncoding.HEX);

        sign(cardModel, signerId, SignerType.SELF, privateKey);
    }
}
