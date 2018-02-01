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

package com.virgilsecurity.sdk.cards.validation;

import com.sun.istack.internal.NotNull;
import com.virgilsecurity.sdk.cards.SignerType;
import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class VirgilCardVerifier implements CardVerifier {

    private String virgilCardId = "a3dda3d499d91d8287194d399f992c2317f9b6c529d9a0e4972c6e244c399f25";
    private String virgilPublicKeyBase64 = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg=";

    private CardCrypto crypto;
    private boolean verifySelfSignature = true;
    private boolean verifyVirgilSignature = true;
    private List<WhiteList> whiteLists;

    public VirgilCardVerifier(@NotNull CardCrypto crypto) {
        Validator.checkIllegalAgrument(crypto, "VirgilCardVerifier -> 'crypto' should not be null");
        this.crypto = crypto;

        this.whiteLists = new ArrayList<>();
    }

    public VirgilCardVerifier(boolean verifySelfSignature, boolean verifyVirgilSignature) {
        this.verifySelfSignature = verifySelfSignature;
        this.verifyVirgilSignature = verifyVirgilSignature;

        this.crypto = new VirgilCardCrypto();
        this.whiteLists = new ArrayList<>();
    }

    public VirgilCardVerifier(@NotNull CardCrypto crypto,
                              boolean verifySelfSignature,
                              boolean verifyVirgilSignature,
                              @NotNull List<WhiteList> whiteLists) {
        Validator.checkIllegalAgrument(crypto, "VirgilCardVerifier -> 'crypto' should not be null");
        Validator.checkIllegalAgrument(whiteLists, "VirgilCardVerifier -> 'whiteLists' should not be null");

        this.crypto = crypto;
        this.whiteLists = whiteLists;
        this.verifySelfSignature = verifySelfSignature;
        this.verifyVirgilSignature = verifyVirgilSignature;
    }

    @Override public boolean verifyCard(Card card) throws IOException, CryptoException {
        ValidationResult validationResult = new ValidationResult();

        if (verifySelfSignature)
            validate(crypto, card, card.getIdentifier(), card.getPublicKey(), SignerType.SELF, validationResult);

        if (verifyVirgilSignature) {
            byte[] publicKeyData = ConvertionUtils.toBase64Bytes(virgilPublicKeyBase64);
            PublicKey publicKey = crypto.importPublicKey(publicKeyData);
            if (publicKey == null) {
                validationResult.addError("Error importing VIRGIL Public Key");
            }
            validate(crypto, card, virgilCardId, publicKey, SignerType.VIRGIL, validationResult);
        }

        boolean containsSignature = false;
        for (WhiteList whiteList : whiteLists) {
            for (VerifierCredentials verifierCredentials : whiteList.getVerifiersCredentials()) {
                for (CardSignature signerId : card.getSignatures()) {
                    if (signerId.getSignerId().equals(verifierCredentials.getId())) {
                        PublicKey publicKey = crypto.importPublicKey(verifierCredentials.getPublicKey());
                        if (publicKey != null)
                            containsSignature = true;
                        else
                            validationResult.addError("Error importing Whitelist Public Key for " + verifierCredentials.getId());
                    }
                }
            }
        }

        if (!containsSignature)
            validationResult.addError("The card does not contain signature from specified Whitelist");

        return validationResult.isValid();
    }

    private void validate(CardCrypto crypto,
                          Card card,
                          String signerCardId,
                          PublicKey signerPublicKey,
                          SignerType signerType,
                          ValidationResult validationResult) throws IOException, CryptoException {

        if (card.getSignatures() == null || card.getSignatures().isEmpty()) {
            validationResult.addError("The card does not contain any signature");
            return;
        }

        CardSignature signature = card.getSignatures().get(0);
        if (!signature.getSignerId().equals(signerCardId)) {
            validationResult.addError("The card does not contain the " + signerType + " signature");
            return;
        }

        byte[] cardSnapshot = ConvertionUtils.captureSnapshot(card);
        if (cardSnapshot == null) {
            validationResult.addError("The card with id " + signerCardId + " was corrupted");
            return;
        }

        byte[] extraDataSnapshot = new byte[0];
        if (signerType == SignerType.EXTRA) {
            byte[] extraSnapshot = ConvertionUtils.captureSnapshot(signature.getExtraFields());
            if (extraSnapshot == null) {
                validationResult.addError("The EXTRA signature for " + signerCardId + " was corrupted");
                return;
            }
            extraDataSnapshot = extraSnapshot;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(cardSnapshot);
        outputStream.write(extraDataSnapshot);

        byte[] fingerprint = crypto.generateSHA256(outputStream.toByteArray());

        if (!crypto.verifySignature(ConvertionUtils.base64ToBytes(signature.getSignature()), fingerprint, signerPublicKey)) {
            validationResult.addError("The card with id " + signerCardId + " was corrupted");
        }
    }

    public CardCrypto getCardCrypto() {
        return crypto;
    }

    public boolean isIgnoreSelfSignature() {
        return verifySelfSignature;
    }

    public void setIgnoreSelfSignature(boolean ignoreSelfSignature) {
        this.verifySelfSignature = ignoreSelfSignature;
    }

    public boolean isIgnoreVirgilSignature() {
        return verifyVirgilSignature;
    }

    public void setIgnoreVirgilSignature(boolean ignoreVirgilSignature) {
        this.verifyVirgilSignature = ignoreVirgilSignature;
    }

    public List<WhiteList> getWhiteList() {
        return whiteLists;
    }

    public String getVirgilCardId() {
        return virgilCardId;
    }

    public String getVirgilPublicKeyBase64() {
        return virgilPublicKeyBase64;
    }

    public void changeServiceCredentials(String virgilCardId, String virgilPublicKeyBase64) {
        this.virgilCardId = virgilCardId;
        this.virgilPublicKeyBase64 = virgilPublicKeyBase64;
    }
}
