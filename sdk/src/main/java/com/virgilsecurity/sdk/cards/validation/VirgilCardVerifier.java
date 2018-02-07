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

package com.virgilsecurity.sdk.cards.validation;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.SignerType;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Log;
import com.virgilsecurity.sdk.utils.Validator;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The {@link VirgilCardVerifier} is used to verify cards.
 */
public class VirgilCardVerifier implements CardVerifier {
    private String virgilPublicKeyBase64 = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg=";

    private CardCrypto cardCrypto;
    private boolean verifySelfSignature = true;
    private boolean verifyVirgilSignature = true;
    private List<WhiteList> whiteLists;

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *         the crypto
     */
    public VirgilCardVerifier(CardCrypto cardCrypto) {
        Validator.checkNullAgrument(cardCrypto, "VirgilCardVerifier -> 'cardCrypto' should not be null");
        this.cardCrypto = cardCrypto;

        this.whiteLists = new ArrayList<>();
    }

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *         the card crypto
     * @param verifySelfSignature
     *         whether the self signature should be verified
     * @param verifyVirgilSignature
     *         whether the virgil signature should be verified
     * @param whiteLists
     *         the white lists that should contain Card signatures, otherwise Card validation
     *         will be failed
     */
    public VirgilCardVerifier(CardCrypto cardCrypto,
                              boolean verifySelfSignature,
                              boolean verifyVirgilSignature,
                              List<WhiteList> whiteLists) {
        Validator.checkNullAgrument(cardCrypto, "VirgilCardVerifier -> 'cardCrypto' should not be null");
        Validator.checkNullAgrument(whiteLists, "VirgilCardVerifier -> 'whiteLists' should not be null");

        this.cardCrypto = cardCrypto;
        this.whiteLists = whiteLists;
        this.verifySelfSignature = verifySelfSignature;
        this.verifyVirgilSignature = verifyVirgilSignature;
    }

    @Override
    public boolean verifyCard(Card card) throws CryptoException {
        if (verifySelfSignature)
            if (!verify(card, SignerType.SELF.getRawValue(), card.getPublicKey()))
                return false;

        if (verifyVirgilSignature) {
            byte[] publicKeyData = ConvertionUtils.base64ToBytes(virgilPublicKeyBase64);
            PublicKey publicKey = cardCrypto.importPublicKey(publicKeyData);

            if (!verify(card, SignerType.VIRGIL.getRawValue(), publicKey))
                return false;
        }

        boolean containsSignature = false;
        for (WhiteList whiteList : whiteLists) {
            for (VerifierCredentials verifierCredentials : whiteList.getVerifiersCredentials()) {
                for (CardSignature cardSignature : card.getSignatures()) {
                    if (Objects.equals(cardSignature.getSigner(), verifierCredentials.getSigner())) {
                        PublicKey publicKey = cardCrypto.importPublicKey(verifierCredentials.getPublicKey());
                        containsSignature = true;
                        if (!verify(card, cardSignature.getSigner(), publicKey))
                            return false;
                    }
                }
            }
        }

        if (!whiteLists.isEmpty() && !containsSignature) {
            Log.d("The card does not contain signature from specified Whitelist");
            return false;
        }

        return true;
    }

    /**
     * Verifies provided Card.
     *
     * @param card
     *         the card
     * @param signer
     *         the signer
     * @param signerPublicKey
     *         the signer's public key
     * @return {@code true} if Card is valid, otherwise {@code false}
     */
    private boolean verify(Card card, String signer, PublicKey signerPublicKey) {
        CardSignature cardSignature = null;
        for (CardSignature signature : card.getSignatures()) {
            if (Objects.equals(signature.getSigner(), signer))
                cardSignature = signature;
        }

        if (cardSignature == null) {
            Log.d("The card does not contain the " + signer + " signature");
            return false;
        }

        byte[] combinedSnapshot = ConvertionUtils
                .concatenate(card.getRawCard().getContentSnapshot(), cardSignature.getSnapshot());

        byte[] fingerprint;
        try {
            fingerprint = cardCrypto.generateSHA512(combinedSnapshot);
        } catch (CryptoException e) {
            e.printStackTrace();
            return false;
        }

        try {
            if (!cardCrypto.verifySignature(cardSignature.getSignature(), fingerprint, signerPublicKey))
                return false;
        } catch (CryptoException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Gets card crypto.
     *
     * @return the card crypto
     */
    public CardCrypto getCardCrypto() {
        return cardCrypto;
    }

    /**
     * Gets whether the self signature verification should be ignored.
     *
     * @return {@code true} if the self signature verification should be ignored, otherwise {@code false}
     */
    public boolean isIgnoreSelfSignature() {
        return verifySelfSignature;
    }

    /**
     * Sets whether the self signature verification should be ignored.
     *
     * @param ignoreSelfSignature
     *         {@code true} if the self signature verification should be ignored, otherwise {@code false}
     */
    public void setIgnoreSelfSignature(boolean ignoreSelfSignature) {
        this.verifySelfSignature = ignoreSelfSignature;
    }

    /**
     * Gets whether the virgil signature verification should be ignored.
     *
     * @return {@code true} if the virgil signature verification should be ignored, otherwise {@code false}
     */
    public boolean isIgnoreVirgilSignature() {
        return verifyVirgilSignature;
    }

    /**
     * Sets whether the virgil signature verification should be ignored.
     *
     * @param ignoreVirgilSignature
     *         {@code true} if the virgil signature verification should be ignored, otherwise {@code false}
     */
    public void setIgnoreVirgilSignature(boolean ignoreVirgilSignature) {
        this.verifyVirgilSignature = ignoreVirgilSignature;
    }

    /**
     * Gets white list.
     *
     * @return the white list
     */
    public List<WhiteList> getWhiteList() {
        return whiteLists;
    }

    /**
     * Gets virgil public key in base64 string.
     *
     * @return the virgil public key in base64 string
     */
    public String getVirgilPublicKeyBase64() {
        return virgilPublicKeyBase64;
    }
}
