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
package com.virgilsecurity.sdk.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.virgilsecurity.sdk.client.CardValidator;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;

/**
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCardValidator implements CardValidator {

    private Crypto crypto;
    private boolean verifyV3Cards;
    private Map<String, PublicKey> verifiers;

    private final static String SERVICE_CARD_ID = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
    private final static String SERVICE_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAx"
            + "a1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5E" + "IFBVQkxJQyBLRVktLS0tLQo=";

    /**
     * Create a new instance of {@code VirgilCardValidator}
     *
     * @param crypto
     *            The crypto instance.
     */
    public VirgilCardValidator(Crypto crypto) {
        this.crypto = crypto;
        this.verifyV3Cards = false;

        PublicKey servicePublicKey = crypto.importPublicKey(ConvertionUtils.base64ToBytes(SERVICE_PUBLIC_KEY));

        this.verifiers = new HashMap<>();
        this.verifiers.put(SERVICE_CARD_ID, servicePublicKey);
    }

    /**
     * Adds the signature verifier.
     * 
     * @param verifierId
     *            the verifier identifier.
     * @param verifierPublicKey
     *            the verifier public key.
     */
    public void addVerifier(String verifierId, byte[] verifierPublicKey) {
        if (StringUtils.isBlank(verifierId)) {
            throw new EmptyArgumentException("verifierId");
        }

        if (verifierPublicKey == null) {
            throw new EmptyArgumentException("verifierPublicKey");
        }

        PublicKey publicKey = this.crypto.importPublicKey(verifierPublicKey);
        this.verifiers.put(verifierId, publicKey);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.CardValidator#validate(com.virgilsecurity. sdk.client.model.Card)
     */
    @Override
    public boolean validate(CardModel card) {
        // Support for legacy Cards.
        if (!this.verifyV3Cards && "3.0".equals(card.getMeta().getVersion())) {
            return true;
        }

        Fingerprint fingerprint = this.crypto.calculateFingerprint(card.getSnapshot());
        String fingerprintHex = fingerprint.toHex();

        if (!fingerprintHex.equals(card.getId())) {
            return false;
        }

        // add self signature verifier
        Map<String, PublicKey> allVerifiers = new HashMap<>(verifiers);
        allVerifiers.put(fingerprintHex, this.crypto.importPublicKey(card.getSnapshotModel().getPublicKeyData()));

        for (Entry<String, PublicKey> verifier : allVerifiers.entrySet()) {

            if (!card.getMeta().getSignatures().containsKey(verifier.getKey())) {
                return false;
            }

            try {
                boolean isValid = this.crypto.verify(fingerprint.getValue(),
                        card.getMeta().getSignatures().get(verifier.getKey()), verifier.getValue());

                if (!isValid) {
                    return false;
                }
            } catch (CryptoException e) {
                return false;
            }
        }

        return true;
    }

    /**
     * Enable/disable v3 Virgil Cards verification. Disabled by default.
     * 
     * @param verifyV3Cards
     *            set to {@code true} to verify v3 Virgil Cards.
     */
    public void setVerifyV3Cards(boolean verifyV3Cards) {
        this.verifyV3Cards = verifyV3Cards;
    }
}
