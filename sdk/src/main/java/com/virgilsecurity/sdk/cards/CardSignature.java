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

package com.virgilsecurity.sdk.cards;

import java.util.Map;
import java.util.Objects;

/**
 * The {@link CardSignature} class represents set of data that defines signature of Card.
 */
public class CardSignature {

    private String signerId;


    private String signerType;

    private String signature;

    private String snapshot;

    private Map<String, String> extraFields;

    /**
     * Gets signer identifier.
     *
     * @return the signer identifier
     */
    public String getSignerId() {
        return signerId;
    }

    /**
     * Gets signer type of {@link SignerType} type
     *
     * @return the signer type
     */
    public String getSignerType() {
        return signerType;
    }

    /**
     * Gets signer signature.
     *
     * @return the signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Gets snapshot.
     *
     * @return the snapshot
     */
    public String getSnapshot() {
        return snapshot;
    }

    /**
     * Gets extra fields associated with the signature.
     *
     * @return the extra fields associated with the signature
     */
    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    /**
     * The type Card signature builder.
     */
    public static final class CardSignatureBuilder {
        private String signerId;
        private String signerType;
        private String signature;
        private String snapshot;
        private Map<String, String> extraFields;

        /**
         * Instantiates a new Card signature builder.
         */
        public CardSignatureBuilder() {
        }

        /**
         * Set signer identifier.
         *
         * @param signerId the signer id
         * @return the card signature builder
         */
        public CardSignatureBuilder signerId(String signerId) {
            this.signerId = signerId;
            return this;
        }

        /**
         * Set signer type of {@link SignerType}.
         *
         * @param signerType the signer type
         * @return the card signature builder
         */
        public CardSignatureBuilder signerType(String signerType) {
            this.signerType = signerType;
            return this;
        }

        /**
         * Set signature.
         *
         * @param signature the signature
         * @return the card signature builder
         */
        public CardSignatureBuilder signature(String signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Set snapshot.
         *
         * @param snapshot the snapshot
         * @return the card signature builder
         */
        public CardSignatureBuilder snapshot(String snapshot) {
            this.snapshot = snapshot;
            return this;
        }

        /**
         * Set extra fields.
         *
         * @param extraFields the extra fields
         * @return the card signature builder
         */
        public CardSignatureBuilder extraFields(Map<String, String> extraFields) {
            this.extraFields = extraFields;
            return this;
        }

        /**
         * Build {@link CardSignature}.
         *
         * @return the card signature
         */
        public CardSignature build() {
            CardSignature cardSignature = new CardSignature();
            cardSignature.snapshot = this.snapshot;
            cardSignature.signerType = this.signerType;
            cardSignature.signerId = this.signerId;
            cardSignature.extraFields = this.extraFields;
            cardSignature.signature = this.signature;
            return cardSignature;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CardSignature that = (CardSignature) o;
        return Objects.equals(signerId, that.signerId) &&
                Objects.equals(signerType, that.signerType) &&
                Objects.equals(signature, that.signature) &&
                Objects.equals(snapshot, that.snapshot) &&
                Objects.equals(extraFields, that.extraFields);
    }

    @Override
    public int hashCode() {

        return Objects.hash(signerId, signerType, signature, snapshot, extraFields);
    }
}
