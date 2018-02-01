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

public class CardSignature {

    /**
     * The card ID.
     */
    private String signerId;

    /**
     * Gets the type of signer signature.
     */
    private String signerType;

    /**
     * The digital signature
     */
    private String signature;

    /**
     * The digital snapshot
     */
    private String snapshot;

    /**
     * EXTRA fields
     */
    private Map<String, String> extraFields;

    public String getSignerId() {
        return signerId;
    }

    private void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public String getSignerType() {
        return signerType;
    }

    private void setSignerType(String signerType) {
        this.signerType = signerType;
    }

    public String getSignature() {
        return signature;
    }

    private void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSnapshot() {
        return snapshot;
    }

    private void setSnapshot(String snapshot) {
        this.snapshot = snapshot;
    }

    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    private void setExtraFields(Map<String, String> extraFields) {
        this.extraFields = extraFields;
    }


    public static final class CardSignatureBuilder {
        private String signerId;
        private String signerType;
        private String signature;
        private String snapshot;
        private Map<String, String> extraFields;

        public CardSignatureBuilder() {
        }

        public CardSignatureBuilder signerId(String signerId) {
            this.signerId = signerId;
            return this;
        }

        public CardSignatureBuilder signerType(String signerType) {
            this.signerType = signerType;
            return this;
        }

        public CardSignatureBuilder signature(String signature) {
            this.signature = signature;
            return this;
        }

        public CardSignatureBuilder snapshot(String snapshot) {
            this.snapshot = snapshot;
            return this;
        }

        public CardSignatureBuilder extraFields(Map<String, String> extraFields) {
            this.extraFields = extraFields;
            return this;
        }

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

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CardSignature that = (CardSignature) o;
        return Objects.equals(signerId, that.signerId) &&
                Objects.equals(signerType, that.signerType) &&
                Objects.equals(signature, that.signature) &&
                Objects.equals(snapshot, that.snapshot) &&
                Objects.equals(extraFields, that.extraFields);
    }

    @Override public int hashCode() {

        return Objects.hash(signerId, signerType, signature, snapshot, extraFields);
    }
}
