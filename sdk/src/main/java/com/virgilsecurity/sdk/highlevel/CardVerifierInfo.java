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
package com.virgilsecurity.sdk.highlevel;

/**
 * The {@linkplain CardVerifierInfo} class represents an information about Virgil Card verifier such as Public key and
 * Card Id.
 * 
 * @author Andrii Iakovenko
 *
 */
public class CardVerifierInfo {

    private String cardId;

    private VirgilBuffer publicKeyData;

    /**
     * Create new instance of {@link CardVerifierInfo}.
     */
    public CardVerifierInfo() {
    }

    /**
     * Create new instance of {@link CardVerifierInfo}.
     * 
     * @param cardId
     *            The card identifier.
     * @param publicKeyData
     *            The public key data.
     */
    public CardVerifierInfo(String cardId, VirgilBuffer publicKeyData) {
        this.cardId = cardId;
        this.publicKeyData = publicKeyData;
    }

    /**
     * Gets the Virgil Card identifier.
     * 
     * @return the cardId
     */
    public String getCardId() {
        return cardId;
    }

    /**
     * Sets the Virgil Card identifier.
     * 
     * @param cardId
     *            the cardId to set
     */
    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

    /**
     * Gets the Public key value.
     * 
     * @return the publicKeyData
     */
    public VirgilBuffer getPublicKeyData() {
        return publicKeyData;
    }

    /**
     * Sets the Public key value.
     * 
     * @param publicKeyData
     *            the publicKeyData to set
     */
    public void setPublicKeyData(VirgilBuffer publicKeyData) {
        this.publicKeyData = publicKeyData;
    }

}
