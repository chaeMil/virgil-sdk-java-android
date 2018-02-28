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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.exceptions.NotSupportedException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.client.requests.PublishGlobalCardRequest;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * A Virgil Card is the main entity of the Virgil Security services, it includes an information about the user and his
 * public key. The Virgil Card identifies the user by one of his available types, such as an email, a phone number, etc.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilCard {

    private VirgilApiContext context;
    private CardModel card;
    private PublicKey publicKey;

    /**
     * Create new instance of {@link VirgilCard}.
     * 
     * @param context
     *            The context.
     * @param card
     *            The card model.
     */
    public VirgilCard(VirgilApiContext context, CardModel card) {
        this.context = context;
        this.card = card;

        this.publicKey = this.context.getCrypto().importPublicKey(this.card.getSnapshotModel().getPublicKeyData());
    }

    /**
     * Gets the unique identifier for the Virgil Card.
     * 
     * @return The card identifier.
     */
    public String getId() {
        return this.card.getId();
    }

    /**
     * Gets the value of current Virgil Card identity.
     * 
     * @return The identity.
     */
    public String getIdentity() {
        return this.card.getSnapshotModel().getIdentity();
    }

    /**
     * Gets the identityType of current Virgil Card identity.
     * 
     * @return The identity type.
     */
    public String getIdentityType() {
        return this.card.getSnapshotModel().getIdentityType();
    }

    /**
     * Get the card model.
     * 
     * @return the card model.
     */
    public CardModel getModel() {
        return this.card;
    }

    /**
     * Gets the custom Virgil Card parameters.
     * 
     * @return Custom fields.
     */
    public Map<String, String> getCustomFields() {
        return this.card.getSnapshotModel().getData();
    }

    /**
     * Gets a Public key that is assigned to current Virgil Card.
     * 
     * @return The public key.
     */
    PublicKey getPublicKey() {
        return this.publicKey;
    }

    /**
     * Encrypts the specified data for current {@linkplain VirgilCard} recipient.
     * 
     * @param buffer
     *            The data to be encrypted.
     * @return The encrypted data.
     * @throws EncryptionException
     */
    public VirgilBuffer encrypt(VirgilBuffer buffer) throws EncryptionException {
        if (buffer == null) {
            throw new NullArgumentException("buffer");
        }
        return encrypt(buffer.getBytes());
    }

    /**
     * Encrypts the plain text for current {@linkplain VirgilCard} recipient.
     * 
     * @param plaintext
     *            The plain text to be encrypted.
     * @return The encrypted data.
     * @throws EncryptionException
     */
    public VirgilBuffer encrypt(String plaintext) throws EncryptionException {
        if (plaintext == null) {
            throw new NullArgumentException("plaintext");
        }
        return encrypt(ConvertionUtils.toBytes(plaintext));
    }

    /**
     * Encrypts the data for current {@linkplain VirgilCard} recipient.
     * 
     * @param data
     *            The data to be encrypted.
     * @return The encrypted data.
     * @throws EncryptionException
     */
    public VirgilBuffer encrypt(byte[] data) throws EncryptionException {
        if (data == null) {
            throw new NullArgumentException("data");
        }
        byte[] cipherdata = this.context.getCrypto().encrypt(data, this.publicKey);
        return VirgilBuffer.from(cipherdata);
    }

    /**
     * / Verifies the specified buffer and signature with current {@linkplain VirgilCard} recipient.
     * 
     * @param buffer
     *            The data to be verified.
     * @param signature
     *            The signature used to verify the data integrity.
     * @return {@code true} if verification success.
     * @throws VerificationException
     */
    public boolean verify(VirgilBuffer buffer, VirgilBuffer signature) throws VerificationException {
        if (buffer == null) {
            throw new NullArgumentException("buffer");
        }
        if (signature == null) {
            throw new NullArgumentException("signature");
        }
        boolean isValid = this.context.getCrypto().verify(buffer.getBytes(), signature.getBytes(), this.publicKey);

        return isValid;
    }

    /**
     * / Verifies the specified plain text and signature with current {@linkplain VirgilCard} recipient.
     * 
     * @param plaintext
     *            The plain text to be verified.
     * @param signature
     *            The signature used to verify the data integrity.
     * @return {@code true} if verification success.
     * @throws VerificationException
     */
    public boolean verify(String plaintext, VirgilBuffer signature) throws VerificationException {
        if (plaintext == null) {
            throw new NullArgumentException("plaintext");
        }
        return verify(VirgilBuffer.from(plaintext), signature);
    }

    /**
     * / Verifies the specified plain text and signature with current {@linkplain VirgilCard} recipient.
     * 
     * @param plaintext
     *            The plain text to be verified.
     * @param signature
     *            The signature as Base64 string used to verify the data integrity.
     * @return {@code true} if verification success.
     * @throws VerificationException
     */
    public boolean verify(String plaintext, String signature) throws VerificationException {
        return verify(plaintext, VirgilBuffer.from(signature, StringEncoding.Base64));
    }

    /**
     * / Verifies the specified plain text and signature with current {@linkplain VirgilCard} recipient.
     * 
     * @param plaintext
     *            The plain text to be verified.
     * @param signature
     *            The signature used to verify the data integrity.
     * @return {@code true} if verification success.
     * @throws VerificationException
     */
    public boolean verify(String plaintext, byte[] signature) throws VerificationException {
        return verify(plaintext, VirgilBuffer.from(signature));
    }

    /**
     * Exports a current {@linkplain VirgilCard} instance into base64 encoded string.
     * 
     * @return A string that represents a {@linkplain VirgilCard}
     */
    public String export() {
        String serializedCard = ConvertionUtils.getGson().toJson(this.card);
        return VirgilBuffer.from(serializedCard).toString(StringEncoding.Base64);
    }

    /**
     * Initiates an identity verification process for current Card identity type. It is only working for Global identity
     * types like Email.
     * 
     * @return An instance of {@link IdentityVerificationAttempt} that contains information about operation etc...
     */
    public IdentityVerificationAttempt checkIdentity() {
        return checkIdentity(null);
    }

    /**
     * Initiates an identity verification process for current Card identity type. It is only working for Global identity
     * types like Email.
     * 
     * @param options
     *            The verification options.
     * @return An instance of {@link IdentityVerificationAttempt} that contains information about operation etc...
     */
    public IdentityVerificationAttempt checkIdentity(IdentityVerificationOptions options) {
        Map<String, String> extraFields = null;
        if (options != null) {
            extraFields = options.getExtraFields();
        }
        String actionId = this.context.getClient().verifyIdentity(this.getIdentity(), this.getIdentityType(),
                extraFields);

        IdentityVerificationAttempt attempt = new IdentityVerificationAttempt(this.context);
        attempt.setActionId(actionId);
        attempt.setIdentity(this.getIdentity());
        attempt.setIdentityType(this.getIdentityType());
        if (options != null) {
            attempt.setTimeToLive(options.getTimeToLive());
            attempt.setCountToLive(options.getCountToLive());
        }

        return attempt;
    }

    /**
     * Publishes a current {@linkplain VirgilCard} to the Virgil Security services.
     * 
     * @return This card.
     * @throws CryptoException
     */
    public VirgilCard publish() throws CryptoException {
        PublishCardRequest publishCardRequest = new PublishCardRequest(this.card.getSnapshot(),
                this.card.getMeta().getSignatures());

        String appId = this.context.getCredentials().getAppId();
        PrivateKey appKey = this.context.getCredentials().getAppKey(this.context.getCrypto());

        RequestSigner requestSigner = new RequestSigner(this.context.getCrypto());
        requestSigner.authoritySign(publishCardRequest, appId, appKey);

        CardModel updatedModel = this.context.getClient().publishCard(publishCardRequest);

        this.card.setMeta(updatedModel.getMeta());

        return this;
    }

    /**
     * Publishes a current {@linkplain VirgilCard} to the Virgil Security services into global scope.
     * 
     * @param identityToken
     *            The identity validation token.
     * @return This card.
     */
    public VirgilCard publishAsGlobal(IdentityValidationToken identityToken) {
        if (identityToken == null) {
            throw new NullArgumentException("identityToken");
        }

        if (!CardScope.GLOBAL.equals(this.card.getSnapshotModel().getScope())) {
            throw new NotSupportedException();
        }

        PublishGlobalCardRequest publishCardRequest = new PublishGlobalCardRequest(this.card.getSnapshot(),
                identityToken.getValue(), this.card.getMeta().getSignatures());

        CardModel updatedModel = this.context.getClient().publishGlobalCard(publishCardRequest);

        this.card.setMeta(updatedModel.getMeta());

        return this;
    }

    /**
     * Encrypts data for list of recipients Cards.
     * 
     * @param buffer
     *            The data to be encrypted.
     * @param recipients
     *            The recipients.
     * @return A new {@link VirgilBuffer} with encrypted data.
     * @throws EncryptionException
     */
    VirgilBuffer encrypt(VirgilBuffer buffer, Collection<VirgilCard> recipients) throws EncryptionException {
        List<PublicKey> publicKeyRecipients = new ArrayList<>();
        if (recipients != null && !recipients.isEmpty()) {
            for (VirgilCard card : recipients) {
                publicKeyRecipients.add(card.publicKey);
            }
        }

        byte[] cipherdata = this.context.getCrypto().encrypt(buffer.getBytes(),
                publicKeyRecipients.toArray(new PublicKey[0]));
        return VirgilBuffer.from(cipherdata);
    }
}
