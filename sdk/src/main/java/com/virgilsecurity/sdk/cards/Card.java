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

import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.CardUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

import java.util.*;
import java.util.logging.Logger;

/**
 * The {@link Card} class is the main entity of Virgil Services. Every user/device is represented with a Virgil Card
 * which contains a public key and information about identity.
 */
public class Card {
    private static final Logger LOGGER = Logger.getLogger(Card.class.getName());

    private String identifier;
    private String identity;
    private PublicKey publicKey;
    private String version;
    private Date createdAt;
    private String previousCardId;
    private Card previousCard;
    private List<CardSignature> signatures;
    private boolean isOutdated;
    private byte[] contentSnapshot;

    /**
     * Instantiates a new Card.
     *
     * @param identifier
     *            uniquely identifies the Card in Virgil Services
     * @param identity
     *            unique identity value
     * @param publicKey
     *            the public key
     * @param version
     *            the version of Card (ex. "5.0")
     * @param createdAt
     *            when the Card was created at
     * @param signatures
     *            the list of signatures
     */
    public Card(String identifier, String identity, PublicKey publicKey, String version, Date createdAt,
            List<CardSignature> signatures, byte[] contentSnapshot) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.signatures = signatures;
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Instantiates a new Card.
     *
     * @param identifier
     *            uniquely identifies the Card in Virgil Services
     * @param identity
     *            unique identity value
     * @param publicKey
     *            the public key
     * @param version
     *            the version of Card (ex. "5.0")
     * @param createdAt
     *            when the Card was created at
     * @param previousCardId
     *            the previous Card identifier that current card is used to override
     * @param signatures
     *            the list of signatures
     */
    public Card(String identifier, String identity, PublicKey publicKey, String version, Date createdAt,
            String previousCardId, List<CardSignature> signatures, byte[] contentSnapshot) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.signatures = signatures;
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Instantiates a new Card.
     *
     * @param identifier
     *            uniquely identifies the Card in Virgil Services
     * @param identity
     *            unique identity value
     * @param publicKey
     *            the public key
     * @param version
     *            the version of Card (ex. "5.0")
     * @param createdAt
     *            when the Card was created at
     * @param previousCardId
     *            the previous Card identifier that current card is used to override
     * @param previousCard
     *            the previous Card that current card is used to override
     * @param signatures
     *            the list of signatures
     */
    public Card(String identifier, String identity, PublicKey publicKey, String version, Date createdAt,
            String previousCardId, Card previousCard, List<CardSignature> signatures, byte[] contentSnapshot) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.previousCard = previousCard;
        this.signatures = signatures;
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Instantiates a new Card.
     *
     * @param identity
     *            unique identity value
     * @param publicKey
     *            the public key
     * @param version
     *            the version of Card (ex. "5.0")
     * @param createdAt
     *            when the Card was created at
     * @param previousCardId
     *            the previous Card identifier that current card is used to override
     * @param previousCard
     *            the previous Card that current card is used to override
     * @param signatures
     *            the list of signatures
     * @param isOutdated
     *            whether the card is overridden by another card
     */
    public Card(String identifier, String identity, PublicKey publicKey, String version, Date createdAt,
            String previousCardId, Card previousCard, List<CardSignature> signatures, boolean isOutdated,
            byte[] contentSnapshot) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.previousCard = previousCard;
        this.signatures = signatures;
        this.isOutdated = isOutdated;
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Gets the Card identifier that uniquely identifies the Card in Virgil Services.
     *
     * @return the Card identifier
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Gets the identity value that can be anything which identifies the user in your application.
     *
     * @return the identity
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Gets the public key.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Gets the version of the card.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Gets the date and time fo card creation in UTC.
     *
     * @return the created at
     */
    public Date getCreatedAt() {
        return createdAt;
    }

    /**
     * Get previous Card identifier that current card is used to override to.
     *
     * @return the previous card id
     */
    public String getPreviousCardId() {
        return previousCardId;
    }

    /**
     * Get previous Card that current card is used to override to.
     *
     * @return the previous card
     */
    public Card getPreviousCard() {
        return previousCard;
    }

    /**
     * Set previous Card that current card is used to override to
     *
     * @param previousCard
     *            the previous card
     */
    public void setPreviousCard(Card previousCard) {
        Validator.checkNullAgrument(previousCard, "Card -> 'previousCard' shoud not be null");
        this.previousCard = previousCard;
    }

    /**
     * Gets a list of signatures.
     *
     * @return the signatures
     */
    public List<CardSignature> getSignatures() {
        return signatures;
    }

    /**
     * Whether the card is overridden by another card.
     *
     * @return if the Card is outdated - {@code true}, otherwise {@code false}
     */
    public boolean isOutdated() {
        return isOutdated;
    }

    /**
     * Sets whether the card is overridden by another card.
     *
     * @param outdated
     *            if the Card is outdated - {@code true}, otherwise {@code false}
     */
    public void setOutdated(boolean outdated) {
        isOutdated = outdated;
    }

    /**
     * Get Card's content snapshot which is representation of {@link RawCardContent}.
     *
     * @return the content snapshot as byte [ ]
     */
    public byte[] getContentSnapshot() {
        return contentSnapshot;
    }

    /**
     * Sets Card's content snapshot which is representation of {@link RawCardContent}.
     *
     * @param contentSnapshot
     *            the content snapshot as byte [ ]
     */
    public void setContentSnapshot(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;
    }

    /**
     * Parse card from provided raw signed model.
     *
     * @param crypto
     *            the crypto
     * @param cardModel
     *            the card model to be parsed
     * @return the card that is parsed from provided {@link RawSignedModel}
     * @throws CryptoException
     */
    public static Card parse(CardCrypto crypto, RawSignedModel cardModel) throws CryptoException {
        if (cardModel == null)
            throw new NullArgumentException("Card -> 'cardModel' should not be null");

        RawCardContent rawCardContent = ConvertionUtils.deserializeFromJson(new String(cardModel.getContentSnapshot()),
                RawCardContent.class);

        String cardId = CardUtils.generateCardId(crypto, cardModel.getContentSnapshot());
        PublicKey publicKey = crypto.importPublicKey(ConvertionUtils.base64ToBytes(rawCardContent.getPublicKey()));

        // Converting RawSignatures to CardSignatures
        List<CardSignature> cardSignatures = new ArrayList<>();
        if (cardModel.getSignatures() != null) {
            for (RawSignature rawSignature : cardModel.getSignatures()) {
                CardSignature.CardSignatureBuilder cardSignature = new CardSignature.CardSignatureBuilder(
                        rawSignature.getSigner(), ConvertionUtils.base64ToBytes(rawSignature.getSignature()));
                if (rawSignature.getSnapshot() != null) {
                    String snapshot = rawSignature.getSnapshot();
                    Map<String, String> additionalDataSignature = ConvertionUtils
                            .deserializeMapFromJson(ConvertionUtils.base64ToString(snapshot));

                    cardSignature.snapshot(ConvertionUtils.base64ToBytes(snapshot));
                    cardSignature.extraFields(additionalDataSignature);
                } else {
                    LOGGER.info(String.format("Signature '%s' has no additional data", rawSignature.getSigner()));
                }

                cardSignatures.add(cardSignature.build());
            }
        } else {
            throw new VirgilCardVerificationException("Card should have at least self signature");
        }

        return new Card(cardId, rawCardContent.getIdentity(), publicKey, rawCardContent.getVersion(),
                rawCardContent.getCreatedAtDate(), rawCardContent.getPreviousCardId(), cardSignatures,
                cardModel.getContentSnapshot());
    }

    /**
     * Gets raw signed model from current Card.
     *
     * @return the {@link RawSignedModel} exported from this Card
     */
    public RawSignedModel getRawCard() {
        RawCardContent cardContent = new RawCardContent(contentSnapshot);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);

        RawSignedModel cardModel = new RawSignedModel(snapshot);

        for (CardSignature signature : signatures) {
            if (signature.getSnapshot() != null) {
                cardModel.addSignature(new RawSignature(ConvertionUtils.toBase64String(signature.getSnapshot()),
                        signature.getSigner(), ConvertionUtils.toBase64String(signature.getSignature())));
            } else {
                cardModel.addSignature(new RawSignature(signature.getSigner(),
                        ConvertionUtils.toBase64String(signature.getSignature())));
            }
        }

        return cardModel;
    }

    public CardSignature getSelfSignature() throws VirgilCardVerificationException {
        for (CardSignature cardSignature : signatures) {
            if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue()))
                return cardSignature;
        }

        LOGGER.warning("Card must have self signature");
        throw new VirgilCardVerificationException("Card -> card must have 'self' signature");
    }

    @Override
    public int hashCode() {

        return Objects.hash(identifier, identity, publicKey, version, createdAt, previousCardId, previousCard,
                signatures, isOutdated);
    }
}
