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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * The {@link CardManager} class provides list of methods to work with {@link Card}.
 */
public class CardManager {
    private static final String CURRENT_CARD_VERSION = "5.0";
    private static final String TOKEN_CONTEXT_OPERATION = "SomeOperation";

    private ModelSigner modelSigner;
    private CardCrypto crypto;
    private AccessTokenProvider accessTokenProvider;
    private CardVerifier cardVerifier;
    private CardClient cardClient;
    private SignCallback signCallback;

    /**
     * Instantiates a new Card manager.
     *
     * 
     * @param crypto
     *            the crypto
     * @param accessTokenProvider
     *            the access token provider
     * @param modelSigner
     *            the model signer
     * @param cardClient
     *            the card client
     * @param cardVerifier
     *            the card verifier
     * @param signCallback
     *            the sign callback
     */
    public CardManager(CardCrypto crypto, AccessTokenProvider accessTokenProvider, ModelSigner modelSigner,
            CardClient cardClient, CardVerifier cardVerifier, SignCallback signCallback) {
        Validator.checkNullAgrument(crypto, "CardManager -> 'crypto' should not be null");
        Validator.checkNullAgrument(accessTokenProvider, "CardManager -> 'accessTokenProvider' should not be null");
        // Validator.checkNullAgrument(modelSigner, "CardManager -> 'modelSigner' should not be null");
        // Validator.checkNullAgrument(cardClient, "CardManager -> 'cardClient' should not be null");
        // Validator.checkNullAgrument(cardVerifier, "CardManager -> 'cardVerifier' should not be null");

        this.modelSigner = modelSigner;
        this.crypto = crypto;
        this.accessTokenProvider = accessTokenProvider;
        this.cardVerifier = cardVerifier;
        this.cardClient = cardClient;
        this.signCallback = signCallback;
    }

    /**
     * Verifies whether provided {@link Card} is valid with provided {@link CardVerifier}.
     *
     * @param card
     *            to verify
     * @throws CryptoException
     *             if verification of card issue occurred
     * @throws IOException
     */
    private void verifyCard(Card card) throws CryptoException, IOException {
        if (!cardVerifier.verifyCard(card))
            throw new VerificationException();
    }

    /**
     * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains the public key for
     * which the card should be registered, identity information (such as a user name) and integrity protection in form
     * of digital self signature.
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param previousCardId
     *            the previous card id that current card is used to override
     * @param additionalData
     *            the additional data associated with the card
     * @return a new instance of {@link RawSignedModel}
     * @throws CryptoException
     *             if issue occurred during exporting public key or self sign operation
     */
    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey, String identity,
            String previousCardId, Map<String, String> additionalData) throws CryptoException {
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date(),
                previousCardId);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, ConvertionUtils.captureSnapshot(additionalData), privateKey);

        if (signCallback != null)
            cardModel = signCallback.onSign(cardModel);

        return cardModel;
    }

    /**
     * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains the public key for
     * which the card should be registered, identity information (such as a user name) and integrity protection in form
     * of digital self signature.
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param previousCardId
     *            the previous card id that current card is used to override
     * @return a new instance of {@link RawSignedModel}
     * @throws CryptoException
     *             if issue occurred during exporting public key or self sign operation
     */
    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey, String identity,
            String previousCardId) throws CryptoException {
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date(),
                previousCardId);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey);

        if (signCallback != null)
            cardModel = signCallback.onSign(cardModel);

        return cardModel;
    }

    /**
     * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains the public key for
     * which the card should be registered, identity information (such as a user name) and integrity protection in form
     * of digital self signature.
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param additionalData
     *            the additional data associated with the card
     * @return a new instance of {@link RawSignedModel}
     * @throws CryptoException
     *             if issue occurred during exporting public key or self sign operation
     */
    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey, String identity,
            Map<String, String> additionalData) throws CryptoException {
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date());

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, ConvertionUtils.captureSnapshot(additionalData), privateKey);

        if (signCallback != null)
            cardModel = signCallback.onSign(cardModel);

        return cardModel;
    }

    /**
     * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains the public key for
     * which the card should be registered, identity information (such as a user name) and integrity protection in form
     * of digital self signature.
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @return a new instance of {@link RawSignedModel}
     * @throws CryptoException
     *             if issue occurred during exporting public key or self sign operation
     */
    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey, String identity)
            throws CryptoException {
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date());

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey);

        if (signCallback != null)
            cardModel = signCallback.onSign(cardModel);

        return cardModel;
    }

    /**
     * Publishes card to the Virgil Cards service. You should use
     * {@link #generateRawCard(PrivateKey, PublicKey, String)} method, or it's overridden variations
     *
     * @param cardModel
     *            the card model to publish
     * @return the card that is returned from the Virgil Cards service after successful publishing
     * @throws CryptoException
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws IOException
     *             if issue occurred verifying card that was received from the Virgil Cards service
     * @see #generateRawCard(PrivateKey, PublicKey, String)
     */
    public Card publishCard(RawSignedModel cardModel) throws CryptoException, IOException {
        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));
        Card card = Card.parse(crypto, cardClient.publishCard(cardModel, token.stringRepresentation()));

        verifyCard(card);

        return card;
    }

    /**
     * Publish card to the Virgil Cards service.
     * <p>
     * Internally {@link #generateRawCard(PrivateKey, PublicKey, String, String, Map)} method will be called to generate
     * {@link RawSignedModel} with provided parameters after that card model will be published via
     * {@link #publishCard(RawSignedModel)} method
     * </p>
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param previousCardId
     *            the previous card id that current card is used to override
     * @param additionalData
     *            the additional data associated with the card
     * @return the card that is returned from the Virgil Cards service after successful publishing
     * @throws CryptoException
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws IOException
     *             if issue occurred verifying card that was received from the Virgil Cards service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity, String previousCardId,
            Map<String, String> additionalData) throws CryptoException, IOException {

        RawSignedModel cardModel = generateRawCard(privateKey, publicKey, identity, previousCardId, additionalData);

        return publishCard(cardModel);
    }

    /**
     * Publish card to the Virgil Cards service.
     * <p>
     * Internally {@link #generateRawCard(PrivateKey, PublicKey, String, Map)} method will be called to generate
     * {@link RawSignedModel} with provided parameters after that card model will be published via
     * {@link #publishCard(RawSignedModel)} method
     * </p>
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param additionalData
     *            the additional data associated with the card
     * @return the card that is returned from the Virgil Cards service after successful publishing
     * @throws CryptoException
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws IOException
     *             if issue occurred verifying card that was received from the Virgil Cards service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity,
            Map<String, String> additionalData) throws CryptoException, IOException {

        RawSignedModel cardModel = generateRawCard(privateKey, publicKey, identity, additionalData);

        return publishCard(cardModel);
    }

    /**
     * Publish card to the Virgil Cards service.
     * <p>
     * Internally {@link #generateRawCard(PrivateKey, PublicKey, String, String)} method will be called to generate
     * {@link RawSignedModel} with provided parameters after that card model will be published via
     * {@link #publishCard(RawSignedModel)} method
     * </p>
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @param previousCardId
     *            the previous card id that current card is used to override
     * @return the card that is returned from the Virgil Cards service after successful publishing
     * @throws CryptoException
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws IOException
     *             if issue occurred verifying card that was received from the Virgil Cards service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity, String previousCardId)
            throws CryptoException, IOException {

        RawSignedModel cardModel = generateRawCard(privateKey, publicKey, identity, previousCardId);

        return publishCard(cardModel);
    }

    /**
     * Publish card to the Virgil Cards service.
     * <p>
     * Internally {@link #generateRawCard(PrivateKey, PublicKey, String)} method will be called to generate
     * {@link RawSignedModel} with provided parameters after that card model will be published via
     * {@link #publishCard(RawSignedModel)} method
     * </p>
     *
     * @param privateKey
     *            the private key that used to generate self signature
     * @param publicKey
     *            the public key
     * @param identity
     *            the unique identity value
     * @return the card that is returned from the Virgil Cards service after successful publishing
     * @throws CryptoException
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws IOException
     *             if issue occurred verifying card that was received from the Virgil Cards service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity)
            throws CryptoException, IOException {
        RawSignedModel cardModel = generateRawCard(privateKey, publicKey, identity);

        return publishCard(cardModel);
    }

    /**
     * Gets the card by specified identifier.
     *
     * @param cardId
     *            the card identifier
     * @return card from the Virgil Cards service
     * @throws CryptoException
     *             the crypto exception
     * @throws IOException
     *             the io exception
     */
    public Card getCard(String cardId) throws CryptoException, IOException {
        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));
        Tuple<RawSignedModel, Boolean> response = cardClient.getCard(cardId, token.stringRepresentation());
        Card card = Card.parse(crypto, response.getLeft());

        if (response.getRight()) {
            card.setOutdated(true);
        }

        verifyCard(card);

        return card;
    }

    /**
     * Search for all cards with specified identity.
     *
     * @param identity
     *            the identity to search cards for
     * @return list of cards that corresponds to provided identity
     * @throws CryptoException
     *             the crypto exception
     */
    public List<Card> searchCards(String identity) throws CryptoException {
        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));

        List<RawSignedModel> cardModels = cardClient.searchCards(identity, token.stringRepresentation());

        List<Card> cards = new ArrayList<>();
        for (RawSignedModel cardModel : cardModels)
            cards.add(Card.parse(crypto, cardModel));

        for (Card cardOuter : cards) {
            for (Card cardInner : cards) {
                if (cardOuter.getPreviousCardId().equals(cardInner.getIdentifier())) {
                    cardOuter.setPreviousCard(cardInner);
                    cardInner.setOutdated(true);
                    break;
                }
            }
        }

        List<Card> result = new ArrayList<>();
        for (Card card : cards) {
            if (!card.isOutdated())
                result.add(card);
        }

        return result;
    }

    /**
     * Import card from base64 string .
     *
     * @param card
     *            the card
     * @return imported card from Base64 String
     * @throws CryptoException
     */
    public Card importCardAsString(String card) throws CryptoException {
        String json = ConvertionUtils.base64ToString(card);
        RawSignedModel cardModel = ConvertionUtils.deserializeFromJson(json, RawSignedModel.class);

        return importCardAsRawModel(cardModel);
    }

    /**
     * Import card from json in string format.
     *
     * @param card
     *            the card
     * @return the card
     */
    public Card importCardAsJson(String card) throws CryptoException {
        RawSignedModel cardModel = ConvertionUtils.deserializeFromJson(card, RawSignedModel.class);
        return importCardAsRawModel(cardModel);
    }

    /**
     * Import card from raw signed model.
     *
     * @param cardModel
     *            the card model
     * @return the card
     * @throws CryptoException 
     */
    public Card importCardAsRawModel(RawSignedModel cardModel) throws CryptoException {
        return Card.parse(crypto, cardModel);
    }

    /**
     * Export card as base64 string.
     *
     * @param card
     *            the card
     * @return Base64 String from exported card
     */
    public String exportCardAsString(Card card) {
        return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(card));
    }

    /**
     * Export card as json in string format.
     *
     * @param card
     *            the card
     * @return the string
     */
    public String exportCardAsJson(Card card) {
        return ConvertionUtils.serializeToJson(card);
    }

    /**
     * Export raw signed model from the provided card.
     *
     * @param card
     *            the card
     * @return the raw signed model
     * @throws CryptoException
     *             the crypto exception
     */
    public RawSignedModel exportCardAsRawModel(Card card) throws CryptoException {
        return card.getRawCard();
    }

    /**
     * The interface that provides sign callback to let user perform some custom predefined signing actions when
     * generating raw card.
     */
    public interface SignCallback {
        /**
         * On sign raw signed model callback than will be called when raw card is about to be generated.
         *
         * @param rawSignedModel
         *            the raw signed model
         * @return the raw signed model
         * @see #generateRawCard(PrivateKey, PublicKey, String, String, Map)
         */
        RawSignedModel onSign(RawSignedModel rawSignedModel);
    }
}
