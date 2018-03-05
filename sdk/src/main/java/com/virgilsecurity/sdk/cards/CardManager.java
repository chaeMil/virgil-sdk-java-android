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

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.IncompleteInitializationException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * The {@link CardManager} class provides list of methods to work with {@link Card}.
 */
public class CardManager {
    private static final Logger LOGGER = Logger.getLogger(CardManager.class.getName());

    private static final String CURRENT_CARD_VERSION = "5.0";
    private static final String TOKEN_CONTEXT_OPERATION = "SomeOperation";

    private ModelSigner modelSigner;
    private CardCrypto crypto;
    private AccessTokenProvider accessTokenProvider;
    private CardVerifier cardVerifier;
    private CardClient cardClient;
    private SignCallback signCallback;

    /**
     * Create new instance of {@link CardManager}.
     */
    private CardManager() {
    }

    /**
     * Verifies whether provided {@link Card} is valid with provided {@link CardVerifier}.
     *
     * @param card
     *            to verify
     * @throws CryptoException
     *             if verification of card issue occurred
     */
    private void verifyCard(Card card) throws CryptoException {
        if (!cardVerifier.verifyCard(card)) {
            LOGGER.warning(String.format("Card '%s' verification was failed", card.getIdentifier()));
            throw new VirgilCardVerificationException();
        }
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
        verifyModelSignerNotNull();
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date(),
                previousCardId);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey, ConvertionUtils.captureSnapshot(additionalData));

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
        verifyModelSignerNotNull();
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date(),
                previousCardId);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey);

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
        verifyModelSignerNotNull();
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date());

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey, ConvertionUtils.captureSnapshot(additionalData));

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
        verifyModelSignerNotNull();
        RawCardContent cardContent = new RawCardContent(identity,
                ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), CURRENT_CARD_VERSION, new Date());

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot);
        modelSigner.selfSign(cardModel, privateKey);

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
     * @throws VirgilServiceException
     *             if card was not created by a service
     * @see #generateRawCard(PrivateKey, PublicKey, String)
     */
    public Card publishCard(RawSignedModel cardModel) throws CryptoException, VirgilServiceException {
        Validator.checkNullAgrument(cardModel, "CardManager -> 'cardModel' should not be null");
        verifyCardClientNotNull();

        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));
        RawSignedModel cardModelPublished;

        if (signCallback != null) {
            cardModel = signCallback.onSign(cardModel);
            LOGGER.fine("Card model was signed with signCallback");
        } else {
            LOGGER.fine("Card model was NOT signed with signCallback");
        }

        try {
            cardModelPublished = cardClient.publishCard(cardModel, token.stringRepresentation());
        } catch (VirgilServiceException exceptionOuter) {
            if (exceptionOuter.getHttpError() != null
                    && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                LOGGER.fine("Token is expired, trying to reload...");
                token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, true));
                try {
                    cardModelPublished = cardClient.publishCard(cardModel, token.stringRepresentation());
                } catch (VirgilServiceException exceptionInner) {
                    LOGGER.log(Level.SEVERE, "An error ocurred while publishing a card", exceptionOuter);
                    throw exceptionInner;
                }
            } else {
                if (exceptionOuter.getHttpError() != null) {
                    LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
                            exceptionOuter);
                } else {
                    LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(), exceptionOuter);
                }
                throw exceptionOuter;
            }
        }

        Card card = Card.parse(crypto, cardModelPublished);

        // Be sure that a card received from service is the same card we publishing
        if (!Arrays.equals(cardModel.getContentSnapshot(), cardModelPublished.getContentSnapshot())) {
            LOGGER.warning(
                    "Card that is received from the Cards Service (during publishing) is not equal to the published one");
            throw new VirgilCardServiceException("Server returned a wrong card");
        }

        // Be sure that self signatures are equals
        RawSignature selfSignature = getSignature(SignerType.SELF.getRawValue(), cardModel.getSignatures());
        RawSignature responseSelfSignature = getSignature(SignerType.SELF.getRawValue(),
                cardModelPublished.getSignatures());
        if (selfSignature != null || responseSelfSignature != null) {
            if (selfSignature == null || responseSelfSignature == null) {
                String msg = String.format("Self signature is missing for card %s", card.getIdentifier());
                LOGGER.severe(msg);
                throw new VirgilCardServiceException(msg);
            }

            if (!StringUtils.equals(selfSignature.getSnapshot(), responseSelfSignature.getSnapshot())) {
                String msg = String.format("Self signature was changed by a service for card %s", card.getIdentifier());
                LOGGER.severe(msg);
                throw new VirgilCardServiceException(msg);
            }
        }

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
     * @throws VirgilServiceException
     *             if card was not created by a service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity, String previousCardId,
            Map<String, String> additionalData) throws CryptoException, VirgilServiceException {

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
     * @throws VirgilServiceException
     *             if card was not created by a service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity,
            Map<String, String> additionalData) throws CryptoException, VirgilServiceException {

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
     * @throws VirgilServiceException
     *             if card was not created by a service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity, String previousCardId)
            throws CryptoException, VirgilServiceException {

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
     * @throws VirgilServiceException
     *             if card was not created by a service
     */
    public Card publishCard(PrivateKey privateKey, PublicKey publicKey, String identity)
            throws CryptoException, VirgilServiceException {
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
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws VirgilServiceException
     *             if service call failed
     */
    public Card getCard(String cardId) throws CryptoException, VirgilServiceException {
        verifyCardClientNotNull();
        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));
        Tuple<RawSignedModel, Boolean> response;

        try { // Hell is here (:
            response = cardClient.getCard(cardId, token.stringRepresentation());
        } catch (VirgilServiceException exceptionOuter) {
            if (exceptionOuter.getHttpError() != null
                    && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                LOGGER.fine("Token is expired, trying to reload...");
                token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, true));
                try {
                    response = cardClient.getCard(cardId, token.stringRepresentation());
                } catch (VirgilServiceException exceptionInner) {
                    LOGGER.log(Level.SEVERE, "An error ocurred while retrieving a card", exceptionOuter);
                    throw exceptionInner;
                }
            } else {
                if (exceptionOuter.getHttpError() != null) {
                    LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
                            exceptionOuter);
                } else {
                    LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(), exceptionOuter);
                }
                throw exceptionOuter;
            }
        }

        Card card = Card.parse(crypto, response.getLeft());
        if (!Objects.equals(cardId, card.getIdentifier())) {
            LOGGER.warning(String.format(
                    "Card\'s id ('%s') that received from the Cards Service is not equal to the requested one ('%s')",
                    card.getIdentifier(), cardId));
            throw new VirgilCardServiceException();
        }

        if (response.getRight()) {
            LOGGER.fine("Card is marked as outdated");
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
     *             if issue occurred during get generating token or verifying card that was received from the Virgil
     *             Cards service
     * @throws VirgilServiceException
     *             if service call failed
     */
    public List<Card> searchCards(String identity) throws CryptoException, VirgilServiceException {
        verifyCardClientNotNull();
        AccessToken token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, false));

        List<RawSignedModel> cardModels;
        try {
            cardModels = cardClient.searchCards(identity, token.stringRepresentation());
        } catch (VirgilServiceException exceptionOuter) {
            if (exceptionOuter.getHttpError() != null
                    && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                LOGGER.fine("Token is expired, trying to reload...");
                token = accessTokenProvider.getToken(new TokenContext(TOKEN_CONTEXT_OPERATION, true));
                try {
                    cardModels = cardClient.searchCards(identity, token.stringRepresentation());
                } catch (VirgilServiceException exceptionInner) {
                    LOGGER.log(Level.SEVERE, "An error ocurred while searching for cards", exceptionOuter);
                    throw exceptionInner;
                }
            } else {
                if (exceptionOuter.getHttpError() != null) {
                    LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
                            exceptionOuter);
                } else {
                    LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(), exceptionOuter);
                }
                throw exceptionOuter;
            }
        }

        // Parsing Card models into Cards
        List<Card> cards = new ArrayList<>();
        for (RawSignedModel cardModel : cardModels)
            cards.add(Card.parse(crypto, cardModel));

        // Finding Cards that are outdated (if Card with equal previousCardId is found)
        // and setting them as previousCard for the newer one and marking them as outdated
        for (Card cardOuter : cards) {
            for (Card cardInner : cards) {
                if (cardOuter.getPreviousCardId() != null && cardInner.getPreviousCardId() != null
                        && cardOuter.getIdentifier().equals(cardInner.getIdentifier())) {
                    cardOuter.setPreviousCard(cardInner);
                    cardInner.setOutdated(true);
                    break;
                }
            }
        }

        // Creating Card-chains - it's List of the newest Cards
        // which could have previousCard and is NOT outdated
        List<Card> result = new ArrayList<>();
        for (Card card : cards) {
            if (!card.isOutdated())
                result.add(card);
        }

        // Check if provided for search identity is equal to Cards identities that was found
        // as well as verifying Cards
        for (Card card : result) {
            if (!Objects.equals(identity, card.getIdentity())) {
                LOGGER.warning(String.format("Card '%s' verification was failed", card.getIdentifier()));
                throw new VirgilCardServiceException();
            }

            verifyCard(card);
        }

        return result;
    }

    /**
     * Import card from base64 string .
     *
     * @param cardAsString
     *            the card
     * @return imported card from Base64 String
     * @throws CryptoException
     *             if card importing failed
     */
    public Card importCardAsString(String cardAsString) throws CryptoException {
        RawSignedModel cardModel = RawSignedModel.fromString(cardAsString);
        Card card = Card.parse(crypto, cardModel);

        verifyCard(card);

        return card;
    }

    /**
     * Import card from json in string format.
     *
     * @param cardAsJson
     *            the card
     * @return the card
     * @throws CryptoException
     *             if card importing failed
     */
    public Card importCardAsJson(String cardAsJson) throws CryptoException {
        RawSignedModel cardModel = RawSignedModel.fromJson(cardAsJson);
        Card card = Card.parse(crypto, cardModel);

        verifyCard(card);

        return card;
    }

    /**
     * Import card from raw signed model.
     *
     * @param cardModel
     *            the card model
     * @return the card
     * @throws CryptoException
     *             if any crypto operation failed
     */
    public Card importCardAsRawModel(RawSignedModel cardModel) throws CryptoException {
        Card card = Card.parse(crypto, cardModel);

        verifyCard(card);

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
     * Gets model signer.
     *
     * @return the model signer
     */
    public ModelSigner getModelSigner() {
        return modelSigner;
    }

    /**
     * Gets crypto.
     *
     * @return the crypto
     */
    public CardCrypto getCrypto() {
        return crypto;
    }

    /**
     * Gets access token provider.
     *
     * @return the access token provider
     */
    public AccessTokenProvider getAccessTokenProvider() {
        return accessTokenProvider;
    }

    /**
     * Gets card verifier.
     *
     * @return the card verifier
     */
    public CardVerifier getCardVerifier() {
        return cardVerifier;
    }

    /**
     * Gets card client.
     *
     * @return the card client
     */
    public CardClient getCardClient() {
        return cardClient;
    }

    /**
     * Gets sign callback.
     *
     * @return the sign callback
     */
    public SignCallback getSignCallback() {
        return signCallback;
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

    private RawSignature getSignature(String type, Collection<RawSignature> signatures) {
        if (signatures == null || signatures.isEmpty()) {
            return null;
        }
        for (RawSignature signature : signatures) {
            if (type.equalsIgnoreCase(signature.getSigner())) {
                return signature;
            }
        }
        return null;
    }

    private void verifyModelSignerNotNull() {
        if (this.modelSigner == null) {
            throw new IncompleteInitializationException("Model signer should be set first");
        }
    }

    private void verifyCardClientNotNull() {
        if (this.cardClient == null) {
            throw new IncompleteInitializationException("Card client should be set first");
        }
    }

    /**
     * A builder of {@link CardManager} objects.
     * 
     * @author Andrii Iakovenko
     *
     */
    public static class Builder {
        private CardCrypto cardCrypto;
        private AccessTokenProvider accessTokenProvider;
        private ModelSigner modelSigner;
        private CardVerifier cardVerifier;
        private CardClient cardClient;
        private SignCallback signCallback;

        /**
         * Build Card manager.
         * 
         * @return the instance of {@link CardManager}
         * @throws NullPointerException
         *             if any mandatory parameter is not set.
         */
        public CardManager build() {
            if (this.cardCrypto == null) {
                throw new NullArgumentException("crypto");
            }
            if (this.accessTokenProvider == null) {
                throw new NullArgumentException("accessTokenProvider");
            }
            if (this.cardVerifier == null) {
                throw new NullArgumentException("cardVerifier");
            }

            CardManager manager = new CardManager();
            manager.crypto = this.cardCrypto;
            manager.accessTokenProvider = this.accessTokenProvider;
            manager.modelSigner = this.modelSigner;
            manager.cardVerifier = this.cardVerifier;
            manager.cardClient = this.cardClient;
            manager.signCallback = this.signCallback;

            return manager;
        };

        /**
         * Sets the model signer.
         * 
         * @param modelSigner
         *            the model signer
         */
        public Builder setModelSigner(ModelSigner modelSigner) {
            this.modelSigner = modelSigner;

            return this;
        }

        /**
         * Sets the card crypto.
         * 
         * @param cardCrypto
         *            the card crypto
         */
        public Builder setCrypto(CardCrypto cardCrypto) {
            this.cardCrypto = cardCrypto;

            return this;
        }

        /**
         * Sets the access token provider.
         * 
         * @param accessTokenProvider
         *            the access token provider
         */
        public Builder setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
            this.accessTokenProvider = accessTokenProvider;

            return this;
        }

        /**
         * Sets the card verifier.
         * 
         * @param cardVerifier
         *            the card verifier
         */
        public Builder setCardVerifier(CardVerifier cardVerifier) {
            this.cardVerifier = cardVerifier;

            return this;
        }

        /**
         * Sets the card client.
         * 
         * @param cardClient
         *            the card client
         */
        public Builder setCardClient(CardClient cardClient) {
            this.cardClient = cardClient;

            return this;
        }

        /**
         * Sets the sign callback.
         * 
         * @param signCallback
         *            the sign callback
         */
        public Builder setSignCallback(SignCallback signCallback) {
            this.signCallback = signCallback;

            return this;
        }
    }
}
