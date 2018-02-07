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

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.common.StringEncoding;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.virgilsecurity.sdk.utils.TestUtils.assertCardsEquals;
import static org.junit.Assert.*;

public class CardsManagerTest extends PropertyManager {

    private static final String SIGNER_TYPE_EXTRA = "bestsignerever";

    private Mocker mocker;
    private VirgilCrypto crypto;
    private CardCrypto cardCrypto;
    private CardClient cardClient;
    private CardManager cardManager;
    private VirgilCardVerifier cardVerifier;

    @Before
    public void setUp() {
        mocker = new Mocker();
        crypto = new VirgilCrypto();
        cardCrypto = new VirgilCardCrypto();
        cardClient = new CardClient(CARDS_SERVICE_URL);
        cardVerifier = new VirgilCardVerifier(cardCrypto);
        cardManager = new CardManager(cardCrypto,
                new GeneratorJwtProvider(mocker.getJwtGenerator(), Generator.identity()), new ModelSigner(cardCrypto),
                cardClient, cardVerifier, new CardManager.SignCallback() {
                    @Override
                    public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                        return rawSignedModel;
                    }
                });

//        PlatformLogger.getLogger("sun.net.www.protocol.http.HttpURLConnection").setLevel(PlatformLogger.Level.ALL);
    }

    @Test
    public void publishAndGet() throws IOException, CryptoException {
        String identity = Generator.identity();

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity);
        Card generatedCard = Card.parse(cardCrypto, cardModel);
        Card publishedCard = null;
        try {
            publishedCard = cardManager.publishCard(cardModel);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        assertFalse(publishedCard.isOutdated());
        assertCardsEquals(generatedCard, publishedCard);

        Card cardFromService = null;
        try {
            cardFromService = cardManager.getCard(generatedCard.getIdentifier());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertFalse(cardFromService.isOutdated());
        assertCardsEquals(generatedCard, cardFromService);
    }

    @Test
    public void publishAndGetWithMeta() throws IOException, CryptoException {
        String identity = Generator.identity();

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put("Sense of life", "42");
        additionalData.put("Secret but not secret", "idn");

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity, additionalData);
        Card generatedCard = Card.parse(cardCrypto, cardModel);
        Card publishedCard = null;
        try {
            publishedCard = cardManager.publishCard(cardModel);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        assertFalse(publishedCard.isOutdated());
        assertCardsEquals(generatedCard, publishedCard);

        Card cardFromService = null;
        try {
            cardFromService = cardManager.getCard(generatedCard.getIdentifier());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertFalse(cardFromService.isOutdated());
        assertCardsEquals(generatedCard, cardFromService);
    }

    @Test
    public void publishAndGetOutdated() throws IOException, CryptoException {
        String identity = Generator.identity();

        VirgilKeyPair keyPairVirgiledOne = crypto.generateKeys();
        RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
                keyPairVirgiledOne.getPublicKey(), identity);
        Card generatedCardOne = Card.parse(cardCrypto, cardModelOne);
        Card publishedCardOne = null;
        try {
            publishedCardOne = cardManager.publishCard(cardModelOne);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        assertFalse(publishedCardOne.isOutdated());
        assertCardsEquals(generatedCardOne, publishedCardOne);

        Card cardFromServiceOne = null;
        try {
            cardFromServiceOne = cardManager.getCard(generatedCardOne.getIdentifier());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertFalse(cardFromServiceOne.isOutdated());
        assertCardsEquals(generatedCardOne, cardFromServiceOne);

        VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeys();
        RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
                keyPairVirgiledTwo.getPublicKey(), identity, generatedCardOne.getIdentifier());
        Card generatedCardTwo = Card.parse(cardCrypto, cardModelTwo);
        Card publishedCardTwo = null;
        try {
            publishedCardTwo = cardManager.publishCard(cardModelTwo);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        assertFalse(publishedCardTwo.isOutdated());
        assertCardsEquals(generatedCardTwo, publishedCardTwo);

        Card cardFromServiceTwo = null;
        try {
            cardFromServiceTwo = cardManager.getCard(generatedCardTwo.getIdentifier());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertFalse(cardFromServiceTwo.isOutdated());
        assertCardsEquals(generatedCardTwo, cardFromServiceTwo);

        Card outdatedCard = null;
        try {
            outdatedCard = cardManager.getCard(generatedCardOne.getIdentifier());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertTrue(outdatedCard.isOutdated());
        outdatedCard.setOutdated(false);
        assertCardsEquals(generatedCardOne, outdatedCard);
    }

    @Test
    public void searchChainsWithOutdated() throws CryptoException, IOException {
        String identity = Generator.identity();

        VirgilKeyPair keyPairVirgiledOne = crypto.generateKeys();
        RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
                keyPairVirgiledOne.getPublicKey(), identity);
        Card publishedCardOne = null;
        try {
            publishedCardOne = cardManager.publishCard(cardModelOne);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeys();
        RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
                keyPairVirgiledTwo.getPublicKey(), identity, publishedCardOne.getIdentifier());
        Card publishedCardTwo = null;
        try {
            publishedCardTwo = cardManager.publishCard(cardModelTwo);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        VirgilKeyPair keyPairVirgiledThree = crypto.generateKeys();
        RawSignedModel cardModelThree = cardManager.generateRawCard(keyPairVirgiledThree.getPrivateKey(),
                keyPairVirgiledThree.getPublicKey(), identity);
        Card publishedCardThree = null;
        try {
            publishedCardThree = cardManager.publishCard(cardModelThree);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        List<Card> searchedCards = null;
        try {
            searchedCards = cardManager.searchCards(identity);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }
        assertTrue(searchedCards.size() == 2);

        Card singleCardFromChain = null;
        for (Card card : searchedCards) {
            if (card.getIdentifier().equals(publishedCardTwo.getIdentifier())) {
                assertEquals(publishedCardOne.getIdentifier(), card.getPreviousCardId());
                assertEquals(publishedCardOne, card.getPreviousCard());
                assertFalse(card.isOutdated());
            } else if (card.getIdentifier().equals(publishedCardThree.getIdentifier())) {
                singleCardFromChain = card;
            }
        }

        assertCardsEquals(publishedCardThree, singleCardFromChain);
    }

    @Test
    public void publishCardExtraSign() throws CryptoException, IOException {
        String identity = Generator.identity();
        CardManager cardManagerExtraSign = new CardManager(cardCrypto,
                new GeneratorJwtProvider(mocker.getJwtGenerator(), Generator.identity()), new ModelSigner(cardCrypto),
                cardClient, cardVerifier, new CardManager.SignCallback() {
                    @Override
                    public RawSignedModel onSign(RawSignedModel cardModel) {
                        ModelSigner modelSigner = new ModelSigner(cardCrypto);
                        String signerId = null;
                        try {
                            VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
                            signerId = ConvertionUtils.toString(
                                    cardCrypto.generateSHA512(cardModel.getContentSnapshot()), StringEncoding.HEX);
                            modelSigner.sign(cardModel, signerId, SIGNER_TYPE_EXTRA, keyPairVirgiled.getPrivateKey());
                        } catch (CryptoException e) {
                            e.printStackTrace();
                            fail();
                        }

                        return cardModel;
                    }
                });

        // Map<String, String> additionalData = new HashMap<>();
        // additionalData.put("Sense of life", "42");
        // additionalData.put("Secret but not secret", "idn");

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManagerExtraSign.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity);
        Card generatedCard = Card.parse(cardCrypto, cardModel);

        assertEquals(generatedCard.getSignatures().size(), 2);

        Card publishedCard = null;
        try {
            publishedCard = cardManagerExtraSign.publishCard(cardModel);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
        }

        assertCardsEquals(generatedCard, publishedCard);
    }
}
