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

import com.virgilsecurity.sdk.CompatibilityDataProvider;
import com.virgilsecurity.sdk.cards.CardManager.SignCallback;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.*;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.JSON;
import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static com.virgilsecurity.sdk.utils.TestUtils.assertCardsEquals;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class CardsManagerTest extends PropertyManager {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String SIGNER_TYPE_EXTRA = "bestsignerever";

    private Mocker mocker;
    private VirgilCrypto crypto;
    private CardCrypto cardCrypto;
    private CardClient cardClient;
    private CardManager cardManager;
    private VirgilCardVerifier cardVerifier;
    private CompatibilityDataProvider dataProvider;

    @Before
    public void setUp() {
        mocker = new Mocker();
        crypto = new VirgilCrypto();
        cardCrypto = new VirgilCardCrypto();
        String url = getCardsServiceUrl();
        if (StringUtils.isBlank(url)) {
            cardClient = new CardClient();
        } else {
            cardClient = new CardClient(url);
        }
        cardVerifier = new VirgilCardVerifier(cardCrypto);
        dataProvider = new CompatibilityDataProvider();
    }

    private void initCardManager(String identity) {
        
        cardManager = new CardManager(cardCrypto,
                                      new GeneratorJwtProvider(mocker.getJwtGenerator(), identity),
                                      cardVerifier,
                                      cardClient,
                                      new CardManager.SignCallback() {
                                          @Override
                                          public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                                              return rawSignedModel;
                                          }
                                      },
                                      false);
    }

    private CardManager init_STC_13() throws CryptoException, VirgilServiceException {
        CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(false);

        RawSignedModel modelFromString = RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING));

        CardClient cardClientMock = Mockito.mock(CardClient.class);
        Mockito.when(cardClientMock.publishCard(Mockito.any(RawSignedModel.class), Mockito.anyString()))
                .thenReturn(modelFromString);
        Mockito.when(cardClientMock.getCard(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(new Tuple<>(modelFromString, false));
        Mockito.when(cardClientMock.searchCards(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(Collections.singletonList(modelFromString));

        AccessToken jwt = Mockito.mock(AccessToken.class);
        Mockito.when(jwt.stringRepresentation()).thenReturn("");

        AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
        Mockito.when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

        return new CardManager(cardCrypto,
                               accessTokenProvider,
                               cardVerifier,
                               cardClientMock,
                               new CardManager.SignCallback() {
                                   @Override
                                   public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                                       return rawSignedModel;
                                   }
                               },
                               false);
    }

    @Test
    public void STC_13_2() throws CryptoException, VirgilServiceException {
        CardManager virgilCardManager = init_STC_13();
        expectedException.expect(VirgilCardVerificationException.class);
        virgilCardManager.importCardAsString(dataProvider.getTestDataAs(3, STRING));
    }

    @Test
    public void STC_13_3() throws CryptoException, VirgilServiceException {
        CardManager virgilCardManager = init_STC_13();
        expectedException.expect(VirgilCardVerificationException.class);
        virgilCardManager.importCardAsJson(dataProvider.getTestDataAs(3, JSON));
    }

    @Test
    public void STC_13_4() throws CryptoException, VirgilServiceException {
        CardManager virgilCardManager = init_STC_13();
        expectedException.expect(VirgilCardVerificationException.class);
        virgilCardManager.publishCard(RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
    }

    @Test
    public void STC_13_5() throws CryptoException, VirgilServiceException {
        CardManager virgilCardManager = init_STC_13();
        expectedException.expect(VirgilCardVerificationException.class);
        Card card = Card.parse(cardCrypto, RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
        virgilCardManager.getCard(card.getIdentifier());
    }

    @Test
    public void STC_13_6() throws CryptoException, VirgilServiceException {
        init_STC_13();
    }

    @Test
    public void STC_13_7() throws CryptoException, VirgilServiceException {
        CardManager virgilCardManager = init_STC_13();
        expectedException.expect(VirgilCardVerificationException.class);
        Card card = Card.parse(cardCrypto, RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
        virgilCardManager.searchCards(card.getIdentity());
    }

    @Test
    public void STC_17() throws CryptoException, VirgilServiceException {
        String identity = Generator.identity();
        initCardManager(identity);

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity);
        Card generatedCard = Card.parse(cardCrypto, cardModel);
        Card publishedCard = cardManager.publishCard(cardModel);
        assertNotNull(publishedCard);

        assertFalse(publishedCard.isOutdated());
        assertCardsEquals(generatedCard, publishedCard);

        Card cardFromService = cardManager.getCard(generatedCard.getIdentifier());
        assertNotNull(cardFromService);
        assertFalse(cardFromService.isOutdated());
        assertCardsEquals(generatedCard, cardFromService);
    }

    @Test
    public void STC_18() throws CryptoException, VirgilServiceException {
        String identity = Generator.identity();
        initCardManager(identity);

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put("Sense of life", "42");
        additionalData.put("Secret but not secret", "idn");

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity, additionalData);
        Card generatedCard = Card.parse(cardCrypto, cardModel);
        Card publishedCard = cardManager.publishCard(cardModel);
        assertNotNull(publishedCard);

        assertFalse(publishedCard.isOutdated());
        assertCardsEquals(generatedCard, publishedCard);

        Card cardFromService = cardManager.getCard(generatedCard.getIdentifier());
        assertNotNull(cardFromService);
        assertFalse(cardFromService.isOutdated());
        assertCardsEquals(generatedCard, cardFromService);
    }

    @Test
    public void STC_19() throws CryptoException, VirgilServiceException, InterruptedException {
        String identity = Generator.identity();
        initCardManager(identity);

        VirgilKeyPair keyPairVirgiled1 = crypto.generateKeys();
        RawSignedModel cardModel1 = cardManager.generateRawCard(keyPairVirgiled1.getPrivateKey(),
                keyPairVirgiled1.getPublicKey(), identity);
        Card generatedCard1 = Card.parse(cardCrypto, cardModel1);
        Card publishedCard1 = cardManager.publishCard(cardModel1);
        assertNotNull(publishedCard1);

        assertFalse(publishedCard1.isOutdated());
        assertCardsEquals(generatedCard1, publishedCard1);

        Card cardFromService1 = cardManager.getCard(generatedCard1.getIdentifier());
        assertNotNull(cardFromService1);
        assertFalse(cardFromService1.isOutdated());
        assertCardsEquals(generatedCard1, cardFromService1);

        // Generate KeyPair2
        VirgilKeyPair keyPairVirgiled2 = crypto.generateKeys();
        RawSignedModel cardModel2 = cardManager.generateRawCard(keyPairVirgiled2.getPrivateKey(),
                keyPairVirgiled2.getPublicKey(), identity, generatedCard1.getIdentifier());
        Card generatedCard2 = Card.parse(cardCrypto, cardModel2);

        // Call publishCard(privateKey2, publicKey2, Card1.identifier)
        Card publishedCard2 = cardManager.publishCard(cardModel2);
        // Card2 is successfully created and matches card that was generated on the client side
        assertNotNull(publishedCard2);
        assertFalse(publishedCard2.isOutdated());
        assertCardsEquals(generatedCard2, publishedCard2);
        assertEquals(cardFromService1.getIdentifier(), publishedCard2.getPreviousCardId());

        // Get Card2 using getCard
        Card cardFromService2 = cardManager.getCard(generatedCard2.getIdentifier());
        // Card2 is successfully retrieved and matches card that was generated on the client side (including
        // previousCardId and isOutdated=false).
        assertNotNull(cardFromService2);
        assertFalse(cardFromService2.isOutdated());
        assertCardsEquals(generatedCard2, cardFromService2);
        assertEquals(cardFromService1.getIdentifier(), cardFromService2.getPreviousCardId());

        // Get Card1 using getCard
        Card outdatedCard = cardManager.getCard(generatedCard1.getIdentifier());
        // Card1 is successfully retrieved and matches card that was generated on the client side. (isOutdated=true)
        assertNotNull(outdatedCard);
        assertTrue(outdatedCard.isOutdated());
        generatedCard1.setOutdated(true);
        assertCardsEquals(generatedCard1, outdatedCard);
    }

    @Test
    public void STC_20() throws CryptoException, VirgilServiceException {
        String identity = Generator.identity();
        initCardManager(identity);

        VirgilKeyPair keyPairVirgiledOne = crypto.generateKeys();
        RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
                keyPairVirgiledOne.getPublicKey(), identity);
        Card publishedCardOne = cardManager.publishCard(cardModelOne);
        assertNotNull(publishedCardOne);

        VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeys();
        RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
                keyPairVirgiledTwo.getPublicKey(), identity, publishedCardOne.getIdentifier());
        Card publishedCardTwo = cardManager.publishCard(cardModelTwo);
        assertNotNull(publishedCardTwo);

        VirgilKeyPair keyPairVirgiledThree = crypto.generateKeys();
        RawSignedModel cardModelThree = cardManager.generateRawCard(keyPairVirgiledThree.getPrivateKey(),
                keyPairVirgiledThree.getPublicKey(), identity);
        Card publishedCardThree = cardManager.publishCard(cardModelThree);
        assertNotNull(publishedCardThree);

        List<Card> searchedCards = cardManager.searchCards(identity);
        assertNotNull(searchedCards);
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
    public void STC_21() throws CryptoException, VirgilServiceException {
        String identity = Generator.identity();

        CardManager cardManagerExtraSign = new CardManager(cardCrypto,
                                                           new GeneratorJwtProvider(mocker.getJwtGenerator(), identity),
                                                           cardVerifier,
                                                           cardClient,
                                                           new CardManager.SignCallback() {
                                                               @Override
                                                               public RawSignedModel onSign(RawSignedModel cardModel) {
                                                                   ModelSigner modelSigner = new ModelSigner(cardCrypto);
                                                                   try {
                                                                       VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
                                                                       modelSigner.sign(cardModel, SIGNER_TYPE_EXTRA, keyPairVirgiled.getPrivateKey());
                                                                   } catch (CryptoException e) {
                                                                       fail(e.getMessage());
                                                                   }

                                                                   return cardModel;
                                                               }
                                                           },
                                                           false);

        VirgilKeyPair keyPairVirgiled = crypto.generateKeys();
        RawSignedModel cardModel = cardManagerExtraSign.generateRawCard(keyPairVirgiled.getPrivateKey(),
                keyPairVirgiled.getPublicKey(), identity);
        Card generatedCard = Card.parse(cardCrypto, cardModel);

        Card publishedCard = cardManagerExtraSign.publishCard(cardModel);
        assertNotNull(publishedCard);
        assertEquals(publishedCard.getSignatures().size(), 3);

        assertCardsEquals(generatedCard, publishedCard);
    }

    @Test
    public void STC_34() throws CryptoException, VirgilServiceException {
        ModelSigner modelSigner = new ModelSigner(this.cardCrypto);
        AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
        CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        CardClient cardClient = Mockito.mock(CardClient.class);
        SignCallback signCallback = Mockito.mock(SignCallback.class);
        CardManager cardManager = new CardManager(this.cardCrypto,
                                                  accessTokenProvider,
                                                  cardVerifier,
                                                  cardClient,
                                                  signCallback,
                                                  false);
        Jwt jwt = Mockito.mock(Jwt.class);

        when(jwt.stringRepresentation()).thenReturn("");
        when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

        String cardId = "375f795bf6799b18c4836d33dce5208daf0895a3f7aacbcd0366529aed2345d4";
        RawSignedModel cardModel = RawSignedModel.fromString(dataProvider.getString("STC-34.as_string"));
        Tuple<RawSignedModel, Boolean> tuple = new Tuple<RawSignedModel, Boolean>(cardModel, false);
        when(cardClient.getCard(Mockito.anyString(), Mockito.anyString())).thenReturn(tuple);

        try {
            cardManager.getCard(cardId);
            fail("Service returned wrong card, but we didn't recognized that");
        } catch (VirgilCardServiceException e) {
            // It's OK if Error is thrown
        }
    }

    private CardManager init_STC_35() throws CryptoException, VirgilServiceException {
        CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

        RawSignedModel modelFromString = RawSignedModel.fromString(dataProvider.getTestDataAs(34, STRING));

        CardClient cardClientMock = Mockito.mock(CardClient.class);
        Mockito.when(cardClientMock.publishCard(Mockito.any(RawSignedModel.class), Mockito.anyString()))
                .thenReturn(modelFromString);

        AccessToken jwt = Mockito.mock(AccessToken.class);
        Mockito.when(jwt.stringRepresentation()).thenReturn(UUID.randomUUID().toString());

        AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
        Mockito.when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

        return new CardManager(cardCrypto,
                               accessTokenProvider,
                               cardVerifier,
                               cardClient,
                               new CardManager.SignCallback() {
                                   @Override
                                   public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                                       return rawSignedModel;
                                   }
                               },
                               false);
    }

    @Test
    public void STC_35_1() throws VirgilServiceException, CryptoException {
        CardManager virgilCardManager = init_STC_35();

        RawCardContent cardContent = new RawCardContent(Generator.identity(),
                dataProvider.getJsonByKey(34, "public_key_base64"), new Date());
        RawSignedModel rawSignedModelTwo = new RawSignedModel(cardContent.exportAsBase64String());

        ModelSigner signer = new ModelSigner(cardCrypto);
        VirgilPrivateKey privateKey = crypto
                .importPrivateKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "private_key_base64")));
        signer.selfSign(rawSignedModelTwo, privateKey,
                ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "self_signature_snapshot_base64")));

        expectedException.expect(VirgilCardServiceException.class);
        virgilCardManager.publishCard(rawSignedModelTwo);
    }

    @Test
    public void STC_35_2() throws VirgilServiceException, CryptoException {
        CardManager virgilCardManager = init_STC_35();

        ModelSigner signer = new ModelSigner(cardCrypto);
        VirgilPrivateKey privateKey = crypto
                .importPrivateKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "private_key_base64")));

        RawSignedModel rawSignedModel = new RawSignedModel(
                ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "content_snapshot_base64")));
        signer.selfSign(rawSignedModel, privateKey, Generator.randomBytes(64));

        expectedException.expect(VirgilCardServiceException.class);
        virgilCardManager.publishCard(rawSignedModel);
    }
}
