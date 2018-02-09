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

package com.virgilsecurity.sdk;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.JwtVerifier;
import com.virgilsecurity.sdk.jwt.accessProviders.ConstAccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.JSON;
import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static org.junit.Assert.*;

public class CrossCompatibilityTest {

    private CompatibilityDataProvider dataProvider;

    @Before
    public void setUp() {
        dataProvider = new CompatibilityDataProvider();
    }

    @Test
    public void STC_1_json() {
        String importedFromJson = dataProvider.getTestDataAs(1, JSON);
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals("TUNvd0JRWURLMlZ3QXlFQTZkOWJRUUZ1RW5VOHZTbXg5ZkRvMFd4ZWM0MkpkTmc0VlI0Rk9yNC9CVWs9",
                     ConvertionUtils.toBase64String(cardContent.getPublicKey()));
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void STC_1_string() {
        String importedFromString = dataProvider.getTestDataAs(1, STRING);
        ;
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=",
                     cardContent.getPublicKey());
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void STC_2_json() {
        String importedFromJson = dataProvider.getTestDataAs(2, JSON);
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=", cardContent.getPublicKey());
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertEquals(cardContent.getPreviousCardId(),
                     "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
        assertEquals(cardModel.getSignatures().size(), 3);

        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "virgil":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "extra":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQAAJD/9HE6iJwPHXuws+WBBUeG6HXB0eJcxojz9DtElJMPkkDxktgv/pBiBTkES3CAXfAtGS0rkvQL/OkjdCZwE=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                default:
                    fail();
                    break;
            }
        }
    }

    @Test
    public void STC_2_string() throws IOException {
        String importedFromString = dataProvider.getTestDataAs(2, STRING);
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=", cardContent.getPublicKey());
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertEquals(cardContent.getPreviousCardId(),
                     "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
        assertEquals(cardModel.getSignatures().size(), 3);


        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "virgil":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "extra":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQAAJD/9HE6iJwPHXuws+WBBUeG6HXB0eJcxojz9DtElJMPkkDxktgv/pBiBTkES3CAXfAtGS0rkvQL/OkjdCZwE=",
                            rawSignature.getSignature());
                    assertNull(rawSignature.getSnapshot());
                    break;
                default:
                    fail();
                    break;
            }
        }
    }

    @Test
    public void STC_3_json() throws IOException, CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto, new ConstAccessTokenProvider(),
                                                  new ModelSigner(cardCrypto), new CardClient(), cardVerifier,
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = dataProvider.getTestDataAs(3, JSON);
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(dataProvider.getJsonByKey(3, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 0);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 17);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        calendar.clear(Calendar.MILLISECOND);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }

    @Test
    public void STC_3_string() throws CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto, new ConstAccessTokenProvider(),
                                                  new ModelSigner(cardCrypto), new CardClient(), cardVerifier,
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromString = dataProvider.getTestDataAs(3, STRING);
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromString));

        assertEquals(dataProvider.getJsonByKey(3, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 0);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 17);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        calendar.clear(Calendar.MILLISECOND);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }
    // TODO: 1/30/18 test Card.parse

    @Test
    public void STC_4_json() throws CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto, new ConstAccessTokenProvider(),
                                                  new ModelSigner(cardCrypto), new CardClient(), cardVerifier,
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = dataProvider.getTestDataAs(4, JSON);
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(dataProvider.getJsonByKey(4, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertArrayEquals(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(4, "public_key_base64")),
                          ((VirgilPublicKey) card.getPublicKey()).getRawKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 0);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 17);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        calendar.clear(Calendar.MILLISECOND);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(card.getSignatures().size(), 3);

        for (CardSignature rawSignature : card.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r+RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm/oc1wRUzk7ccz1RbTWEt2XP+1GbkF0Z6s6FYf1QEUQI=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "virgil":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r+RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm/oc1wRUzk7ccz1RbTWEt2XP+1GbkF0Z6s6FYf1QEUQI=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "extra":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQMZrDdHSSDbE2Hadr7XWRgi4SlSN1etOpk+2DdvYCI/LRfwXwuaof/piA3nTKKPAZcRtvCuG7+DrDGzeDTepZgg=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                default:
                    fail();
                    break;
            }
        }
    }

    @Test
    public void STC_4_string() throws CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto, new ConstAccessTokenProvider(),
                                                  new ModelSigner(cardCrypto), new CardClient(), cardVerifier,
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromString = dataProvider.getTestDataAs(4, STRING);
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromString));

        assertEquals(dataProvider.getJsonByKey(4, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertArrayEquals(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(4, "public_key_base64")),
                          ((VirgilPublicKey) card.getPublicKey()).getRawKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 0);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 17);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        calendar.clear(Calendar.MILLISECOND);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(card.getSignatures().size(), 3);

        for (CardSignature rawSignature : card.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r+RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm/oc1wRUzk7ccz1RbTWEt2XP+1GbkF0Z6s6FYf1QEUQI=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "virgil":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r+RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm/oc1wRUzk7ccz1RbTWEt2XP+1GbkF0Z6s6FYf1QEUQI=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                case "extra":
                    assertEquals(
                            "MFEwDQYJYIZIAWUDBAIDBQAEQMZrDdHSSDbE2Hadr7XWRgi4SlSN1etOpk+2DdvYCI/LRfwXwuaof/piA3nTKKPAZcRtvCuG7+DrDGzeDTepZgg=",
                            ConvertionUtils.toBase64String(rawSignature.getSignature()));
                    assertNull(rawSignature.getSnapshot());
                    break;
                default:
                    fail();
                    break;
            }
        }
    }

    @Test
    public void STC_22() throws CryptoException {
        final String apiPublicKey = dataProvider
                .getJsonByKey(22, "api_public_key_base64"); // TODO: 2/6/18 from test_data
        final String apiPublicKeyIdentifier = dataProvider.getJsonByKey(22, "api_key_id");
        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
        VirgilCrypto crypto = new VirgilCrypto();
        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                                                  apiPublicKeyIdentifier, accessTokenSigner);

        String jwtImported = dataProvider.getJsonByKey(22, "jwt");
        Jwt jwt = new Jwt(jwtImported);

        assertTrue(jwtVerifier.verifyToken(jwt));
    }

    @Test
    public void STC_23() throws CryptoException {
        final String apiPublicKey = dataProvider.getJsonByKey(23, "api_public_key_base64");
        final String apiPublicKeyIdentifier = dataProvider.getJsonByKey(23, "api_key_id");
        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
        VirgilCrypto crypto = new VirgilCrypto();
        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                                                  apiPublicKeyIdentifier, accessTokenSigner);

        PrivateKey privateKey = crypto.importPrivateKey(
                ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(23, "api_private_key_base64")));
        JwtGenerator jwtGenerator = new JwtGenerator(dataProvider.getJsonByKey(23, "app_id"), privateKey,
                                                     dataProvider.getJsonByKey(23, "api_public_key_base64"),
                                                     TimeSpan.fromTime(1, TimeUnit.HOURS),
                                                     accessTokenSigner);
        Jwt jwt = jwtGenerator.generateToken("test");

        assertTrue(jwtVerifier.verifyToken(jwt));
    }
}
