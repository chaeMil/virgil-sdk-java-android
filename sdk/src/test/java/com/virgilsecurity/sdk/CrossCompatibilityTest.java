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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.common.PropertyManager;
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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.JSON;
import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static org.junit.Assert.*;

public class CrossCompatibilityTest extends PropertyManager {

    private static final String CREATED_AT = "created_at";
    private static final String IDENTITY = "identity";
    private static final String PREVIOUS_CARD_ID = "previous_card_id";
    private static final String PUBLIC_KEY = "public_key";
    private static final String VERSION = "version";

    private static final String CONTENT_SNAPSHOT = "content_snapshot";
    private static final String SIGNATURES = "signatures";
    private static final String SELF = "self";
    private static final String VIRGIL = "virgil";
    private static final String EXTRA = "extra";

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

        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=", cardContent.getPublicKey());
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void STC_2_json() {
        JsonObject baseData = dataProvider.getJsonObject(2);
        String importedFromJson = dataProvider.getTestDataAs(2, JSON);
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(getFromSnapshot(baseData, IDENTITY), cardContent.getIdentity());
        assertEquals(getFromSnapshot(baseData, PUBLIC_KEY), cardContent.getPublicKey());
        assertEquals(getFromSnapshot(baseData, VERSION), cardContent.getVersion());
        assertEquals(Long.parseLong(getFromSnapshot(baseData, CREATED_AT)), cardContent.getCreatedAtTimestamp());
        assertEquals(getFromSnapshot(baseData, PREVIOUS_CARD_ID), cardContent.getPreviousCardId());
        assertEquals(3, cardModel.getSignatures().size());

        Map<String, String> signatures = extractSignatures(baseData);

        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
            case SELF:
                assertEquals(signatures.get(SELF), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            case VIRGIL:
                assertEquals(signatures.get(VIRGIL), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            case EXTRA:
                assertEquals(signatures.get(EXTRA), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            default:
                fail();
                break;
            }
        }
    }

    @Test
    public void STC_2_string() {
        JsonObject baseData = dataProvider.getJsonObject(2);
        String importedFromString = dataProvider.getTestDataAs(2, STRING);
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(getFromSnapshot(baseData, IDENTITY), cardContent.getIdentity());
        assertEquals(getFromSnapshot(baseData, PUBLIC_KEY), cardContent.getPublicKey());
        assertEquals(getFromSnapshot(baseData, VERSION), cardContent.getVersion());
        assertEquals(Long.parseLong(getFromSnapshot(baseData, CREATED_AT)), cardContent.getCreatedAtTimestamp());
        assertEquals(getFromSnapshot(baseData, PREVIOUS_CARD_ID), cardContent.getPreviousCardId());
        assertEquals(3, cardModel.getSignatures().size());

        Map<String, String> signatures = extractSignatures(baseData);

        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
            case SELF:
                assertEquals(signatures.get(SELF), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            case VIRGIL:
                assertEquals(signatures.get(VIRGIL), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            case EXTRA:
                assertEquals(signatures.get(EXTRA), rawSignature.getSignature());
                assertNull(rawSignature.getSnapshot());
                break;
            default:
                fail();
                break;
            }
        }
    }

    @Test
    public void STC_3_json() throws CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class),
                                                  false);

        String importedFromJson = dataProvider.getTestDataAs(3, JSON);
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(dataProvider.getJsonByKey(3, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");

        RawSignedModel rawSignedModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent rawCardContent = RawCardContent.fromString(ConvertionUtils.toBase64String(rawSignedModel.getContentSnapshot()));

        assertEquals(rawCardContent.getCreatedAtTimestamp(), card.getCreatedAt().getTime() / 1000);
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }

    @Test
    public void STC_3_string() throws CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class),
                                                  false);

        String importedFromString = dataProvider.getTestDataAs(3, STRING);
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromString));

        assertEquals(dataProvider.getJsonByKey(3, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");

        RawSignedModel rawSignedModel = RawSignedModel.fromString(importedFromString);
        RawCardContent rawCardContent = RawCardContent.fromString(ConvertionUtils.toBase64String(rawSignedModel.getContentSnapshot()));

        assertEquals(rawCardContent.getCreatedAtTimestamp(), card.getCreatedAt().getTime() / 1000);
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }
    // TODO: 1/30/18 test Card.parse

    @Test
    public void STC_4_json() throws CryptoException {
        JsonObject baseData = dataProvider.getJsonObject(4);
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class),
                                                  false);

        String importedFromJson = dataProvider.getTestDataAs(4, JSON);
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(dataProvider.getJsonByKey(4, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertArrayEquals(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(4, "public_key_base64")),
                ((VirgilPublicKey) card.getPublicKey()).getRawKey());
        assertEquals(card.getVersion(), "5.0");

        RawSignedModel rawSignedModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent rawCardContent = RawCardContent.fromString(ConvertionUtils.toBase64String(rawSignedModel.getContentSnapshot()));

        assertEquals(rawCardContent.getCreatedAtTimestamp(), card.getCreatedAt().getTime() / 1000);
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(3, card.getSignatures().size());

        Map<String, String> signatures = extractSignatures(baseData);

        for (CardSignature rawSignature : card.getSignatures()) {
            switch (rawSignature.getSigner()) {
            case SELF:
                assertEquals(signatures.get(SELF), ConvertionUtils.toBase64String(rawSignature.getSignature()));
                assertNull(rawSignature.getSnapshot());
                break;
            case VIRGIL:
                assertEquals(signatures.get(VIRGIL), ConvertionUtils.toBase64String(rawSignature.getSignature()));
                assertNull(rawSignature.getSnapshot());
                break;
            case EXTRA:
                assertEquals(signatures.get(EXTRA), ConvertionUtils.toBase64String(rawSignature.getSignature()));
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
        JsonObject baseData = dataProvider.getJsonObject(4);
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class),
                                                  false);

        String importedFromString = dataProvider.getTestDataAs(4, STRING);
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromString));

        assertEquals(dataProvider.getJsonByKey(4, "card_id"), card.getIdentifier());
        assertEquals(card.getIdentity(), "test");
        assertArrayEquals(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(4, "public_key_base64")),
                ((VirgilPublicKey) card.getPublicKey()).getRawKey());
        assertEquals(card.getVersion(), "5.0");

        RawSignedModel rawSignedModel = RawSignedModel.fromString(importedFromString);
        RawCardContent rawCardContent = RawCardContent.fromString(ConvertionUtils.toBase64String(rawSignedModel.getContentSnapshot()));

        assertEquals(rawCardContent.getCreatedAtTimestamp(), card.getCreatedAt().getTime() / 1000);
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(card.getSignatures().size(), 3);

        Map<String, String> signatures = extractSignatures(baseData);

        for (CardSignature rawSignature : card.getSignatures()) {
            switch (rawSignature.getSigner()) {
            case SELF:
                assertEquals(signatures.get(SELF), ConvertionUtils.toBase64String(rawSignature.getSignature()));
                assertNull(rawSignature.getSnapshot());
                break;
            case VIRGIL:
                assertEquals(signatures.get(VIRGIL), ConvertionUtils.toBase64String(rawSignature.getSignature()));
                assertNull(rawSignature.getSnapshot());
                break;
            case EXTRA:
                assertEquals(signatures.get(EXTRA), ConvertionUtils.toBase64String(rawSignature.getSignature()));
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
        final String apiPublicKey = dataProvider.getJsonByKey(22, "api_public_key_base64"); // TODO: 2/6/18 from
        // test_data
        final String apiPublicKeyIdentifier = dataProvider.getJsonByKey(22, "api_key_id");
        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
        VirgilCrypto crypto = new VirgilCrypto();
        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                apiPublicKeyIdentifier, accessTokenSigner);

        final String jwtImported = dataProvider.getJsonByKey(22, "jwt");
        final Jwt jwt = new Jwt(jwtImported);

        assertTrue(jwtVerifier.verifyToken(jwt));
    }

    @Test
    public void STC_23() throws CryptoException {
        final String apiPublicKey = dataProvider.getJsonByKey(23, "api_public_key_base64");
        final String apiPublicKeyIdentifier = dataProvider.getJsonByKey(23, "api_key_id");
        final String apiAppId = dataProvider.getJsonByKey(23, "app_id");
        VirgilCrypto crypto = new VirgilCrypto();

        PrivateKey privateKey = crypto.importPrivateKey(
                ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(23, "api_private_key_base64")));

        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                apiPublicKeyIdentifier, accessTokenSigner);

        JwtGenerator jwtGenerator = new JwtGenerator(apiAppId, privateKey, apiPublicKeyIdentifier,
                                                     TimeSpan.fromTime(1, TimeUnit.HOURS), accessTokenSigner);

        Jwt jwt = jwtGenerator.generateToken("test");

        assertTrue(jwtVerifier.verifyToken(jwt));
    }

    private Map<String, String> extractSignatures(JsonObject baseData) {
        Map<String, String> signatures = new HashMap<>();
        for (JsonElement jsonElement : baseData.getAsJsonArray(SIGNATURES)) {
            signatures.put(jsonElement.getAsJsonObject().get("signer").getAsString(),
                    jsonElement.getAsJsonObject().get("signature").getAsString());
        }

        return signatures;
    }

    private String getFromSnapshot(JsonObject baseData, String key) {
        JsonElement jsonElement = new Gson().fromJson(
                ConvertionUtils.base64ToString(baseData.get(CONTENT_SNAPSHOT).getAsString()), JsonElement.class);

        return jsonElement.getAsJsonObject().get(key).getAsString();
    }
}
