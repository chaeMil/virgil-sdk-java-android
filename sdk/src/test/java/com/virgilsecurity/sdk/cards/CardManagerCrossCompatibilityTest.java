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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Calendar;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class CardManagerCrossCompatibilityTest {

    private FakeDataFactory fake;
    private VirgilCrypto crypto;
    private CardCrypto cardCrypto;
    private AccessTokenProvider generator;
    private JsonObject sampleJson;
    private ModelSigner modelSigner;
    private CardVerifier cardVerifier;
    private CardClient cardClient;

    @Before
    public void setup() throws CryptoException {
        this.fake = new FakeDataFactory();
        this.crypto = this.fake.getCrypto();
        this.cardCrypto = new VirgilCardCrypto(this.crypto);
        this.modelSigner = new ModelSigner(this.cardCrypto);
        this.cardClient = new CardClient();
        this.cardVerifier = new VirgilCardVerifier(this.cardCrypto);

        sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("com/virgilsecurity/sdk/test_data.txt")));
    }

    @Test
    public void test_STC_3() throws IOException, CryptoException {
        String identity = UUID.randomUUID().toString();

        GeneratorJwtProvider generator = new GeneratorJwtProvider(this.fake.getJwtGenerator(), identity);
        CardManager cardManager = new CardManager(this.cardCrypto, generator, this.modelSigner, this.cardClient,
                this.cardVerifier, null);

        String rawCardString = sampleJson.get("STC-3.as_string").getAsString();
        assertNotNull(rawCardString);

        Card card1 = cardManager.importCardAsString(rawCardString);
        assertNotNull(card1);

        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2018);
        cal.set(Calendar.MONTH, 2018);
        cal.set(Calendar.DAY_OF_MONTH, 2018);
        cal.set(Calendar.HOUR, 2018);
        cal.set(Calendar.MINUTE, 2018);
        cal.set(Calendar.SECOND, 2018);
        cal.set(Calendar.MILLISECOND, 0);

        assertEquals("551a933671d4e20524bc7f42e3062e810a1d62250fcbb217263c34c762de9dd0", card1.getIdentifier());
        assertEquals("test", card1.getIdentity());
        assertNotNull(card1.getPublicKey());
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=",
                ConvertionUtils.toBase64String(this.crypto.exportPublicKey((VirgilPublicKey) card1.getPublicKey())));
        assertEquals("5.0", card1.getVersion());
        assertNull(card1.getPreviousCard());
        assertNull(card1.getPreviousCardId());
        assertTrue(card1.getSignatures().isEmpty());
        assertEquals(cal.getTime(), card1.getCreatedAt());

        // NSData *rawCardDic = [self.testData[@"STC-3.as_json"] dataUsingEncoding:NSUTF8StringEncoding];
        // XCTAssert(rawCardDic != nil);
        //
        // NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:rawCardDic options:kNilOptions error:nil];
        // XCTAssert(dic != nil);
        //
        // VSSCard *card2 = [cardManager importCardWithJson:dic];
        // XCTAssert(card2 != nil);
        //
        // [self.utils isCardsEqualWithCard:card1 and:card2];
        //
        // NSString *exportedCardString = [cardManager exportCardAsStringWithCard:card1 error:&error];
        // XCTAssert(error == nil);
        //
        // VSSCard *newImportedCard1 = [cardManager importCardWithString:exportedCardString];
        // XCTAssert(newImportedCard1 != nil);
        //
        // XCTAssert([self.utils isCardsEqualWithCard:card1 and:newImportedCard1]);
        //
        // NSDictionary *exportedCardJson = [cardManager exportCardAsJsonWithCard:card2 error:&error];
        // XCTAssert(error == nil);
        //
        // VSSCard *newImportedCard2 = [cardManager importCardWithJson:exportedCardJson];
        // XCTAssert(newImportedCard2 != nil);
        // XCTAssert([self.utils isCardsEqualWithCard:card2 and:newImportedCard2]);
    }
}
