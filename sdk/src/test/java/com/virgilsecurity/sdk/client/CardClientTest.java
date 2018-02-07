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

package com.virgilsecurity.sdk.client;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.utils.TestUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import sun.util.logging.PlatformLogger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class CardClientTest extends PropertyManager {

    private static final String IDENTITY = "SomeTestIdentity";

    private CardClient cardClient;
    private Mocker mocker;

    @Before
    public void setUp() {
        cardClient = new CardClient(CARDS_SERVICE_URL);
        mocker = new Mocker();
//        PlatformLogger.getLogger("sun.net.www.protocol.http.HttpURLConnection").setLevel(PlatformLogger.Level.ALL);
    }

    @Test
    public void tokenVerification() throws CryptoException {
        Jwt accessToken = mocker.generateAccessToken(IDENTITY);
        Assert.assertTrue(mocker.getVerifier().verifyToken(accessToken));
    }

    @Test
    public void validTokenPublish() throws CryptoException {
        String identity = Generator.identity();

        RawSignedModel cardModelBeforePublish = mocker.generateCardModel(identity);

        RawSignedModel cardModelAfterPublish = null;
        try {
            cardModelAfterPublish = cardClient.publishCard(cardModelBeforePublish,
                                                           mocker.generateAccessToken(identity).stringRepresentation());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            fail();
        }

        TestUtils.assertCardModelsEquals(cardModelBeforePublish, cardModelAfterPublish);
    }

    @Test
    public void STC_25_publish() throws CryptoException {
        String identity = Generator.identity();

        try {
            cardClient.publishCard(mocker.generateCardModel(identity),
                                   mocker.generateFakeAccessToken(identity).stringRepresentation());
//            cardClient.publishCard(mocker.generateCardModel(identity),
//                                   "Try our fried tokens");
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            assertEquals(401, e.getHttpError().getCode());
        }
    }

    @Test
    public void STC_25_get() throws CryptoException {
        String identity = Generator.identity();

        try {
//            cardClient.getCard(Generator.cardId(),
//                                   mocker.generateFakeAccessToken(identity).stringRepresentation());
            cardClient.getCard(Generator.cardId(),
                               "Try our fried tokens");
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            assertEquals(401, e.getHttpError().getCode());
        }
    }

    @Test
    public void STC_25_search() throws CryptoException {
        String identity = Generator.identity();

        try {
            cardClient.searchCards(Generator.identity(),
                                   mocker.generateFakeAccessToken(identity).stringRepresentation());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            assertEquals(401, e.getHttpError().getCode());
        }
    }

    @Test
    public void STC_27() throws CryptoException {
        String identity = Generator.identity();
        String identitySecond = Generator.identity();

        try {
            cardClient.publishCard(mocker.generateCardModel(identity),
                                   mocker.generateAccessToken(identitySecond).stringRepresentation());
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            assertEquals(401, e.getHttpError().getCode());
            // FIXME: 2/7/18 after service will handle this - refactor error handling in this case
        }
    }
}
