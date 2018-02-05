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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.utils.TestUtils;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import sun.util.logging.PlatformLogger;

public class CardClientTest extends PropertyManager {

    private static final String IDENTITY = "SomeTestIdentity";

    private CardClient cardClient;
    private Mocker mocker;

    @Before
    public void setUp() {
        cardClient = new CardClient(CARDS_SERVICE_URL);
        mocker = new Mocker();

        PlatformLogger.getLogger("sun.net.www.protocol.http.HttpURLConnection").setLevel(PlatformLogger.Level.ALL);
    }

    @Test
    public void tokenVerification() throws CryptoException {
        Jwt accessToken = mocker.generateAccessToken(IDENTITY);
        Assert.assertTrue(mocker.getVerifier().verifyToken(accessToken));
    }

    @Test
    public void validTokenPublishCard() throws CryptoException {
        String identity = Generator.identity();

        RawSignedModel cardModelBeforePublish = mocker.generateCardModel(identity);

        RawSignedModel cardModelAfterPublish = cardClient.publishCard(cardModelBeforePublish,
                mocker.generateAccessToken(identity).toString());

        TestUtils.assertCardModelsEquals(cardModelBeforePublish, cardModelAfterPublish);
    }

    @Test
    public void validTokenPublishCardExported() throws CryptoException {
        String jsonCardModel = "{\"content_snapshot\":\"ewogICJ2ZXJzaW9uIiA6ICI1LjAiLAogICJwdWJsaWNfa2"
                + "V5IiA6ICJMUzB0TFMxQ1JVZEpUaUJRVlVKTVNVTWdTMFZaTFMwdExTMEtUVU52ZDBKUldVUkxNbFozUVhsRlF"
                + "XSTBTRlVyZUVsclVDdDJkM0F2VmpZeU5tZHNlWE5SWjJWaFdYbFJNV2RCT1ZkVFNreDZkVzQ0WkdzOUNpMHRM"
                + "UzB0UlU1RUlGQlZRa3hKUXlCTFJWa3RMUzB0TFFvPSIsCiAgImlkZW50aXR5IiA6ICJpZGVudGl0eSIsCiAgI"
                + "mNyZWF0ZWRfYXQiIDogMTUxNjk3MjAwOQp9\",\"signatures\":[{\"signer_type\":\"self\",\"sig"
                + "nature\":\"MFEwDQYJYIZIAWUDBAICBQAEQINRagKzeNyk2juS5G6Ratlk5sNYFDB4TtIJ2ELQflYJSq9LoP"
                + "H541IRdbl0q/jzEJw94v4VCfNhEioXBRv0hAU=\",\"snapshot\":\"\",\"signer_id\":\"56d5df161e"
                + "f884a2d3702c41ad9487036720208a68c425b968f86cd1a45fb75e\"}]}";

        RawSignedModel cardModelBeforePublish = ConvertionUtils.deserializeFromJson(jsonCardModel,
                RawSignedModel.class);

        RawSignedModel cardModelAfterPublish = cardClient.publishCard(cardModelBeforePublish,
                mocker.generateAccessToken(IDENTITY).toString());

        Assert.assertEquals(cardModelBeforePublish, cardModelAfterPublish);
    }

    @Test
    public void fakeTokenPublishCard() throws CryptoException {
        RawSignedModel cardModelBeforePublish = mocker.generateCardModel();

        RawSignedModel cardModelAfterPublish = cardClient.publishCard(cardModelBeforePublish, "Try our tokens");

        Assert.assertEquals(cardModelBeforePublish, cardModelAfterPublish);
    }
}
