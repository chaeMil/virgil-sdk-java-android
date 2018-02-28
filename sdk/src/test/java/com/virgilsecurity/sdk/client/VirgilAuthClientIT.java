/*******************************************************************************
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
 *******************************************************************************/
package com.virgilsecurity.sdk.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.client.model.auth.GetChallengeMessageResponse;
import com.virgilsecurity.sdk.client.model.auth.ObtainAccessTokenResponse;
import com.virgilsecurity.sdk.highlevel.AppCredentials;
import com.virgilsecurity.sdk.highlevel.VirgilApi;
import com.virgilsecurity.sdk.highlevel.VirgilApiContext;
import com.virgilsecurity.sdk.highlevel.VirgilApiImpl;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.highlevel.VirgilCard;
import com.virgilsecurity.sdk.highlevel.VirgilKey;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilAuthClientIT extends BaseIT {

    private String identity;
    private VirgilKey key;
    private VirgilCard card;
    private VirgilAuthClient authClient;

    @Before
    public void setup() throws MalformedURLException, InterruptedException {
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_PRIVATE_KEY));
        credentials.setAppKeyPassword(APP_PRIVATE_KEY_PASSWORD);

        VirgilClientContext ctx = new VirgilClientContext();
        String url = getPropertyByName("CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("RO_CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setReadOnlyCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("IDENTITY_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setIdentityServiceURL(new URL(url));
        }
        url = getPropertyByName("AUTH_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setAuthServiceURL(new URL(url));
        }
        VirgilApiContext apiCtx = new VirgilApiContext(APP_TOKEN);
        apiCtx.setCredentials(credentials);
        apiCtx.setClientContext(ctx);

        VirgilApi virgilApi = new VirgilApiImpl(apiCtx);

        // FIXME Validate identity first
        identity = "alice_" + UUID.randomUUID().toString();
        key = virgilApi.getKeys().generate();
        card = virgilApi.getCards().createGlobal(identity, key, IdentityType.APPLICATION);

        authClient = new VirgilAuthClient(ctx);

        Thread.sleep(2000);
    }

    @Test
    @Ignore
    public void testFlow() {
        GetChallengeMessageResponse challengeMessage = authClient.getChallengeMessage(card.getId());
        assertNotNull(challengeMessage);

        String acknowledge = authClient.acknowledge(challengeMessage);
        assertNotNull(acknowledge);

        ObtainAccessTokenResponse accessToken = authClient.obtainAccessToken(acknowledge);
        assertNotNull(accessToken);

        String virgilCardId = authClient.verify(accessToken.getAccessToken());
        assertNotNull(virgilCardId);
        assertEquals(card.getId(), virgilCardId);

    }
}
