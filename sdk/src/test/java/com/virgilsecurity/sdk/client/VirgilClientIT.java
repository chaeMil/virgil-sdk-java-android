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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.RevocationReason;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * Test cases for Virgil Client.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilClientIT extends BaseIT {

    private Crypto crypto;
    private VirgilClient client;
    private RequestSigner requestSigner;
    private PrivateKey appKey;

    @Before
    public void setUp() throws MalformedURLException, CryptoException {
        crypto = new VirgilCrypto();

        VirgilClientContext ctx = new VirgilClientContext(APP_TOKEN);

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

        client = new VirgilClient(ctx);
        requestSigner = new RequestSigner(crypto);

        appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);
    }

    @Test
    public void testCustomCards() throws VirgilException {
        KeyPair aliceKeys = crypto.generateKeys();

        // Create card
        byte[] exportedPublicKey = crypto.exportPublicKey(aliceKeys.getPublicKey());
        PublishCardRequest createCardRequest = new PublishCardRequest("alice", "username", exportedPublicKey);

        CardModel aliceCard = null;
        try {
            requestSigner.selfSign(createCardRequest, aliceKeys.getPrivateKey());
            requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

            aliceCard = client.publishCard(createCardRequest);

            assertNotNull(aliceCard);
            assertNotNull(aliceCard.getId());
            assertEquals("alice", aliceCard.getSnapshotModel().getIdentity());
            assertEquals("username", aliceCard.getSnapshotModel().getIdentityType());
            assertEquals(CardScope.APPLICATION, aliceCard.getSnapshotModel().getScope());
            assertNotNull(aliceCard.getMeta().getVersion());
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Get card
        try {
            CardModel card = client.getCard(aliceCard.getId());
            assertNotNull(card);
            assertEquals(aliceCard.getId(), card.getId());
            assertEquals("alice", card.getSnapshotModel().getIdentity());
            assertEquals("username", card.getSnapshotModel().getIdentityType());
            assertEquals(CardScope.APPLICATION, card.getSnapshotModel().getScope());
            assertNotNull(card.getMeta().getVersion());
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by Application bundle
        SearchCriteria criteria = SearchCriteria.byAppBundle(APP_BUNDLE);

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (APP_ID.equals(card.getId())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by application", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by identity
        criteria = SearchCriteria.byIdentity("alice");

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (aliceCard.getId().equals(card.getId())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by identity", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search by identities
        criteria = SearchCriteria.byIdentities(Arrays.asList("alice", "bob"));

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (aliceCard.getId().equals(card.getId())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by identities", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Revoke card
        RevokeCardRequest revokeRequest = new RevokeCardRequest(aliceCard.getId(), RevocationReason.UNSPECIFIED);

        requestSigner.authoritySign(revokeRequest, APP_ID, appKey);

        try {
            client.revokeCard(revokeRequest);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }
    }

}
