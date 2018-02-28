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
package com.virgilsecurity.sdk.highlevel;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.BaseIT;
import com.virgilsecurity.sdk.client.CardValidator;
import com.virgilsecurity.sdk.client.VirgilClientContext;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilCardManagerTest extends BaseIT {

    private String aliceIdentity = "alice";
    private String aliceEmail = "alice@mailinator.com";
    private CardManager cardManager;
    private VirgilKey virgilKey;

    @Before
    public void setUp() throws MalformedURLException {
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_PRIVATE_KEY));
        credentials.setAppKeyPassword(APP_PRIVATE_KEY_PASSWORD);

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

        VirgilApiContext context = new VirgilApiContext(APP_TOKEN);
        context.setCredentials(credentials);
        context.setClientContext(ctx);
        context.getClient().setCardValidator(new CardValidator() {

            @Override
            public boolean validate(CardModel card) {
                return true;
            }
        });

        VirgilApi virgilApi = new VirgilApiImpl(context);

        cardManager = virgilApi.getCards();
        virgilKey = virgilApi.getKeys().generate();

        aliceIdentity = "alice" + new Date().getTime();
        aliceEmail = aliceIdentity + "@mailinator.com";
    }

    @Test
    public void create_by_identity_key() {
        VirgilCard virgilCard = cardManager.create(aliceIdentity, virgilKey);
        assertNotNull(virgilCard);
        assertEquals(aliceIdentity, virgilCard.getIdentity());
        assertEquals("unknown", virgilCard.getIdentityType());
        assertNull(virgilCard.getCustomFields());
    }

    @Test
    public void create_by_identity_key_identityType() {
        VirgilCard virgilCard = cardManager.create(aliceIdentity, virgilKey, "username");
        assertNotNull(virgilCard);
        assertEquals(aliceIdentity, virgilCard.getIdentity());
        assertEquals("username", virgilCard.getIdentityType());
        assertNull(virgilCard.getCustomFields());
    }

    @Test
    public void create_EmptyCustomFields() {
        Map<String, String> customFields = new HashMap<>();
        VirgilCard virgilCard = cardManager.create(aliceIdentity, virgilKey, "username", customFields);
        assertNotNull(virgilCard);
        assertEquals(aliceIdentity, virgilCard.getIdentity());
        assertEquals("username", virgilCard.getIdentityType());
        assertNotNull(virgilCard.getCustomFields());
        assertTrue(virgilCard.getCustomFields().isEmpty());
    }

    @Test
    public void create() {
        Map<String, String> customFields = new HashMap<>();
        customFields.put("field1", "value1");
        customFields.put("field2", "value2");
        VirgilCard virgilCard = cardManager.create(aliceIdentity, virgilKey, "username", customFields);
        assertNotNull(virgilCard);
        assertEquals(aliceIdentity, virgilCard.getIdentity());
        assertEquals("username", virgilCard.getIdentityType());
        assertNotNull(virgilCard.getCustomFields());
        assertEquals(2, virgilCard.getCustomFields().size());
        assertEquals("value1", virgilCard.getCustomFields().get("field1"));
        assertEquals("value2", virgilCard.getCustomFields().get("field2"));
    }

    @Test
    public void createGlobal_identity_key_identityType() {
        VirgilCard virgilCard = cardManager.createGlobal(aliceEmail, virgilKey, IdentityType.EMAIL);
        assertNotNull(virgilCard);
        assertEquals(aliceEmail, virgilCard.getIdentity());
        assertEquals("email", virgilCard.getIdentityType());
        assertNull(virgilCard.getCustomFields());
    }

    @Test
    public void createGlobal() {
        Map<String, String> customFields = new HashMap<>();
        customFields.put("field1", "value1");
        customFields.put("field2", "value2");
        VirgilCard virgilCard = cardManager.createGlobal(aliceEmail, virgilKey, IdentityType.EMAIL, customFields);
        assertNotNull(virgilCard);
        assertEquals(aliceEmail, virgilCard.getIdentity());
        assertEquals("email", virgilCard.getIdentityType());
        assertNotNull(virgilCard.getCustomFields());
        assertEquals(2, virgilCard.getCustomFields().size());
        assertEquals("value1", virgilCard.getCustomFields().get("field1"));
        assertEquals("value2", virgilCard.getCustomFields().get("field2"));
    }

    @Test
    public void importCard() {
        VirgilCard aliceCard = cardManager.create(aliceIdentity, virgilKey, "username");
        String exportedCard = aliceCard.export();

        VirgilCard importedCard = cardManager.importCard(exportedCard);
        assertNotNull(importedCard);
        compareCards(aliceCard, importedCard);
    }

    @Test
    public void importCard_cardModel() {
        VirgilCard aliceCard = cardManager.create(aliceIdentity, virgilKey, "username");
        CardModel cardModel = aliceCard.getModel();
        VirgilCard importedCard = cardManager.importCard(cardModel);
        assertNotNull(importedCard);
        compareCards(aliceCard, importedCard);
    }

    @Test
    public void publish_find_revoke() throws InterruptedException, VirgilException {
        // Publish
        VirgilCard aliceCard = cardManager.create(aliceIdentity, virgilKey, "username");
        aliceCard.publish();

        // Get
        VirgilCard foundCard = cardManager.get(aliceCard.getId());
        assertNotNull(foundCard);
        compareCards(aliceCard, foundCard);

        // Find by identity
        VirgilCards aliceCards = cardManager.find(aliceIdentity);
        assertNotNull(aliceCards);
        assertFalse(aliceCards.isEmpty());

        foundCard = selectById(aliceCard.getId(), aliceCards);
        assertNotNull(foundCard);
        compareCards(aliceCard, foundCard);

        // Find by identities
        aliceCards = cardManager.find(Arrays.asList(aliceIdentity));
        assertNotNull(aliceCards);
        assertFalse(aliceCards.isEmpty());

        foundCard = selectById(aliceCard.getId(), aliceCards);
        assertNotNull(foundCard);
        compareCards(aliceCard, foundCard);

        // Find by identity type (negative)
        aliceCards = cardManager.find("usernames", Arrays.asList(aliceIdentity));
        assertNotNull(aliceCards);
        assertTrue(aliceCards.isEmpty());

        // Find by identity type (positive)
        aliceCards = cardManager.find("username", Arrays.asList(aliceIdentity));
        assertNotNull(aliceCards);
        assertFalse(aliceCards.isEmpty());

        foundCard = selectById(aliceCard.getId(), aliceCards);
        assertNotNull(foundCard);
        compareCards(aliceCard, foundCard);

        // Revoke
        cardManager.revoke(aliceCard);
        foundCard = cardManager.get(aliceCard.getId());
        // assertNull(foundCard);
    }

    private VirgilCard selectById(String cardId, List<VirgilCard> cards) {
        for (VirgilCard card : cards) {
            if (cardId.equals(card.getId())) {
                return card;
            }
        }
        return null;
    }

    private void compareCards(VirgilCard card1, VirgilCard card2) {
        assertEquals(card1.getId(), card2.getId());
        assertEquals(card1.getIdentity(), card2.getIdentity());
        assertEquals(card1.getIdentityType(), card2.getIdentityType());
    }

}
