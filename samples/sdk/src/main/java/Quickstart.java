
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

import java.util.List;

import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * This sample will help you get started using the Crypto Library and VIRGIL Keys Services for the most popular
 * platforms and languages.
 * 
 * @author Andrii Iakovenko
 *
 */
public class Quickstart {

    public static void main(String[] args) throws Exception, VirgilException {

        // Initializing an API Client
        CardClient client = new CardClient("[YOUR_APP_ACCESS_TOKEN_HERE]");

        // Initializing Crypto
        Crypto crypto = new VirgilCrypto();

        // Creating a VIRGIL Card
        String appID = "[YOUR_APP_ID_HERE]";
        String appKeyPassword = "[YOUR_APP_KEY_PASSWORD_HERE]";
        byte[] appKeyData = "[YOUR_APP_KEY_HERE]".getBytes();

        PrivateKey appKey = crypto.importPrivateKey(appKeyData, appKeyPassword);

        /** Generate a new Public/Private keypair using VirgilCrypto class. */
        KeyPair aliceKeys = crypto.generateKeys();

        /** Prepare request */
        byte[] exportedPublicKey = crypto.exportPublicKey(aliceKeys.getPublicKey());
//        PublishCardRequest createCardRequest = new PublishCardRequest("alice", "username", exportedPublicKey);
//
//        /**
//         * then, use RequestSigner class to generateStreamSignature request with owner and app keys.
//         */
//        RequestSigner requestSigner = new RequestSigner(crypto);
//
//        requestSigner.selfSign(createCardRequest, aliceKeys.getPrivateKey());
//        requestSigner.authoritySign(createCardRequest, appID, appKey);
//
//        /** Publish a VIRGIL Card */
//        CardModel aliceCard = client.publishCard(createCardRequest);
//
//        // Get VIRGIL Card
//        CardModel foundCard = client.getCard(aliceCard.getIdentifier());

        // Search for VIRGIL Cards
        SearchCriteria criteria = SearchCriteria.byIdentity("alice");
        List<CardModel> cards = client.searchCards(criteria);

        // Validating a VIRGIL Cards
        CardValidator cardValidator = new VirgilCardValidator(crypto);
        client.setCardValidator(cardValidator);

        try {
            cards = client.searchCards(criteria);
        } catch (CardValidationException e) {
            // Handle validation exception here
        }

        // Revoking a VIRGIL Card
        /** Use your card ID */
//        String cardId = aliceCard.getIdentifier();
//
//        RevokeCardRequest revokeRequest = new RevokeCardRequest(cardId, RevocationReason.UNSPECIFIED);
//
//        requestSigner.selfSign(revokeRequest, aliceKeys.getPrivateKey());
//        requestSigner.authoritySign(revokeRequest, appID, appKey);
//
//        client.revokeCard(revokeRequest);
    }

}
