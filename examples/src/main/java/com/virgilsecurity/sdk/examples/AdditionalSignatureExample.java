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
package com.virgilsecurity.sdk.examples;

import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.CardManager.SignCallback;
import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;

import java.util.Date;

/**
 * @author Andrii Iakovenko
 *
 */
public class AdditionalSignatureExample {

    // Your's server private key
    private final PrivateKey PRIVATE_KEY;

    /**
     * Create new instance of {@link AdditionalSignatureExample}.
     * 
     * @throws CryptoException
     */
    public AdditionalSignatureExample() throws CryptoException {
        PRIVATE_KEY = new VirgilCrypto().generateKeys().getPrivateKey();
    }

    public static void main(String[] args) throws CryptoException {
        new AdditionalSignatureExample().run();
    }

    private void run() throws CryptoException {
        Tuple<String, String> keys = generateKey();

        RawCardContent rawCard = new RawCardContent("Alice", keys.getRight(), new Date());
        String rawCardStr = rawCard.exportAsBase64String();
        System.out.println(String.format("Unigned card: %s", rawCardStr));
        String signedCard = signCard(rawCardStr);
        System.out.println(String.format("Signed card: %s", signedCard));
    }

    private Tuple<String, String> generateKey() throws CryptoException {
        // generate a key pair
        VirgilCrypto crypto = new VirgilCrypto();
        VirgilKeyPair keyPair = crypto.generateKeys();

        // export private and public key
        byte[] privateKeyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), "<YOUR_PASSWORD>");
        byte[] publicKeyData = crypto.exportPublicKey(keyPair.getPublicKey());

        // Save it securely
        String privateKeyStr = ConvertionUtils.toBase64String(privateKeyData);

        // Embed it in client-side apps
        String publicKeyStr = ConvertionUtils.toBase64String(publicKeyData);

        return new Tuple<String, String>(privateKeyStr, publicKeyStr);
    }

    @SuppressWarnings("unused")
    private void transmitCard() {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(new CallbackJwtProvider.GetTokenCallback() {
            @Override
            public String onGetToken(TokenContext tokenContext) {
                return "your token generation implementation";
            }
        });
        CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto);
        SignCallback signCallback = new SignCallback() {

            @Override
            public RawSignedModel onSign(RawSignedModel rawCard) {
                String rawCardStr = rawCard.exportAsBase64String();

                // Send this string to server-side, where it will be signed
                RawSignedModel signedRawCard = new RawSignedModel(rawCardStr);
                return signedRawCard;
            }
        };

        CardManager cardManager = new CardManager(cardCrypto,
                                                  accessTokenProvider,
                                                  cardVerifier,
                                                  signCallback);
    }

    private String signCard(String rawCardStr) throws CryptoException {
        // Receive rawCardStr from a client
        RawSignedModel rawCard = new RawSignedModel(rawCardStr);

        CardCrypto cardCrypto = new VirgilCardCrypto();
        ModelSigner modelSigner = new ModelSigner(cardCrypto);

        // sign a user's card with a server's private key
        modelSigner.sign(rawCard, "YOUR_BACKEND", PRIVATE_KEY);

        // Send it back to the client
        String newRawCardStr = rawCard.exportAsBase64String();

        return newRawCardStr;
    }

}
